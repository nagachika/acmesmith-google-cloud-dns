require "acmesmith/challenge_responders/base"

require "json"
require "google/apis/dns_v1"
require "resolv"

module Acmesmith
  module ChallengeResponders
    class GoogleCloudDns < Base
      def support?(type)
        type == 'dns-01'
      end

      def cap_respond_all?
        true
      end

      def initialize(config)
        @config = config
        @scope = "https://www.googleapis.com/auth/ndev.clouddns.readwrite"
        @api = Google::Apis::DnsV1::DnsService.new
        if @config[:compute_engine_service_account]
          @api.authorization = Google::Auth.get_application_default(@scope)
        elsif @config[:private_key_json_file]
          credential = load_json_key(@config[:private_key_json_file])
          @api.authorization = Signet::OAuth2::Client.new(
            token_credential_uri: "https://accounts.google.com/o/oauth2/token",
            audience: "https://accounts.google.com/o/oauth2/token",
            scope: @scope,
            issuer: credential[:email_address],
            signing_key: credential[:private_key])
        else
          raise "You need to specify authentication options (compute_engine_service_account or private_key_json_file)"
        end
        @api.authorization.fetch_access_token!
        @project_id = @config[:project_id]
      end

      def respond_all(*domain_and_challenges)
        challenges_by_zone_names = domain_and_challenges.group_by{ |domain, challenge|
          domain = canonicalize(domain)
          find_managed_zone(domain).name
        }

        challenges_by_zone_names.each do |zone_name, dcs|
          change = change_for_challenges(zone_name, dcs)

          require 'pry'
          binding.pry

          resp = @api.create_change(@project_id, zone_name, change)
          change_id = resp.id

          wait_for_sync_by_api(zone_name, change_id)
          dcs.each do |domain, challenge|
            wait_for_sync_by_dns(zone_name, domain, challenge)
          end
        end
      end

      def cleanup_all(*domain_and_challenges)
        challenges_by_zone_names = domain_and_challenges.group_by{ |domain, challenge|
          domain = canonicalize(domain)
          find_managed_zone(domain).name
        }
        ## TODO: not implemented yet
      end

      ## TODO: remove this method
      def respond(domain, challenge)
        puts "=> Responding challenge dns-01 for #{domain} in #{self.class.name}"

        domain = canonicalize(domain)
        zone_name = find_managed_zone(domain).name

        puts " * create_change: #{challenge.record_type} #{[challenge.record_name, domain].join('.').inspect}, #{challenge.record_content.inspect}"

        change = change_for_challenge(zone_name, domain, challenge)
        resp = @api.create_change(@project_id, zone_name, change)

        change_id = resp.id

        wait_for_sync(zone_name, domain, challenge, change_id)
      end

      ## TODO: remove this method
      def cleanup(domain, challenge)
        domain = canonicalize(domain)
        zone_name = find_managed_zone(domain).name
        change = change_for_challenge(zone_name, domain, challenge, for_cleanup: true)
        @api.create_change(@project_id, zone_name, change)
      end

      private

      def wait_for_sync(zone_name, domain, challenge, change_id)
        wait_for_sync_by_api(zone_name, change_id)
        wait_for_sync_by_dns(zone_name, domain, challenge)
      end

      def wait_for_sync_by_api(zone_name, change_id)
        puts " * requested change: #{change_id}"
        resp = @api.get_change(@project_id, zone_name, change_id)

        while resp.status != 'done'
          puts " * change #{change_id.inspect} is still #{resp.status.inspect}"
          sleep 5
          resp = @api.get_change(@project_id, zone_name, change_id)
        end

        puts " * synced!"
      end

      def wait_for_sync_by_dns(zone_name, domain, challenge)
        puts "=> Checking DNS resource record"
        nameservers =  @api.get_managed_zone(@project_id, zone_name).name_servers
        puts " * nameservers: #{nameservers.inspect}"
        nameservers.each do |ns|
          Resolv::DNS.open(:nameserver => Resolv.getaddresses(ns)) do |dns|
            dns.timeouts = 5
            loop do
              resources = dns.getresources([challenge.record_name, domain].join('.'), Resolv::DNS::Resource::IN::TXT)
              if resources.any?{|resource| resource.data == challenge.record_content }
                puts " * [#{ns}] success: #{resources.map{|r| {ttl: r.ttl, data: r.data} }.inspect}"
                sleep 1
                break
              else
                puts " * [#{ns}] failed: #{resources.map{|r| {ttl: r.ttl, data: r.data} }.inspect}"
                sleep 5
              end
            end
          end
        end
      end

      def load_json_key(filepath)
        obj = JSON.parse(File.read(filepath))
        {
          email_address: obj["client_email"],
          private_key: OpenSSL::PKey.read(obj["private_key"]),
        }
      end

      def canonicalize(domain)
        "#{domain}.".gsub(/\.{2,}/, '.')
      end

      def find_managed_zone(domain)
        managed_zone = @api.list_managed_zones(@project_id).managed_zones.select do |zone|
          /(?:\A|\.)#{Regexp.escape(zone.dns_name)}\z/ =~ domain
        end.max_by{|z| z.dns_name.size }
        if managed_zone.nil?
          raise "Domain #{domain} is not managed in Google Cloud DNS [project_id=#{@project_id}]"
        end
        managed_zone
      end

      ## TODO: remove this method
      def change_for_challenge(zone_name, domain, challenge, for_cleanup: false)
        name = [challenge.record_name, domain].join('.')
        type = challenge.record_type
        data = "\"#{challenge.record_content}\""

        rrsets = @api.fetch_all(items: :rrsets) do |token|
          @api.list_resource_record_sets(@project_id, zone_name, page_token: token)
        end

        current_rrset = rrsets.find{ |rrset| rrset.type == type && rrset.name == name }

        change = Google::Apis::DnsV1::Change.new
        change.deletions = [ current_rrset ] if current_rrset

        new_rrset = Google::Apis::DnsV1::ResourceRecordSet.new(
          name: name,
          type: type,
          rrdatas: current_rrset ? current_rrset.rrdatas.dup : [],
          ttl: @config[:ttl] || 5
        )

        if for_cleanup
          new_rrset.rrdatas.delete(data)
          change.additions = [ new_rrset ] if !new_rrset.rrdatas.empty?
        else
          new_rrset.rrdatas.push(data) if !new_rrset.rrdatas.include?(data)
          change.additions = [ new_rrset ]
        end

        change
      end

      def change_for_challenges(zone_name, domain_and_challenges)
        current_rrsets = @api.fetch_all(items: :rrsets) do |token|
          @api.list_resource_record_sets(@project_id, zone_name, page_token: token)
        end

        change = Google::Apis::DnsV1::Change.new

        change.deletions = domain_and_challenges.map{ |domain, challenge|
          domain = canonicalize(domain)
          name = [challenge.record_name, domain].join('.')
          type = challenge.record_type

          current_rrsets.find{ |rrset| rrset.type == type && rrset.name == name }
        }.uniq.compact

        change.additions = domain_and_challenges.map{ |domain, challenge|
          domain = canonicalize(domain)
          name = [challenge.record_name, domain].join('.')
          type = challenge.record_type
          data = "\"#{challenge.record_content}\""

          {
            name: name,
            type: type,
            rrdatas: [data],
          }
        }.group_by{ |rrset_param|
          [ rrset_param[:name], rrset_param[:type] ]
        }.map{ |(name, type), rrset_params|
          current_rrset = current_rrsets.find{ |rrset| rrset.type == type && rrset.name == name }

          new_rrset = Google::Apis::DnsV1::ResourceRecordSet.new(
            name: name,
            type: type,
            rrdatas: current_rrset ? current_rrset.rrdatas : [],
            ttl: @config[:ttl] || 5,
          )

          new_rrset.rrdatas += rrset_params.map{|rrset| rrset[:rrdatas] }.flatten
          new_rrset
        }

        change.deletions.each.with_index do |deletion, idx|
          puts "change.deletions[#{idx}].name = #{deletion.name.inspect}"
          puts "change.deletions[#{idx}].type = #{deletion.type.inspect}"
          puts "change.deletions[#{idx}].ttl = #{deletion.ttl.inspect}"
          deletion.rrdatas.each.with_index do |rrdata, idx2|
            puts "change.deletions[#{idx}].rrdatas[#{idx2}] = #{rrdata.inspect}"
          end
        end

        change.additions.each.with_index do |addition, idx|
          puts "change.additions[#{idx}].name = #{addition.name.inspect}"
          puts "change.additions[#{idx}].type = #{addition.type.inspect}"
          puts "change.additions[#{idx}].ttl = #{addition.ttl.inspect}"
          addition.rrdatas.each.with_index do |rrdata, idx2|
            puts "change.additions[#{idx}].rrdatas[#{idx2}] = #{rrdata.inspect}"
          end
        end

        change
      end
    end
  end
end
