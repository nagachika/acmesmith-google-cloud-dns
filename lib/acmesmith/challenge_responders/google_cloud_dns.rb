require "acmesmith/challenge_responders/base"

require "json"
require "google/apis/dns_v1"
require "resolv"
require "set"

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

          resp = @api.create_change(@project_id, zone_name, change)
          change_id = resp.id

          wait_for_sync_by_api(zone_name, change_id)
          wait_for_sync_by_dns(zone_name, change)
        end
      end

      def cleanup_all(*domain_and_challenges)
        challenges_by_zone_names = domain_and_challenges.group_by{ |domain, challenge|
          domain = canonicalize(domain)
          find_managed_zone(domain).name
        }

        challenges_by_zone_names.each do |zone_name, dcs|
          change = change_for_challenges(zone_name, dcs, for_cleanup: true)

          resp = @api.create_change(@project_id, zone_name, change)
          change_id = resp.id

          wait_for_sync_by_api(zone_name, change_id)
        end
      end

      private

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

      def wait_for_sync_by_dns(zone_name, change)
        puts "=> Checking DNS resource record"
        nameservers =  @api.get_managed_zone(@project_id, zone_name).name_servers
        puts " * nameservers: #{nameservers.inspect}"
        nameservers.each do |ns|
          Resolv::DNS.open(:nameserver => Resolv.getaddresses(ns)) do |dns|
            dns.timeouts = 5
            change.additions.each do |rrset|
              required_rrdatas = Set.new(rrset.rrdatas.map{|rrdata| rrdata.gsub(/(\A"|"\z)/, '') })

              deletion = change.deletions.find{|_deletion| _deletion.name == rrset.name && _deletion.type == rrset.type }
              if deletion
                required_rrdatas -= Set.new(deletion.rrdatas)
              end

              loop do
                resources = dns.getresources(rrset.name, Resolv::DNS::Resource::IN::TXT)
                actual_rrdatas = resources.map(&:data)
                if required_rrdatas.subset?(Set.new(actual_rrdatas))
                  puts " * [#{ns} -> #{rrset.name}] success. (actual=#{actual_rrdatas.inspect})"
                  sleep 1
                  break
                else
                  puts " * [#{ns} -> #{rrset.name}] failed. (required=#{required_rrdatas.to_a.inspect}, but actual=#{actual_rrdatas.inspect})"
                  sleep 5
                end
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

      def change_for_challenges(zone_name, domain_and_challenges, for_cleanup: false)
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

          if for_cleanup
            new_rrset.rrdatas -= rrset_params.map{|rrset| rrset[:rrdatas] }.flatten
          else
            new_rrset.rrdatas += rrset_params.map{|rrset| rrset[:rrdatas] }.flatten
          end
          new_rrset
        }.select{ |rrset|
          rrset.rrdatas != []
        }

        change
      end
    end
  end
end
