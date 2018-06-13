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

      def respond(domain, challenge)
        puts "=> Responding challenge dns-01 for #{domain} in #{self.class.name}"

        domain = canonicalize(domain)
        zone_name = find_managed_zone(domain).name

        puts " * create_change: #{challenge.record_type} #{[challenge.record_name, domain].join('.').inspect}, #{challenge.record_content.inspect}"

        change = Google::Apis::DnsV1::Change.new

        rrsets = @api.fetch_all(items: :rrsets) do |token|
          @api.list_resource_record_sets(@project_id, zone_name, page_token: token)
        end
        old_rrset = rrsets.find{ |rrset|
          rrset.name == resource_record_set(domain, challenge).name &&
          rrset.type == resource_record_set(domain, challenge).type
        }
        if old_rrset
          change.deletions = [
            old_rrset
          ]
        end

        change.additions = [
          resource_record_set(domain, challenge, old_rrset)
        ]

        resp = @api.create_change(@project_id, zone_name, change)

        change_id = resp.id
        puts " * requested change: #{change_id}"

        while resp.status != 'done'
          puts " * change #{change_id.inspect} is still #{resp.status.inspect}"
          sleep 5
          resp = @api.get_change(@project_id, zone_name, change_id)
        end

        puts " * synced!"

        puts "=> Checking DNS resource record"
        nameservers =  @api.get_managed_zone(@project_id, zone_name).name_servers
        puts " * nameservers: #{nameservers.inspect}"
        nameservers.each do |ns|
          Resolv::DNS.open(:nameserver => Resolv.getaddresses(ns)) do |dns|
            dns.timeouts = 5
            begin
              ret = dns.getresource([challenge.record_name, domain].join('.'), Resolv::DNS::Resource::IN::TXT)
            rescue Resolv::ResolvError => e
              puts " * [#{ns}] failed: #{e.to_s}"
              sleep 5
              retry
            end
            puts " * [#{ns}] success: ttl=#{ret.ttl.inspect}, data=#{ret.data.inspect}"
            sleep 1
          end
        end
      end

      def cleanup(domain, challenge)
        domain = canonicalize(domain)
        zone_name = find_managed_zone(domain).name
        change = Google::Apis::DnsV1::Change.new
        rrsets = @api.fetch_all(items: :rrsets) do |token|
          @api.list_resource_record_sets(@project_id, zone_name, page_token: token)
        end
        old_rrset = rrsets.find{ |rrset|
          rrset.name == resource_record_set(domain, challenge).name &&
          rrset.type == resource_record_set(domain, challenge).type
        }
        if old_rrset
          change.deletions = [
            old_rrset
          ]
          if old_rrset.rrdatas != [challenge.record_content]
            change.additions = [
              Google::Apis::DnsV1::ResourceRecordSet.new(
                name: [challenge.record_name, domain].join("."),
                type: challenge.record_type,
                rrdatas: old_rrset.rrdatas - [challenge.record_content],
                ttl: @config[:ttl] || 5
              )
            ]
          end
          @api.create_change(@project_id, zone_name, change)
        end
      end

      private

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

      def resource_record_set(domain, challenge, old_rrset=nil)
        if old_rrset
          rrdatas = [ *old_rrset.rrdatas, challenge.record_content ]
        else
          rrdatas = [ challenge.record_content ]
        end
        Google::Apis::DnsV1::ResourceRecordSet.new(
          name: [challenge.record_name, domain].join("."),
          type: challenge.record_type,
          rrdatas: rrdatas,
          ttl: @config[:ttl] || 5
        )
      end
    end
  end
end
