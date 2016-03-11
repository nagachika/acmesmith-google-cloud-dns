require "acmesmith/challenge_responders/base"

require "json"
require "google/apis/dns_v1"

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
        domain = canonicalize(domain)
        zone_name = find_managed_zone(domain).name
        change = Google::Apis::DnsV1::Change.new
        change.additions = [
          resource_record_set(domain, challenge)
        ]
        @api.create_change(@project_id, zone_name, change)
      end

      def cleanup(domain, challenge)
        domain = canonicalize(domain)
        zone_name = find_managed_zone(domain).name
        change = Google::Apis::DnsV1::Change.new
        change.deletions = [
          resource_record_set(domain, challenge)
        ]
        @api.create_change(@project_id, zone_name, change)
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

      def resource_record_set(domain, challenge)
        Google::Apis::DnsV1::ResourceRecordSet.new(
          name: [challenge.record_name, domain].join("."),
          type: challenge.record_type,
          rrdatas: [challenge.record_content],
          ttl: @config[:ttl] || 5
        )
      end
    end
  end
end
