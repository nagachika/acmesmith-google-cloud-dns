# acmesmith-google-cloud-dns

This gem is a plugin for [Acmesmith](https://github.com/sorah/acmesmith) and implements an automated `dns-01` challenge responder using Google Cloud DNS.

With this plugin and Acmesmith, you can automate to authorize your domain hosted on [Google Cloud DNS](https://cloud.google.com/dns/) and request TLS certificates for the domains against [Let's Encrypt](https://letsencrypt.org/) and other CAs supporting the ACME protocol.

## Usage
### Prerequisites
- You need to have control of your domain name to change its authoritative nameservers.
- You need to have service account of Google Cloud Platform to operate Google Cloud DNS via API.

### Preparation
- Ask your DNSaaS provider to host a zone for your domain name. They will tell you the DNS content servers that host the zone.
- Ask your domain registrar to set the authoritative nameservers of your domain to the content servers provided by the DNSaaS.

### Installation
Install `acmesith-google-cloud-dns` gem along with `acmesmith`. You can just do `gem install acmesith-google-cloud-dns` or use Bundler if you want.

### Configuration
Use `google-cloud-dns` challenge responder in your `acmesmith.yml`. General instructions about `acmesmith.yml` is available in the manual of Acmesmith.

Write your `tenant_name`, `username`, `password` and `auth_url` in `acmesmith.yml`, or if you don't want to write them down into the file, export these values as the corresponding environment variables `OS_TENANT_NAME`, `OS_USERNAME`, `OS_PASSWORD` and `OS_AUTH_URL`.

```yaml
endpoint: https://acme-v01.api.letsencrypt.org/

storage:
  type: filesystem
  path: /path/to/key/storage

challenge_responders:
  - google_cloud_dns:
      project_id: my-project-id # GCP Project ID. Be careful it's different from Project Name.
      compute_engine_service_account: true # (pick-one): You can use GCE VM instance scope
      private_key_json_file: /path/to/credential.json # (pick-one) Only JSON key file is supported
      ttl: 5  # (optional) long TTL hinders re-authorization, but a DNSaaS provider may restrict short TTL
```

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
