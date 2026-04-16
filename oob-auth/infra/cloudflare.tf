# # --------------------------------------------------------------------------
# # DNS — proxied CNAME to Cloud Run
# # --------------------------------------------------------------------------

# resource "cloudflare_dns_record" "relay" {
#   zone_id = var.cloudflare_zone_id
#   name    = var.domain
#   type    = "CNAME"
#   content = google_cloud_run_v2_service.relay.uri
#   proxied = true
#   ttl     = 1 # Automatic for proxied records.
# }

# # --------------------------------------------------------------------------
# # Zero Trust — Service Token for CF-Access header injection
# # --------------------------------------------------------------------------

# resource "cloudflare_zero_trust_access_service_token" "relay" {
#   zone_id = var.cloudflare_zone_id
#   name    = "oob-auth-relay"
# }

# # --------------------------------------------------------------------------
# # WAF — Rate limiting on queue endpoints (20 req/min/IP)
# # --------------------------------------------------------------------------

# resource "cloudflare_ruleset" "rate_limit" {
#   zone_id = var.cloudflare_zone_id
#   name    = "oob-auth-rate-limit"
#   kind    = "zone"
#   phase   = "http_ratelimit"

#   rules = [{
#     action      = "block"
#     expression  = "(http.request.uri.path wildcard \"/api/v1/queue/*\")"
#     description = "Rate limit queue endpoints to 20 req/min/IP"

#     ratelimit = {
#       characteristics     = ["ip.src"]
#       period              = 60
#       requests_per_period = 20
#       mitigation_timeout  = 60
#     }
#   }]
# }

# # --------------------------------------------------------------------------
# # WAF — Geo-blocking (drop traffic from outside allowed regions)
# # --------------------------------------------------------------------------

# resource "cloudflare_ruleset" "geo_block" {
#   zone_id = var.cloudflare_zone_id
#   name    = "oob-auth-geo-block"
#   kind    = "zone"
#   phase   = "http_request_firewall_custom"

#   rules = [{
#     action      = "block"
#     expression  = "(http.request.uri.path wildcard \"/api/v1/queue/*\" and not ip.geoip.country in {${join(" ", [for c in var.allowed_countries : "\"${c}\""])}})"
#     description = "Block traffic from outside allowed regions"
#   }]
# }

# # --------------------------------------------------------------------------
# # HTTP Request Header Modification — inject CF-Access headers
# # --------------------------------------------------------------------------

# resource "cloudflare_ruleset" "header_injection" {
#   zone_id = var.cloudflare_zone_id
#   name    = "oob-auth-header-injection"
#   kind    = "zone"
#   phase   = "http_request_late_transform"

#   rules = [{
#     action      = "rewrite"
#     expression  = "(http.request.uri.path wildcard \"/api/v1/queue/*\")"
#     description = "Inject CF-Access service token headers to origin"

#     action_parameters = {
#       headers = {
#         "CF-Access-Client-Id" = {
#           operation = "set"
#           value     = cloudflare_zero_trust_access_service_token.relay.client_id
#         }
#         "CF-Access-Client-Secret" = {
#           operation = "set"
#           value     = cloudflare_zero_trust_access_service_token.relay.client_secret
#         }
#       }
#     }
#   }]
# }
