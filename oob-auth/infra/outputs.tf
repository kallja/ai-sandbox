output "cloud_run_url" {
  description = "Cloud Run service URL (direct, bypasses Cloudflare)"
  value       = google_cloud_run_v2_service.relay.uri
}

output "relay_domain" {
  description = "Public relay domain (via Cloudflare)"
  value       = var.domain
}

output "service_account_email" {
  description = "Relay service account email"
  value       = google_service_account.relay.email
}
