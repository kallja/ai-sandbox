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

output "artifact_registry_url" {
  description = "Docker repository URL for pushing relay images"
  value       = "${google_artifact_registry_repository.relay.location}-docker.pkg.dev/${var.gcp_project}/${google_artifact_registry_repository.relay.repository_id}"
}
