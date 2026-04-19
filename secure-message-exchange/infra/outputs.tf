output "cloud_run_url" {
  description = "Cloud Run direct URL for the relay server"
  value       = google_cloud_run_v2_service.e2ee_relay.uri
}

output "relay_registry_url" {
  description = "Artifact Registry URL for relay images"
  value       = "${google_artifact_registry_repository.e2ee_relay.location}-docker.pkg.dev/${var.gcp_project}/${google_artifact_registry_repository.e2ee_relay.repository_id}/relay"
}

output "client_registry_url" {
  description = "Artifact Registry URL for client images"
  value       = "${google_artifact_registry_repository.e2ee_client.location}-docker.pkg.dev/${var.gcp_project}/${google_artifact_registry_repository.e2ee_client.repository_id}/client"
}

output "service_account_email" {
  description = "E2EE relay service account email"
  value       = google_service_account.e2ee_relay.email
}
