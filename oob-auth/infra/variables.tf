variable "gcp_project" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region for Cloud Run and Firestore"
  type        = string
  default     = "europe-north1"
}

# variable "cloudflare_zone_id" {
#   description = "Cloudflare DNS zone ID"
#   type        = string
# }

variable "domain" {
  description = "Custom domain for the relay (e.g. relay.example.com)"
  type        = string
}

variable "relay_image" {
  description = "Container image URL for the relay server"
  type        = string
  default     = null
}

locals {
  relay_image = coalesce(var.relay_image, "${var.gcp_region}-docker.pkg.dev/${var.gcp_project}/${google_artifact_registry_repository.relay.repository_id}/relay:latest")
}

# variable "allowed_countries" {
#   description = "List of allowed country codes for geo-blocking"
#   type        = list(string)
#   default     = ["FI", "SE", "NO", "DK", "DE", "US"]
# }
