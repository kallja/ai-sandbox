variable "gcp_project" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region for Cloud Run and Firestore"
  type        = string
  default     = "europe-north1"
}

variable "cloudflare_zone_id" {
  description = "Cloudflare DNS zone ID"
  type        = string
}

variable "domain" {
  description = "Custom domain for the relay (e.g. relay.example.com)"
  type        = string
}

variable "relay_image" {
  description = "Container image URL for the relay server (e.g. <region>-docker.pkg.dev/<project>/oob-auth/relay:<tag>)"
  type        = string
}

variable "allowed_countries" {
  description = "List of allowed country codes for geo-blocking"
  type        = list(string)
  default     = ["FI", "SE", "NO", "DK", "DE", "US"]
}
