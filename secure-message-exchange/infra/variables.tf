variable "gcp_project" {
  description = "GCP project ID (same as oob-auth)"
  type        = string
}

variable "gcp_region" {
  description = "GCP region for Cloud Run and Firestore"
  type        = string
  default     = "europe-north1"
}

variable "relay_image" {
  description = "Full container image reference for the relay server (region-docker.pkg.dev/project/repo/image@sha256:digest)"
  type        = string
}

variable "client_image" {
  description = "Full container image reference for the client (for tracking; not deployed to Cloud Run)"
  type        = string
}
