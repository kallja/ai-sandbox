terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
    # cloudflare = {
    #   source  = "cloudflare/cloudflare"
    #   version = "~> 5.0"
    # }
  }
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

# provider "cloudflare" {
#   # Authenticated via CLOUDFLARE_API_TOKEN env var.
# }
