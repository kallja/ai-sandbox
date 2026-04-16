# --------------------------------------------------------------------------
# Artifact Registry
# --------------------------------------------------------------------------

resource "google_artifact_registry_repository" "relay" {
  project       = var.gcp_project
  location      = var.gcp_region
  repository_id = "oobate"
  format        = "DOCKER"
  description   = "Oobate relay container images"
}

# --------------------------------------------------------------------------
# Firestore
# --------------------------------------------------------------------------

resource "google_firestore_database" "queue" {
  project     = var.gcp_project
  name        = "oobate-queue"
  location_id = var.gcp_region
  type        = "FIRESTORE_NATIVE"
}

# TTL policy: auto-purge unread messages after 5 minutes.
resource "google_firestore_field" "queue_ttl" {
  project    = var.gcp_project
  database   = google_firestore_database.queue.name
  collection = "oobate_queue"
  field      = "created_at"

  ttl_config {}
}

# --------------------------------------------------------------------------
# Service Account
# --------------------------------------------------------------------------

resource "google_service_account" "relay" {
  account_id   = "oobate-relay"
  display_name = "Oobate Relay"
  project      = var.gcp_project
}

# Scoped Firestore access — datastore.user on the specific database only.
resource "google_project_iam_member" "relay_firestore" {
  project = var.gcp_project
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.relay.email}"

  condition {
    title      = "oobate-db-only"
    expression = "resource.name == 'projects/${var.gcp_project}/databases/${google_firestore_database.queue.name}'"
  }
}

# --------------------------------------------------------------------------
# Cloud Run v2
# --------------------------------------------------------------------------

resource "google_cloud_run_v2_service" "relay" {
  name     = "oobate-relay"
  location = var.gcp_region
  project  = var.gcp_project

  template {
    scaling {
      min_instance_count = 0
    }

    service_account = google_service_account.relay.email

    containers {
      image   = local.relay_image
      command = ["relay"]
      args    = ["--store=firestore", "--gcp-project=${var.gcp_project}", "--addr=:8080"]

      ports {
        container_port = 8080
      }

      # env {
      #   name  = "CF_ACCESS_CLIENT_ID"
      #   value = cloudflare_zero_trust_access_service_token.relay.client_id
      # }

      # env {
      #   name = "CF_ACCESS_CLIENT_SECRET"
      #   value_source {
      #     secret_key_ref {
      #       secret  = google_secret_manager_secret.cf_client_secret.id
      #       version = "latest"
      #     }
      #   }
      # }
    }
  }

  ingress = "INGRESS_TRAFFIC_ALL"
}

# Store the Cloudflare client secret in Secret Manager so it's not
# exposed as a plain-text env var in the Cloud Run revision.
# resource "google_secret_manager_secret" "cf_client_secret" {
#   secret_id = "oobate-cf-client-secret"
#   project   = var.gcp_project

#   replication {
#     auto {}
#   }
# }

# resource "google_secret_manager_secret_version" "cf_client_secret" {
#   secret      = google_secret_manager_secret.cf_client_secret.id
#   secret_data = cloudflare_zero_trust_access_service_token.relay.client_secret
# }

# Grant Cloud Run access to the secret.
# resource "google_secret_manager_secret_iam_member" "relay_secret_access" {
#   secret_id = google_secret_manager_secret.cf_client_secret.id
#   role      = "roles/secretmanager.secretAccessor"
#   member    = "serviceAccount:${google_service_account.relay.email}"
# }
