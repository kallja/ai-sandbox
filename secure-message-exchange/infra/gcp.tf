# --------------------------------------------------------------------------
# Artifact Registry
# --------------------------------------------------------------------------

resource "google_artifact_registry_repository" "e2ee_relay" {
  location      = var.gcp_region
  repository_id = "e2ee-relay"
  format        = "DOCKER"
  description   = "E2EE relay server container images"
}

resource "google_artifact_registry_repository" "e2ee_client" {
  location      = var.gcp_region
  repository_id = "e2ee-client"
  format        = "DOCKER"
  description   = "E2EE client container images"
}

# --------------------------------------------------------------------------
# Firestore (separate database from oob-auth)
# --------------------------------------------------------------------------

resource "google_firestore_database" "e2ee_queue" {
  project     = var.gcp_project
  name        = "e2ee-relay-queue"
  location_id = var.gcp_region
  type        = "FIRESTORE_NATIVE"
}

# TTL policy: auto-purge unread messages after 5 minutes.
resource "google_firestore_field" "queue_ttl" {
  project    = var.gcp_project
  database   = google_firestore_database.e2ee_queue.name
  collection = "e2ee_relay_queue"
  field      = "created_at"

  ttl_config {}
}

# --------------------------------------------------------------------------
# Service Account
# --------------------------------------------------------------------------

resource "google_service_account" "e2ee_relay" {
  account_id   = "e2ee-relay"
  display_name = "E2EE Relay Server"
  project      = var.gcp_project
}

# Scoped Firestore access — datastore.user on the specific database only.
resource "google_project_iam_member" "relay_firestore" {
  project = var.gcp_project
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.e2ee_relay.email}"

  condition {
    title      = "e2ee-db-only"
    expression = "resource.name == 'projects/${var.gcp_project}/databases/${google_firestore_database.e2ee_queue.name}'"
  }
}

# Artifact Registry read access for pulling images.
resource "google_artifact_registry_repository_iam_member" "relay_pull" {
  location   = google_artifact_registry_repository.e2ee_relay.location
  repository = google_artifact_registry_repository.e2ee_relay.repository_id
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.e2ee_relay.email}"
}

# --------------------------------------------------------------------------
# Secret Manager — Relay server identity keys
# --------------------------------------------------------------------------

resource "google_secret_manager_secret" "relay_ed25519_private" {
  secret_id = "e2ee-relay-ed25519-private"
  project   = var.gcp_project
  replication { auto {} }
}

resource "google_secret_manager_secret" "relay_x25519_private" {
  secret_id = "e2ee-relay-x25519-private"
  project   = var.gcp_project
  replication { auto {} }
}

resource "google_secret_manager_secret" "relay_ed25519_public" {
  secret_id = "e2ee-relay-ed25519-public"
  project   = var.gcp_project
  replication { auto {} }
}

resource "google_secret_manager_secret" "relay_x25519_public" {
  secret_id = "e2ee-relay-x25519-public"
  project   = var.gcp_project
  replication { auto {} }
}

# Grant Cloud Run service account access to secrets.
resource "google_secret_manager_secret_iam_member" "relay_ed25519_private_access" {
  secret_id = google_secret_manager_secret.relay_ed25519_private.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.e2ee_relay.email}"
}

resource "google_secret_manager_secret_iam_member" "relay_x25519_private_access" {
  secret_id = google_secret_manager_secret.relay_x25519_private.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.e2ee_relay.email}"
}

resource "google_secret_manager_secret_iam_member" "relay_ed25519_public_access" {
  secret_id = google_secret_manager_secret.relay_ed25519_public.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.e2ee_relay.email}"
}

resource "google_secret_manager_secret_iam_member" "relay_x25519_public_access" {
  secret_id = google_secret_manager_secret.relay_x25519_public.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.e2ee_relay.email}"
}

# --------------------------------------------------------------------------
# Cloud Run v2
# --------------------------------------------------------------------------

resource "google_cloud_run_v2_service" "e2ee_relay" {
  name     = "e2ee-relay"
  location = var.gcp_region
  project  = var.gcp_project

  template {
    scaling {
      min_instance_count = 0
    }

    service_account = google_service_account.e2ee_relay.email

    containers {
      image = var.relay_image

      ports {
        container_port = 8080
      }

      env {
        name  = "GCP_PROJECT"
        value = var.gcp_project
      }

      # Mount server private keys from Secret Manager.
      env {
        name = "RELAY_ED25519_PRIVATE"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.relay_ed25519_private.id
            version = "latest"
          }
        }
      }

      env {
        name = "RELAY_X25519_PRIVATE"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.relay_x25519_private.id
            version = "latest"
          }
        }
      }
    }
  }

  ingress = "INGRESS_TRAFFIC_ALL"
}
