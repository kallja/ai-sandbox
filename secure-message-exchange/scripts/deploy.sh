#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${0}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
INFRA_DIR="${ROOT_DIR}/infra"

echo "=== E2EE Relay Deploy ==="

# Phase 1: Create registry, secrets, Firestore, IAM (no Cloud Run yet).
echo ""
echo "Phase 1: Creating infrastructure prerequisites..."
terraform -chdir="${INFRA_DIR}" apply \
  -target=google_artifact_registry_repository.e2ee_relay \
  -target=google_artifact_registry_repository.e2ee_client \
  -target=google_secret_manager_secret.relay_ed25519_private \
  -target=google_secret_manager_secret.relay_x25519_private \
  -target=google_secret_manager_secret.relay_ed25519_public \
  -target=google_secret_manager_secret.relay_x25519_public \
  -target=google_firestore_database.e2ee_queue \
  -target=google_firestore_field.queue_ttl \
  -target=google_service_account.e2ee_relay \
  -target=google_project_iam_member.relay_firestore \
  -target=google_artifact_registry_repository_iam_member.relay_pull \
  -target=google_secret_manager_secret_iam_member.relay_ed25519_private_access \
  -target=google_secret_manager_secret_iam_member.relay_x25519_private_access \
  -target=google_secret_manager_secret_iam_member.relay_ed25519_public_access \
  -target=google_secret_manager_secret_iam_member.relay_x25519_public_access \
  -var="relay_image=placeholder" \
  -var="client_image=placeholder"

# Phase 2: Provision keys if needed.
echo ""
echo "Phase 2: Key provisioning check"
echo "If relay keys are not yet provisioned, run:"
echo "  ./scripts/provision-keys.sh"
echo ""
read -rp "Press Enter when secrets are populated (or if already done)..."

# Phase 3: Build and push images.
echo ""
echo "Phase 3: Building and pushing container images..."

RELAY_REPO=$(terraform -chdir="${INFRA_DIR}" output -raw relay_registry_url)
CLIENT_REPO=$(terraform -chdir="${INFRA_DIR}" output -raw client_registry_url)

BUILD_TAG="build-$(date +%s)"

docker build -f "${ROOT_DIR}/Dockerfile.relay" -t "e2ee-relay:${BUILD_TAG}" "${ROOT_DIR}"
docker build -f "${ROOT_DIR}/Dockerfile.client" -t "e2ee-client:${BUILD_TAG}" "${ROOT_DIR}"

docker tag "e2ee-relay:${BUILD_TAG}" "${RELAY_REPO}:${BUILD_TAG}"
docker tag "e2ee-client:${BUILD_TAG}" "${CLIENT_REPO}:${BUILD_TAG}"

# Authenticate to Artifact Registry.
REGION=$(echo "${RELAY_REPO}" | cut -d- -f1-2)
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

docker push "${RELAY_REPO}:${BUILD_TAG}"
docker push "${CLIENT_REPO}:${BUILD_TAG}"

# Phase 4: Capture SHA256 digests.
echo ""
echo "Phase 4: Capturing image digests..."

RELAY_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${RELAY_REPO}:${BUILD_TAG}" | cut -d@ -f2)
CLIENT_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${CLIENT_REPO}:${BUILD_TAG}" | cut -d@ -f2)

RELAY_IMAGE="${RELAY_REPO}@${RELAY_DIGEST}"
CLIENT_IMAGE="${CLIENT_REPO}@${CLIENT_DIGEST}"

echo "  Relay:  ${RELAY_IMAGE}"
echo "  Client: ${CLIENT_IMAGE}"

# Phase 5: Full terraform apply with image digests.
echo ""
echo "Phase 5: Deploying Cloud Run service..."
terraform -chdir="${INFRA_DIR}" apply \
  -var="relay_image=${RELAY_IMAGE}" \
  -var="client_image=${CLIENT_IMAGE}"

echo ""
echo "=== Deploy complete ==="
terraform -chdir="${INFRA_DIR}" output
