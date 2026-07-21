#!/bin/bash
# shellcheck disable=SC2086,SC2089,SC2090,SC2162

# Exit on error
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
ENV_TEMPLATE="$SCRIPT_DIR/.env.template"

get_kv_value() {
    local file="$1"
    local key="$2"

    [ -f "$file" ] || return 0
    awk -F '=' -v search_key="$key" '$1 == search_key {print substr($0, index($0, "=") + 1); exit}' "$file"
}

resolve_repo_slug() {
    local remote_url slug

    if [ -n "${GITHUB_REPOSITORY:-}" ]; then
        printf '%s\n' "$GITHUB_REPOSITORY"
        return 0
    fi

    remote_url="$(git -C "$SCRIPT_DIR" config --get remote.origin.url 2>/dev/null || true)"
    case "$remote_url" in
        git@github.com:*)
            slug="${remote_url#git@github.com:}"
            ;;
        https://github.com/*)
            slug="${remote_url#https://github.com/}"
            ;;
        *)
            slug=""
            ;;
    esac

    slug="${slug%.git}"
    if [ -n "$slug" ]; then
        printf '%s\n' "$slug"
    fi
}

normalize_memory_limit() {
    local raw_value="$1"

    if [ -z "$raw_value" ]; then
        printf '%s\n' "1g"
    elif [[ "$raw_value" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        printf '%s\n' "${raw_value}g"
    else
        printf '%s\n' "$raw_value"
    fi
}

generate_runner_auth_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    fi
}

get_docker_host_platform() {
    local os arch

    os="$(docker version --format '{{.Server.Os}}' 2>/dev/null || true)"
    arch="$(docker version --format '{{.Server.Arch}}' 2>/dev/null || true)"

    if [ -n "$os" ] && [ -n "$arch" ]; then
        printf '%s/%s\n' "$os" "$arch"
    else
        printf '%s\n' "linux/amd64"
    fi
}

pull_runner_image_for_host() {
    local runner_ref="$1"
    local host_platform="$2"

    echo "Refreshing task runner image for host platform ${host_platform}..."
    docker pull --platform "$host_platform" "$runner_ref" >/dev/null
}

tag_local_release_image() {
    local image_ref="$1"
    local version_tag="$2"
    local local_tag="${GHCR_IMAGE}:${version_tag}"

    if docker image inspect "$image_ref" >/dev/null 2>&1; then
        docker tag "$image_ref" "$local_tag"
        echo "✅ Local convenience tag updated: ${local_tag}"
    fi
}

REPO_SLUG="$(resolve_repo_slug)"
if [ -z "$REPO_SLUG" ]; then
    TEMPLATE_OWNER="$(get_kv_value "$ENV_TEMPLATE" "GITHUB_REPOSITORY_OWNER_LC")"
    TEMPLATE_NAME="$(get_kv_value "$ENV_TEMPLATE" "REPOSITORY_NAME")"
    if [[ -n "$TEMPLATE_OWNER" && -n "$TEMPLATE_NAME" && "$TEMPLATE_OWNER" != "<github_owner>" && "$TEMPLATE_NAME" != "<repository_name>" ]]; then
        REPO_SLUG="${TEMPLATE_OWNER}/${TEMPLATE_NAME}"
    fi
fi

if [ -z "$REPO_SLUG" ]; then
    echo "❌ Could not determine the GitHub repository owner/name. Set remote.origin.url or update .env.template."
    exit 1
fi

REPO_OWNER="${REPO_SLUG%%/*}"
REPO_NAME="${REPO_SLUG##*/}"
GHCR_IMAGE="ghcr.io/${REPO_OWNER}/${REPO_NAME}/n8n-trusted"
GHCR_RUNNER_IMAGE="ghcr.io/${REPO_OWNER}/${REPO_NAME}/n8n-runners-trusted"
RELEASES_URL="https://github.com/${REPO_SLUG}/releases"

# ─── FLAGS ──────────────────────────────────────────────────────────────────
# Insecure lab mode is explicit; production defaults fail closed.
INSECURE_LAB_MODE=false
for arg in "$@"; do
  case $arg in
    --insecure-lab-mode) INSECURE_LAB_MODE=true ;;
    *) echo "Unknown option: $arg"; exit 2 ;;
  esac
done

echo "============================================="
echo "         ArtifactGate n8n Setup             "
echo "============================================="
echo ""

# ─── PREFLIGHT CHECKS ───────────────────────────────────────────────────────
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker and Docker Compose first."
    exit 1
fi

# ─── DETECT HOST IP ─────────────────────────────────────────────────────────
DETECTED_IP="127.0.0.1"

echo "The HOST_IP is required for n8n Webhook integrations."
echo "Detected your Host IP as: $DETECTED_IP"
echo ""
read -p "Enter your Host IP address (or press Enter to use $DETECTED_IP): " USER_IP
FINAL_IP=${USER_IP:-$DETECTED_IP}
if ! [[ "$FINAL_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[a-zA-Z0-9._:-]+$ ]]; then
    echo "❌ Invalid host address."
    exit 1
fi
echo "✅ Using HOST_IP: $FINAL_IP"

# ─── CHOOSE VERSION ─────────────────────────────────────────────────────────
echo ""
echo "Available releases: ${RELEASES_URL}"
read -p "Enter the n8n version to deploy (e.g. 1.55.3, or press Enter for latest): " USER_VERSION

if [ -z "$USER_VERSION" ] || [ "$USER_VERSION" = "latest" ]; then
    if command -v gh &> /dev/null && gh auth status &> /dev/null 2>&1; then
        USER_VERSION=$(gh release list --repo "$REPO_SLUG" --limit 20 --json tagName \
            | jq -r '.[].tagName' | grep -E '^n8n-[0-9]+\.[0-9]+\.[0-9]+$' \
            | sed 's/^n8n-//' | sort -V | tail -1)
        echo "Resolved latest release: $USER_VERSION"
    else
        echo "⚠️  Cannot auto-resolve latest without GitHub CLI. Please enter an explicit version."
        exit 1
    fi
fi
N8N_VERSION="$USER_VERSION"
if ! [[ "$N8N_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "❌ Version must use x.y.z format."
    exit 1
fi
RELEASE_TAG="n8n-${N8N_VERSION}"

# ─── RESOURCE LIMITS ────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "   Container Resource Limits (Hardening)     "
echo "============================================="
echo "These limits cap the blast radius if the container is compromised."
echo "Press Enter to accept the defaults."
echo ""

read -p "Memory limit in GB by default (e.g. 1, 2, 512m, 1g) [default: 1g]: " INPUT_MEM
MEM_LIMIT="$(normalize_memory_limit "$INPUT_MEM")"

read -p "CPU limit (e.g. 0.5, 1.0, 2.0) [default: 1.0]: " INPUT_CPU
CPU_LIMIT=${INPUT_CPU:-1.0}

read -p "Max processes (pids_limit) [default: 200]: " INPUT_PIDS
PIDS_LIMIT=${INPUT_PIDS:-200}
if ! [[ "$MEM_LIMIT" =~ ^[0-9]+([.][0-9]+)?[kKmMgG]?$ ]] || \
   ! [[ "$CPU_LIMIT" =~ ^[0-9]+([.][0-9]+)?$ ]] || \
   ! [[ "$PIDS_LIMIT" =~ ^[1-9][0-9]*$ ]]; then
    echo "❌ Invalid resource limit."
    exit 1
fi

echo ""
echo "✅ Resource limits: memory=${MEM_LIMIT}, cpus=${CPU_LIMIT}, pids=${PIDS_LIMIT}"

# ─── FETCH DIGEST FROM GITHUB RELEASE ───────────────────────────────────────
echo ""
echo "---------------------------------------------"
echo "🔍 Fetching digest for n8n-trusted:${N8N_VERSION} from GitHub Release..."
echo "---------------------------------------------"

GHCR_DIGEST=""
RUNNER_GHCR_DIGEST=""
if command -v gh &> /dev/null && gh auth status &> /dev/null 2>&1; then
    RELEASE_BODY=$(gh release view "$RELEASE_TAG" --repo "$REPO_SLUG" --json body -q '.body' 2>/dev/null || echo "")
    GHCR_DIGEST=$(printf '%s\n' "$RELEASE_BODY" | sed -nE 's/.*n8n digest: `?(sha256:[[:xdigit:]]{64}).*/\1/p' | head -1)
    RUNNER_GHCR_DIGEST=$(printf '%s\n' "$RELEASE_BODY" | sed -nE 's/.*runner digest: `?(sha256:[[:xdigit:]]{64}).*/\1/p' | head -1)
fi

if [ -z "$GHCR_DIGEST" ] || [ -z "$RUNNER_GHCR_DIGEST" ]; then
    echo "⚠️  Could not fetch digest from GitHub Release."
    echo "❌ Both promoted image digests are required. Deployment aborted."
    exit 1
else
    echo "✅ GHCR digest: $GHCR_DIGEST"
fi

# ─── PROVENANCE VERIFICATION ────────────────────────────────────────────────
echo ""
echo "---------------------------------------------"
echo "🔐 Verifying Cryptographic Provenance..."
echo "---------------------------------------------"

if [ "$INSECURE_LAB_MODE" = true ]; then
    if [ "${ARTIFACTGATE_ENV:-}" != "lab" ]; then
        echo "❌ SECURITY EXCEPTION: --insecure-lab-mode requires setting ARTIFACTGATE_ENV=lab environment variable."
        exit 1
    fi
    if [ -t 0 ]; then
        echo "⚠️ WARNING: You are initiating a security verification bypass (--insecure-lab-mode)."
        echo "   This will skip cryptographic signature and policy verification."
        read -p "   Type 'CONFIRM' to proceed with the bypass: " confirm_insecure
        if [ "$confirm_insecure" != "CONFIRM" ]; then
            echo "❌ Bypass aborted by user."
            exit 1
        fi
    fi
    echo "   ⚠️  INSECURE LAB BYPASS ACTIVE: Cryptographic provenance verification is disabled."
    echo "      [AUDIT LOG ENTRY] Verification bypassed by request on $(date)"
else
    HAS_VERIFIED=false
    VERIFICATION_FAILED=false
    
    COSIGN_IDENTITY="https://github.com/${REPO_SLUG}/.github/workflows/image-promotion.yml@refs/heads/main"
    COSIGN_ISSUER="https://token.actions.githubusercontent.com"

    # 1. Attempt verification with Cosign (Keyless verify)
    if command -v cosign &> /dev/null; then
        echo "   🔍 Running Cosign keyless verification..."
        
        # Verify Signatures
        if cosign verify --certificate-identity="$COSIGN_IDENTITY" --certificate-oidc-issuer="$COSIGN_ISSUER" "${GHCR_IMAGE}@${GHCR_DIGEST}" >/dev/null 2>&1 && \
           cosign verify --certificate-identity="$COSIGN_IDENTITY" --certificate-oidc-issuer="$COSIGN_ISSUER" "${GHCR_RUNNER_IMAGE}@${RUNNER_GHCR_DIGEST}" >/dev/null 2>&1; then
            echo "   ✅ Cosign signatures verified for both application and runner."
            
            # Verify OpenVEX Attestations for both images
            if cosign verify-attestation --type openvex --certificate-identity="$COSIGN_IDENTITY" --certificate-oidc-issuer="$COSIGN_ISSUER" "${GHCR_IMAGE}@${GHCR_DIGEST}" >/dev/null 2>&1 && \
               cosign verify-attestation --type openvex --certificate-identity="$COSIGN_IDENTITY" --certificate-oidc-issuer="$COSIGN_ISSUER" "${GHCR_RUNNER_IMAGE}@${RUNNER_GHCR_DIGEST}" >/dev/null 2>&1; then
                echo "   ✅ Cosign OpenVEX attestations verified for both images."
                HAS_VERIFIED=true
            else
                echo "   ❌ Cosign OpenVEX attestation missing or invalid for one or both images."
                VERIFICATION_FAILED=true
            fi
        else
            echo "   ❌ Cosign signature verification failed for one or both images."
            VERIFICATION_FAILED=true
        fi
    fi
    
    # 2. Attempt verification with GitHub CLI (with explicit identity/repo/predicate constraints)
    if [ "$VERIFICATION_FAILED" = false ] && command -v gh &> /dev/null && gh auth status &> /dev/null 2>&1; then
        echo "   🔍 Running GitHub CLI attestation verification..."
        
        # Provenance constraints
        if gh attestation verify "oci://${GHCR_IMAGE}@${GHCR_DIGEST}" \
             --repo "$REPO_SLUG" \
             --cert-identity "$COSIGN_IDENTITY" \
             --predicate-type "https://slsa.dev/provenance/v1" >/dev/null 2>&1 && \
           gh attestation verify "oci://${GHCR_RUNNER_IMAGE}@${RUNNER_GHCR_DIGEST}" \
             --repo "$REPO_SLUG" \
             --cert-identity "$COSIGN_IDENTITY" \
             --predicate-type "https://slsa.dev/provenance/v1" >/dev/null 2>&1; then
            echo "   ✅ GitHub SLSA build provenance verified."
            
            # SBOM constraints
            if gh attestation verify "oci://${GHCR_IMAGE}@${GHCR_DIGEST}" \
                 --repo "$REPO_SLUG" \
                 --cert-identity "$COSIGN_IDENTITY" \
                 --predicate-type "https://spdx.dev/Document" >/dev/null 2>&1 && \
               gh attestation verify "oci://${GHCR_RUNNER_IMAGE}@${RUNNER_GHCR_DIGEST}" \
                 --repo "$REPO_SLUG" \
                 --cert-identity "$COSIGN_IDENTITY" \
                 --predicate-type "https://spdx.dev/Document" >/dev/null 2>&1; then
                echo "   ✅ GitHub SBOM attestations verified."
                HAS_VERIFIED=true
            else
                echo "   ❌ GitHub SBOM attestation missing or invalid."
                VERIFICATION_FAILED=true
            fi
        else
            echo "   ❌ GitHub SLSA build provenance verification failed."
            VERIFICATION_FAILED=true
        fi
    fi
    
    # 3. Decision
    if [ "$VERIFICATION_FAILED" = true ]; then
        echo ""
        echo "❌ SECURITY ALERT: Provenance verification FAILED."
        echo "   The image may have been tampered with or did not originate from the trusted pipeline."
        echo "   Deployment aborted."
        exit 1
    elif [ "$HAS_VERIFIED" = false ]; then
        echo ""
        echo "⚠️  Provenance verification requires either Cosign or the GitHub CLI (gh) to be authenticated."
        echo "   Please install Cosign (https://sigstore.dev) or authenticate the GitHub CLI (gh auth login)."
        echo "   Alternatively, use --insecure-lab-mode for a local-only verification bypass."
        echo "❌ Deployment aborted."
        exit 1
    else
        echo "✅ Cryptographic trust verification passed."
    fi
fi

# ─── WRITE .ENV ─────────────────────────────────────────────────────────────
PREV_IDENTIFIER=""
N8N_HOST_PORT="$(get_kv_value "$ENV_FILE" "N8N_HOST_PORT")"
N8N_CONTAINER_PORT="$(get_kv_value "$ENV_FILE" "N8N_CONTAINER_PORT")"
N8N_RUNNERS_BROKER_PORT="$(get_kv_value "$ENV_FILE" "N8N_RUNNERS_BROKER_PORT")"
N8N_RUNNERS_AUTO_SHUTDOWN_TIMEOUT="$(get_kv_value "$ENV_FILE" "N8N_RUNNERS_AUTO_SHUTDOWN_TIMEOUT")"
N8N_RUNNERS_AUTH_TOKEN="$(get_kv_value "$ENV_FILE" "N8N_RUNNERS_AUTH_TOKEN")"
PUBLIC_BASE_URL="$(get_kv_value "$ENV_FILE" "PUBLIC_BASE_URL")"

if [ ! -f "$ENV_FILE" ]; then
    echo ""
    echo "📝 Creating .env file from template..."
    cp "$ENV_TEMPLATE" "$ENV_FILE"
else
    echo ""
    echo "📝 Updating existing .env file..."
    PREV_IDENTIFIER=$(grep '^N8N_IMAGE_IDENTIFIER=' "$ENV_FILE" | cut -d '=' -f 2- || true)
fi

N8N_HOST_PORT=${N8N_HOST_PORT:-5678}
N8N_CONTAINER_PORT=${N8N_CONTAINER_PORT:-5678}
N8N_RUNNERS_BROKER_PORT=${N8N_RUNNERS_BROKER_PORT:-5679}
N8N_RUNNERS_AUTO_SHUTDOWN_TIMEOUT=${N8N_RUNNERS_AUTO_SHUTDOWN_TIMEOUT:-15}
PUBLIC_BASE_URL=${PUBLIC_BASE_URL:-https://n8n.example.com/}
read -r -p "Public HTTPS URL [${PUBLIC_BASE_URL}]: " INPUT_PUBLIC_BASE_URL
PUBLIC_BASE_URL=${INPUT_PUBLIC_BASE_URL:-$PUBLIC_BASE_URL}
if ! [[ "$PUBLIC_BASE_URL" =~ ^https://[A-Za-z0-9._:-]+/.*$ ]]; then
    echo "❌ PUBLIC_BASE_URL must be an https:// URL ending in or containing a path slash."
    exit 1
fi
if [ -z "$N8N_RUNNERS_AUTH_TOKEN" ] || [ "$N8N_RUNNERS_AUTH_TOKEN" = "<random_secure_token>" ]; then
    N8N_RUNNERS_AUTH_TOKEN="$(generate_runner_auth_token)"
fi

SED_CMD="sed -i"
[[ "$OSTYPE" == "darwin"* ]] && SED_CMD="sed -i ''"

grep -q '^PUBLIC_BASE_URL=' "$ENV_FILE" || printf '%s\n' 'PUBLIC_BASE_URL=' >> "$ENV_FILE"
grep -q '^N8N_RUNNERS_IMAGE_IDENTIFIER=' "$ENV_FILE" || printf '%s\n' 'N8N_RUNNERS_IMAGE_IDENTIFIER=' >> "$ENV_FILE"

$SED_CMD "s|^HOST_IP=.*|HOST_IP=$FINAL_IP|" "$ENV_FILE"
$SED_CMD "s|^PUBLIC_BASE_URL=.*|PUBLIC_BASE_URL=$PUBLIC_BASE_URL|" "$ENV_FILE"
$SED_CMD "s|^GITHUB_REPOSITORY_OWNER_LC=.*|GITHUB_REPOSITORY_OWNER_LC=$REPO_OWNER|" "$ENV_FILE"
$SED_CMD "s|^REPOSITORY_NAME=.*|REPOSITORY_NAME=$REPO_NAME|" "$ENV_FILE"
$SED_CMD "s|^N8N_HOST_PORT=.*|N8N_HOST_PORT=$N8N_HOST_PORT|" "$ENV_FILE"
$SED_CMD "s|^N8N_CONTAINER_PORT=.*|N8N_CONTAINER_PORT=$N8N_CONTAINER_PORT|" "$ENV_FILE"
$SED_CMD "s|^N8N_RUNNERS_BROKER_PORT=.*|N8N_RUNNERS_BROKER_PORT=$N8N_RUNNERS_BROKER_PORT|" "$ENV_FILE"
$SED_CMD "s|^N8N_RUNNERS_AUTO_SHUTDOWN_TIMEOUT=.*|N8N_RUNNERS_AUTO_SHUTDOWN_TIMEOUT=$N8N_RUNNERS_AUTO_SHUTDOWN_TIMEOUT|" "$ENV_FILE"
$SED_CMD "s|^N8N_RUNNERS_AUTH_TOKEN=.*|N8N_RUNNERS_AUTH_TOKEN=$N8N_RUNNERS_AUTH_TOKEN|" "$ENV_FILE"
$SED_CMD "s|^N8N_IMAGE_VERSION=.*|N8N_IMAGE_VERSION=$N8N_VERSION|" "$ENV_FILE"
$SED_CMD "s|^MEM_LIMIT=.*|MEM_LIMIT=$MEM_LIMIT|" "$ENV_FILE"
$SED_CMD "s|^CPU_LIMIT=.*|CPU_LIMIT=$CPU_LIMIT|" "$ENV_FILE"
$SED_CMD "s|^PIDS_LIMIT=.*|PIDS_LIMIT=$PIDS_LIMIT|" "$ENV_FILE"

if [ -n "$GHCR_DIGEST" ] && [ -n "$RUNNER_GHCR_DIGEST" ]; then
    $SED_CMD "s|^N8N_IMAGE_IDENTIFIER=.*|N8N_IMAGE_IDENTIFIER=@$GHCR_DIGEST|" "$ENV_FILE"
    $SED_CMD "s|^N8N_RUNNERS_IMAGE_IDENTIFIER=.*|N8N_RUNNERS_IMAGE_IDENTIFIER=@$RUNNER_GHCR_DIGEST|" "$ENV_FILE"
    echo "✅ Digest written to .env — Docker will run the exact attested image."
    DEPLOY_IMAGE_REF="${GHCR_IMAGE}@${GHCR_DIGEST}"
fi
chmod 600 "$ENV_FILE"

# ─── DEPLOY ─────────────────────────────────────────────────────────────────
echo ""
echo "🚀 Deploying n8n ${N8N_VERSION}..."
echo "---------------------------------------------"
echo "Image platform: automatic host-native selection"
echo "Task runners: external mode via broker port ${N8N_RUNNERS_BROKER_PORT}"

HOST_PLATFORM="$(get_docker_host_platform)"
pull_runner_image_for_host "${GHCR_RUNNER_IMAGE}@${RUNNER_GHCR_DIGEST}" "$HOST_PLATFORM"

docker compose up -d
tag_local_release_image "$DEPLOY_IMAGE_REF" "$N8N_VERSION"

echo "---------------------------------------------"
echo "⏳ Waiting for n8n to start..."
STARTED=false
POST_DEPLOY_CHECK=false
for _ in $(seq 1 18); do
    if docker ps --filter label=com.docker.compose.service=n8n --filter status=running --format '{{.Names}}' | grep -q . \
        && docker ps --filter label=com.docker.compose.service=task-runners --filter status=running --format '{{.Names}}' | grep -q .; then
        STATUS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://${FINAL_IP}:${N8N_HOST_PORT}/healthz" || true)
        STATUS_BODY=$(curl -s "http://${FINAL_IP}:${N8N_HOST_PORT}/healthz" || true)
        if [ "$STATUS_CODE" = "200" ] && echo "$STATUS_BODY" | grep -q '"status":"ok"'; then
            STARTED=true
            
            # Post-deployment image digest verification
            RUNNING_CONTAINER_ID=$(docker compose ps -q n8n 2>/dev/null || true)
            if [ -n "$RUNNING_CONTAINER_ID" ]; then
                RUNNING_IMAGE_ID=$(docker inspect --format='{{.Image}}' "$RUNNING_CONTAINER_ID" 2>/dev/null || true)
                if [ -n "$RUNNING_IMAGE_ID" ]; then
                    REPO_DIGESTS=$(docker image inspect "$RUNNING_IMAGE_ID" --format='{{.RepoDigests}}' 2>/dev/null || true)
                    if echo "$REPO_DIGESTS" | grep -q "$GHCR_DIGEST"; then
                        echo "   ✅ Post-deployment digest validation passed: running image digest matches $GHCR_DIGEST."
                        POST_DEPLOY_CHECK=true
                    else
                        echo "   ❌ Post-deployment digest validation FAILED: running image digest does not match the promoted target digest."
                        POST_DEPLOY_CHECK=false
                    fi
                fi
            fi
            break
        fi
    fi
    sleep 5
done

if [ "$STARTED" = true ] && [ "$POST_DEPLOY_CHECK" = true ]; then
    echo ""
    echo "🎉 SUCCESS! n8n ${N8N_VERSION} deployed."
    echo "============================================="
    echo "🔗 Access your n8n instance at:"
    echo "http://$FINAL_IP:${N8N_HOST_PORT}"
    echo "============================================="
    echo "To view logs: docker compose logs -f"
    if [ -n "$PREV_IDENTIFIER" ]; then
        echo "To rollback:  $SED_CMD 's|^N8N_IMAGE_IDENTIFIER=.*|N8N_IMAGE_IDENTIFIER=$PREV_IDENTIFIER|' $ENV_FILE && docker compose up -d"
    fi
else
    echo "❌ Deployment verification FAILED. n8n did not start successfully, or digest validation failed."
    echo "   Run 'docker compose logs' to diagnose."
    exit 1
fi

# ─── AUTO-UPGRADE ────────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "       🔄 Auto-Upgrade Configuration         "
echo "============================================="
read -p "Enable daily auto-upgrade? Checks for new versions every day and upgrades automatically. (y/N): " ENABLE_AUTOUPGRADE
ENABLE_AUTOUPGRADE=${ENABLE_AUTOUPGRADE:-N}

if [[ "$ENABLE_AUTOUPGRADE" =~ ^[Yy]$ ]]; then
    UPGRADE_SCRIPT="$(pwd)/upgrade.sh"
    CRON_LOG="$(pwd)/upgrade.log"

    # Make the upgrade script executable
    chmod +x "$UPGRADE_SCRIPT"

    # Remove any existing cron entry for upgrade.sh, then register a fresh one
    CRON_ENTRY="0 3 * * * $UPGRADE_SCRIPT >> $CRON_LOG 2>&1"
    ( crontab -l 2>/dev/null | grep -v "$UPGRADE_SCRIPT" ; echo "$CRON_ENTRY" ) | crontab -

    echo "✅ Daily auto-upgrade enabled. Runs at 03:00 every night."
    echo "   Upgrade log: $CRON_LOG"
    echo "   To disable: crontab -e  and remove the upgrade.sh line."
else
    echo "   Auto-upgrade not enabled. You can run ./upgrade.sh manually to upgrade."
fi
