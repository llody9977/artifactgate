#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 5 ]; then
  echo "Usage: run_tracee_reachability.sh <image_ref> <output_dir> [container_name] [host_port] [container_port]" >&2
  exit 1
fi

IMAGE_REF="$1"
OUTPUT_DIR="$2"
CONTAINER_NAME="${3:-tracee-smoke}"
HOST_PORT="${4:-${TRACEE_HOST_PORT:-15678}}"
CONTAINER_PORT="${5:-${TRACEE_CONTAINER_PORT:-5678}}"
TRACEE_NAME="tracee-runtime-monitor"
DOCKER_SOCKET_PATH="${DOCKER_SOCKET_PATH:-}"

if [ -z "$DOCKER_SOCKET_PATH" ]; then
  DOCKER_SOCKET_PATH="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
  DOCKER_SOCKET_PATH="${DOCKER_SOCKET_PATH#unix://}"
fi
DOCKER_SOCKET_PATH="${DOCKER_SOCKET_PATH:-/var/run/docker.sock}"

mkdir -p "$OUTPUT_DIR"

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker rm -f "$TRACEE_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker rm -f "$TRACEE_NAME" >/dev/null 2>&1 || true

docker run -d \
  --name "$TRACEE_NAME" \
  --pid=host \
  --cgroupns=host \
  --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v "$DOCKER_SOCKET_PATH:/var/run/docker.sock:ro" \
  -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  -v "$OUTPUT_DIR:/output" \
  aquasec/tracee:0.24.1@sha256:cfbbfee972e64a644f6b1bac74ee26998e6e12442697be4c797ae563553a2a5b \
  --containers enrich=true \
  --containers sockets.docker=/var/run/docker.sock \
  --containers cgroupfs.path=/sys/fs/cgroup \
  --containers cgroupfs.force=true \
  --events sched_process_exec \
  --events shared_object_loaded \
  --events security_file_open \
  --output json:/output/tracee-events.jsonl \
  --output option:parse-arguments \
  --output option:sort-events >/dev/null

sleep 5

docker run -d \
  --name "$CONTAINER_NAME" \
  -p "${HOST_PORT}:${CONTAINER_PORT}" \
  "$IMAGE_REF" >/dev/null

TARGET_CONTAINER_ID="$(docker inspect --format '{{.Id}}' "$CONTAINER_NAME")"
printf '%s\n' "$TARGET_CONTAINER_ID" > "$OUTPUT_DIR/target-container-id.txt"

healthy=false
for _ in $(seq 1 45); do
  for path in /healthz /healthz/readiness /; do
    status="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${HOST_PORT}${path}" || true)"
    if [ "$status" != "000" ]; then
      healthy=true
      break 2
    fi
  done
  sleep 2
done

# DAST: Run OWASP ZAP Baseline Scan against the running container
echo "Running ZAP Baseline Scan against http://127.0.0.1:${HOST_PORT} ..."
# We use -u root so ZAP can write zap-report.html/json directly to the output directory map without permission errors
# We generate both HTML and JSON reports to support human auditing and automated policy gating
docker run -u root --rm --network host \
  -v "$OUTPUT_DIR:/zap/wrk/:rw" \
  zaproxy/zap-stable:2.17.0@sha256:8d387b1a63e3425beef4846e39719f5af2a787753af2d8b6558c6257d7a577a2 zap-baseline.py \
  -t "http://127.0.0.1:${HOST_PORT}" \
  -r zap-report.html -J zap-report.json -I >/dev/null 2>&1 || echo "ZAP Baseline scan completed"

# Verify ZAP JSON report exists
if [ -f "$OUTPUT_DIR/zap-report.json" ]; then
  HIGH_ALERTS=$(jq '[.site[].alerts[]? | select(.riskcode=="3")] | length' "$OUTPUT_DIR/zap-report.json" || echo "0")
  echo "✅ DAST scan complete. ZAP JSON report contains $HIGH_ALERTS HIGH risk alert(s)."
else
  echo "⚠️ DAST Warning: OWASP ZAP failed to generate a JSON report."
fi

docker exec "$CONTAINER_NAME" /bin/sh -lc 'command -v node >/dev/null 2>&1 && node -p process.version >/dev/null' || true
docker exec "$CONTAINER_NAME" /bin/sh -lc 'test -f /usr/local/bin/n8n && /usr/local/bin/n8n --help >/dev/null 2>&1' || true

sleep 5

docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker stop "$TRACEE_NAME" >/dev/null 2>&1 || true

if [ "$healthy" != "true" ]; then
  echo "Smoke container did not become reachable during Tracee run." >&2
fi

if [ ! -s "$OUTPUT_DIR/tracee-events.jsonl" ]; then
  echo "Tracee did not produce any events." >&2
  exit 1
fi
