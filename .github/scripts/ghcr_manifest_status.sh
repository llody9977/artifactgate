#!/usr/bin/env bash
# Report the HTTP status of a GHCR manifest lookup — the promotion idempotency check.
#
# Usage: ghcr_manifest_status.sh <owner/repo> <package> <version>
#
# Echoes the HTTP status code, or 000 when no registry token could be obtained
# or the request itself failed.
#
# Callers must treat anything other than 200 as "not promoted" and fall through
# to a normal scan+promote. The asymmetry is deliberate: a wrong "not promoted"
# only costs a redundant run, while a wrong "already promoted" would silently
# skip a promotion that was actually needed.
#
# Two details this request has to get right, or it always reports 404:
#   1. Promoted tags are OCI image indexes (docker buildx imagetools create).
#      GHCR answers 404 unless Accept lists that media type.
#   2. The /v2/ manifest API wants a registry token exchanged via ghcr.io/token,
#      not GITHUB_TOKEN presented directly as a bearer.
#
# GITHUB_TOKEN (optional) authenticates the exchange, which is required for
# private packages. If it is absent or rejected, the exchange retries
# anonymously so the check still works for public packages.
set -euo pipefail

REPOSITORY="${1:?repository required (owner/repo)}"
PACKAGE="${2:?package required}"
VERSION="${3:?version required}"

ACCEPT_HEADER='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
TOKEN_URL="https://ghcr.io/token?service=ghcr.io&scope=repository:${REPOSITORY}/${PACKAGE}:pull"

registry_token=""
if [ -n "${GITHUB_TOKEN:-}" ]; then
    registry_token=$(curl -s -u "${GITHUB_ACTOR:-x-access-token}:${GITHUB_TOKEN}" "$TOKEN_URL" \
        | jq -r '.token // empty' || true)
fi

if [ -z "$registry_token" ]; then
    registry_token=$(curl -s "$TOKEN_URL" | jq -r '.token // empty' || true)
fi

if [ -z "$registry_token" ]; then
    echo "000"
    exit 0
fi

# `|| true` keeps a transient network error from aborting the caller under
# `bash -e`; curl still emits 000, which reads as "not promoted".
status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer ${registry_token}" \
    -H "Accept: ${ACCEPT_HEADER}" \
    "https://ghcr.io/v2/${REPOSITORY}/${PACKAGE}/manifests/${VERSION}" || true)

echo "${status:-000}"
