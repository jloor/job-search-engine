#!/usr/bin/env bash
# Build the relay image and push it to GHCR for Bunny Magic Containers to pull.
#
# Magic Containers only runs linux/amd64, so the platform is pinned rather than
# inherited from whatever machine runs this.
#
# Usage:  ./deploy.sh [tag]
set -euo pipefail

# ⚠️ No default. A registry owner baked in here means an operator who forgets to set it
# pushes to somebody else's namespace, or fails confusingly at push time.
OWNER="${GHCR_OWNER:?set GHCR_OWNER to your container registry namespace}"
IMAGE="ghcr.io/${OWNER}/job-search-relay"
TAG="${1:-$(date -u +%Y%m%d-%H%M)}"
ENGINE="$(command -v podman || command -v docker)"

cd "$(dirname "$0")"

echo "==> building ${IMAGE}:${TAG} (linux/amd64)"
# --format docker keeps the HEALTHCHECK, which podman's default OCI format drops.
"$ENGINE" build --platform linux/amd64 --format docker \
  -t "${IMAGE}:${TAG}" -t "${IMAGE}:latest" .

echo "==> verifying the image actually starts before anything is pushed"
CID=$("$ENGINE" run -d -P \
  -e API_TOKEN=smoke -e INBOUND_TOKEN=smoke -e APPROVAL_SECRET=smoke \
  -e DB_PATH=/tmp/smoke.db "${IMAGE}:${TAG}")
trap '"$ENGINE" rm -f "$CID" >/dev/null 2>&1 || true' EXIT
PORT=$("$ENGINE" port "$CID" 8080/tcp | head -1 | sed 's/.*://')
for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null && break
  sleep 0.4
done
curl -sf "http://127.0.0.1:${PORT}/health" | grep -q '"ok":true' \
  || { echo "image failed its own health check, not pushing"; "$ENGINE" logs "$CID" | tail -20; exit 1; }
echo "    health ok"

echo "==> pushing"
# Needs a GitHub token with write:packages:
#   gh auth refresh -h github.com -s write:packages
#   gh auth token | podman login ghcr.io -u "$OWNER" --password-stdin
"$ENGINE" push "${IMAGE}:${TAG}"
"$ENGINE" push "${IMAGE}:latest"

cat <<EOF

pushed ${IMAGE}:${TAG}

Next, in the Bunny dashboard (Magic Containers):
  1. The package is private, so connect the registry once:
     Type GitHub, username ${OWNER}, a read-only PAT with read:packages.
  2. Image: ${IMAGE}:${TAG}   Port: 8080
  3. Attach the database: Database > Access > Generate Tokens >
     "Add Secrets to Magic Container App". That injects BUNNY_DATABASE_URL
     and BUNNY_DATABASE_AUTH_TOKEN, which app.py reads by those exact names.
  4. Set the remaining secrets: API_TOKEN, INBOUND_TOKEN, APPROVAL_SECRET,
     SMTP_USER, SMTP_PASS, and TRUSTED_PROXY_HOPS to match Bunny's proxy depth.
     ⚠️ TRUSTED_PROXY_HOPS is the one that silently disables the IP allowlist
     if it is wrong. Verify it with the check in README.md before trusting it.
  5. No persistent volume is needed once BUNNY_DATABASE_URL is set.
EOF
