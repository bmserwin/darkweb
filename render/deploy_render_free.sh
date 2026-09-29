#!/usr/bin/env bash
# Deploy the entire platform to Render's FREE tier as ONE service.
#
# The single-container image (Dockerfile.single) runs the FastAPI backend,
# both simulated testbeds (TLS on loopback) and the built dashboard in one
# process on one port - exactly what the free plan allows.
#
# Prerequisites:
#   * a Render API key with permission on the target workspace
#   * billing configured on the workspace (Render requires a card on file
#     even for free-tier services: https://dashboard.render.com/billing)
#   * the GitHub repo pushed (https://github.com/bmserwin/darkweb)
#
# Usage:
#   RENDER_API_KEY=rnd_xxx RENDER_OWNER_ID=tea_xxx ./render/deploy_render_free.sh
set -euo pipefail

RENDER_API_KEY="${RENDER_API_KEY:?set RENDER_API_KEY}"
RENDER_OWNER_ID="${RENDER_OWNER_ID:?set RENDER_OWNER_ID}"
REPO="${REPO:-https://github.com/bmserwin/darkweb}"
BRANCH="${BRANCH:-main}"
REGION="${REGION:-oregon}"
API="https://api.render.com/v1"

echo "== Creating single free-tier web service (whole platform in one container) =="
RES=$(curl -s -X POST "$API/services" \
  -H "Authorization: Bearer $RENDER_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"type\": \"web_service\",
    \"name\": \"forensic-platform\",
    \"ownerId\": \"$RENDER_OWNER_ID\",
    \"repo\": \"$REPO\",
    \"branch\": \"$BRANCH\",
    \"plan\": \"free\",
    \"region\": \"$REGION\",
    \"autoDeploy\": \"yes\",
    \"serviceDetails\": {
      \"runtime\": \"docker\",
      \"dockerfilePath\": \"./Dockerfile.single\",
      \"dockerContext\": \"./\",
      \"port\": 8000,
      \"healthCheckPath\": \"/api/health\"
    },
    \"envVars\": [
      {\"key\": \"FORENSIC_ENVIRONMENT\", \"value\": \"render-free-single\"},
      {\"key\": \"FORENSIC_ALLOW_NETWORK_PROBES\", \"value\": \"true\"}
    ]
  }")

SERVICE_ID=$(echo "$RES" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('service',{}).get('id',''))" 2>/dev/null || true)

if [ -z "$SERVICE_ID" ]; then
  echo "ERROR: service creation failed:"
  echo "$RES" | python3 -m json.tool 2>/dev/null || echo "$RES"
  exit 1
fi

cat <<EOF

============================================================
 Deployment submitted!

 Service id : $SERVICE_ID
 Public URL : https://$SERVICE_ID.onrender.com
 Dashboard  : https://$SERVICE_ID.onrender.com/          (built React UI)
 API docs   : https://$SERVICE_ID.onrender.com/docs
 Health     : https://$SERVICE_ID.onrender.com/api/health

 The first build takes ~5-10 minutes (frontend npm build +
 pip install). Render sleeps free services after ~15 min
 idle; the first request afterwards pays a spin-up delay.

 Note: the case database (SQLite) lives on the instance's
 ephemeral disk and resets on redeploy. Attach a Render
 Disk at /app/data (paid) if you need persistence.

 Render dashboard: https://dashboard.render.com/
============================================================
EOF
