#!/usr/bin/env bash
# Deploy the Evidence-First Forensic Platform to Render.
#
# Prerequisites:
#   * a Render API key with permission on the target workspace
#   * billing configured on the workspace (Render requires a card on file
#     even for free-tier services: dashboard.render.com/billing)
#   * the GitHub repo pushed (https://github.com/bmserwin/darkweb)
#
# Usage:
#   RENDER_API_KEY=rnd_xxx RENDER_OWNER_ID=tea_xxx ./render/deploy_render.sh
#
# The script creates the two mock services first, reads back their real
# <service-id>.onrender.com hostnames from the API responses, then wires the
# backend to them, and finally creates the static frontend pointed at the
# backend's public URL.
set -euo pipefail

RENDER_API_KEY="${RENDER_API_KEY:?set RENDER_API_KEY}"
RENDER_OWNER_ID="${RENDER_OWNER_ID:?set RENDER_OWNER_ID}"
REPO="https://github.com/bmserwin/darkweb"
BRANCH="main"
REGION="${REGION:-oregon}"
PLAN="${PLAN:-free}"
API="https://api.render.com/v1"

_json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)" 2>/dev/null || echo ""; }

create_web() {
  curl -s -X POST "$API/services" \
    -H "Authorization: Bearer $RENDER_API_KEY" \
    -H "Content-Type: application/json" -d "$1"
}

service_json() { # $1 name, $2 dockerfilePath, $3 dockerContext, $4 port, $5 envVars JSON array, $6 healthcheck path
  cat <<EOF
{
  "type": "web_service",
  "name": "$1",
  "ownerId": "$RENDER_OWNER_ID",
  "repo": "$REPO",
  "branch": "$BRANCH",
  "plan": "$PLAN",
  "region": "$REGION",
  "autoDeploy": "yes",
  "serviceDetails": {
    "runtime": "docker",
    "dockerfilePath": "$2",
    "dockerContext": "$3",
    "port": $4,
    "healthCheckPath": "$6"
  },
  "envVars": $5
}
EOF
}

# ---------------------------------------------------------------- 1. mocks
echo "== 1/4 mock-onion =="
MOCK_ENV='[{"key":"MOCK_ROLE","value":"onion"},{"key":"RENDER_CERT_DIR","value":"/app/certs"}]'
RES=$(create_web "$(service_json forensic-mock-onion simulation/Dockerfile.simulation ./simulation 10000 "$MOCK_ENV" /healthz)")
ONION_ID=$(echo "$RES" | _json "d['service']['id']")
[ -n "$ONION_ID" ] || { echo "FAILED: $RES"; exit 1; }
ONION_HOST="${ONION_ID}.onrender.com"
echo "   id=$ONION_ID  host=$ONION_HOST"

echo "== 2/4 mock-clearnet =="
MOCK_ENV='[{"key":"MOCK_ROLE","value":"clearnet"},{"key":"RENDER_CERT_DIR","value":"/app/certs"}]'
RES=$(create_web "$(service_json forensic-mock-clearnet simulation/Dockerfile.simulation ./simulation 10000 "$MOCK_ENV" /healthz)")
CLEAR_ID=$(echo "$RES" | _json "d['service']['id']")
[ -n "$CLEAR_ID" ] || { echo "FAILED: $RES"; exit 1; }
CLEAR_HOST="${CLEAR_ID}.onrender.com"
echo "   id=$CLEAR_ID  host=$CLEAR_HOST"

# -------------------------------------------------------------- 3. backend
echo "== 3/4 backend =="
BACKEND_ENV=$(cat <<EOF
[
  {"key": "FORENSIC_ENVIRONMENT", "value": "render"},
  {"key": "FORENSIC_MOCK_ONION_BASE_URL", "value": "http://$ONION_HOST"},
  {"key": "FORENSIC_MOCK_CLEARNET_BASE_URL", "value": "http://$CLEAR_HOST"},
  {"key": "FORENSIC_ALLOW_NETWORK_PROBES", "value": "true"},
  {"key": "RENDER_CERT_DIR", "value": "/app/certs"}
]
EOF
)
RES=$(create_web "$(service_json forensic-backend backend/Dockerfile ./backend 8000 "$BACKEND_ENV" /api/health)")
BACKEND_ID=$(echo "$RES" | _json "d['service']['id']")
[ -n "$BACKEND_ID" ] || { echo "FAILED: $RES"; exit 1; }
BACKEND_HOST="${BACKEND_ID}.onrender.com"
echo "   id=$BACKEND_ID  host=$BACKEND_HOST"

# ------------------------------------------------------------- 4. frontend
echo "== 4/4 frontend (static site) =="
RES=$(curl -s -X POST "$API/sites" \
  -H "Authorization: Bearer $RENDER_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"forensic-frontend\",
    \"ownerId\": \"$RENDER_OWNER_ID\",
    \"repo\": \"$REPO\",
    \"branch\": \"$BRANCH\",
    \"buildCommand\": \"cd frontend && npm install && npm run build\",
    \"publishPath\": \"frontend/dist\",
    \"envVars\": [{\"key\": \"VITE_API_BASE_URL\", \"value\": \"https://$BACKEND_HOST/api\"}]
  }")
FRONTEND_ID=$(echo "$RES" | _json "d.get('site', d).get('id', '')")
FRONTEND_HOST="${FRONTEND_ID}.onrender.com"
echo "   id=$FRONTEND_ID  host=$FRONTEND_HOST"

cat <<EOF

============================================================
 Deployment submitted.

 Public URLs (after builds finish, ~5-10 min):
   backend    https://$BACKEND_HOST/api  (docs at /docs)
   frontend   https://$FRONTEND_HOST
   mock-onion https://$ONION_HOST  (public edge; TLS by Render)
   mock-clear https://$CLEAR_HOST

 Render dashboard: https://dashboard.render.com/
============================================================
EOF
