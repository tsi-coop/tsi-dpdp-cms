#!/usr/bin/env bash
# Simple dev tool for exercising the Data Principal side of the grievance lifecycle
# against a running instance: submit a grievance (submit_grievance), then confirm a
# notification landed once its status is later changed (resolved/escalated/etc.) --
# whether you did that via the DPO console or some other client. See
# src/org/tsicoop/dpdpcms/service/v1/Grievance.java for where each notification fires.
#
# This intentionally does NOT perform DPO/Operator actions (assign, resolve, escalate)
# -- those are console-only actions, managed by the DPO in web/console/dpo/grievances.html.
# This script only covers what a Data Principal app would do: submit, and check for the
# resulting notification.
#
# This is a synchronous, one-shot curl+jq tool, the same style as
# examples/integration/consent/test-consent-lifecycle.sh.
#
# Requires: curl, jq.
#
# Usage:
#   BASE_URL=http://localhost:8080 API_KEY=<uuid> API_SECRET=<secret> \
#   ./test-grievance-lifecycle.sh submit
#
#   BASE_URL=http://localhost:8080 API_KEY=<uuid> API_SECRET=<secret> \
#   ./test-grievance-lifecycle.sh check <user_id> <notification_type>
#
# Examples:
#   ./test-grievance-lifecycle.sh submit
#       # Submits a grievance for a freshly generated principal, prints USER_ID and
#       # GRIEVANCE_ID, and confirms GRIEVANCE_SUBMITTED_NOTIFICATION landed.
#
#   ./test-grievance-lifecycle.sh check test-principal-1234567890 GRIEVANCE_RESOLVED_NOTIFICATION
#       # After resolving that grievance in the DPO console, confirms the matching
#       # notification landed for that principal. Use GRIEVANCE_ESCALATED_NOTIFICATION
#       # if you escalated it instead.
#
# BASE_URL defaults to http://localhost:8080. API_KEY and API_SECRET are always
# required (generate an App API key via the admin console's "generate_api_key").
#
# Note: no fiduciary_id is ever passed in any payload -- the server resolves it from
# API_KEY.

set -uo pipefail

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

ACTION="${1:-}"
case "$ACTION" in
  submit|check) ;;
  -h|--help|"")
    usage
    exit 0
    ;;
  *)
    echo "Unknown action: $ACTION" >&2
    usage
    exit 1
    ;;
esac

BASE_URL="${BASE_URL:-http://localhost:8080}"
API_KEY="${API_KEY:?Set API_KEY to an App API key (UUID)}"
API_SECRET="${API_SECRET:?Set API_SECRET to that App API secret}"

GRIEVANCE_CLIENT_URL="$BASE_URL/api/v1/client/grievance"
NOTIFICATION_URL="$BASE_URL/api/v1/client/notification"

for cmd in curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

PASS_COUNT=0
FAIL_COUNT=0

# Posts a JSON payload to the grievance client (App API key) endpoint, asserts the
# expected HTTP status, and prints the response body either way. Sets $BODY.
call_grievance_client() {
  local label="$1" payload="$2" expected_status="$3"
  local response http_code
  response=$(curl -sS -w '\n%{http_code}' -X POST "$GRIEVANCE_CLIENT_URL" \
    -H 'Content-Type: application/json' \
    -H "X-API-Key: $API_KEY" \
    -H "X-API-Secret: $API_SECRET" \
    -d "$payload")
  http_code=$(echo "$response" | tail -n1)
  BODY=$(echo "$response" | sed '$d')

  if [ "$http_code" = "$expected_status" ]; then
    echo "[OK]   $label (HTTP $http_code)"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "[FAIL] $label -- expected HTTP $expected_status, got $http_code"
    echo "       Response: $BODY"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# Polls list_notifications once and asserts a row with the given notification_type
# exists for the Data Principal. The notification insert is fire-and-forget
# server-side, so a short retry loop tolerates a small amount of lag rather than racing it.
check_notification() {
  local label="$1" user_id="$2" expected_type="$3"
  local attempt found body
  for attempt in 1 2 3 4 5; do
    body=$(curl -sS -X POST "$NOTIFICATION_URL" \
      -H 'Content-Type: application/json' \
      -H "X-API-Key: $API_KEY" \
      -H "X-API-Secret: $API_SECRET" \
      -d "{\"_func\":\"list_notifications\",\"recipient_type\":\"PRINCIPAL\",\"recipient_id\":\"$user_id\"}")
    found=$(echo "$body" | jq --arg t "$expected_type" '[.[] | select(.notification_type == $t)] | length' 2>/dev/null || echo 0)
    if [ "$found" -gt 0 ] 2>/dev/null; then
      echo "[OK]   $label ($expected_type notification found)"
      PASS_COUNT=$((PASS_COUNT + 1))
      return
    fi
    sleep 1
  done
  echo "[FAIL] $label -- no $expected_type notification found for PRINCIPAL/$user_id after 5 attempts"
  echo "       Last response: $body"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

do_submit() {
  USER_ID="test-principal-$(date +%s)"
  echo "Submitting grievance for USER_ID=$USER_ID ..."
  local payload
  payload=$(cat <<JSON
{
  "_func": "submit_grievance",
  "user_id": "$USER_ID",
  "type": "GENERAL_COMPLAINT",
  "subject": "test-grievance-lifecycle.sh check",
  "description": "Automated check submitted by examples/integration/grievance/test-grievance-lifecycle.sh."
}
JSON
)
  call_grievance_client "submit_grievance" "$payload" "201"
  GRIEVANCE_ID=$(echo "$BODY" | jq -r '.grievance_id // empty')
  if [ -z "$GRIEVANCE_ID" ]; then
    echo "[FAIL] submit_grievance -- response did not include grievance_id" >&2
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return
  fi
  check_notification "GRIEVANCE_SUBMITTED notification" "$USER_ID" "GRIEVANCE_SUBMITTED_NOTIFICATION"
  echo
  echo "GRIEVANCE_ID=$GRIEVANCE_ID"
  echo "USER_ID=$USER_ID"
  echo "Resolve or escalate this grievance in the DPO console, then run:"
  echo "  ./test-grievance-lifecycle.sh check $USER_ID GRIEVANCE_RESOLVED_NOTIFICATION"
  echo "  ./test-grievance-lifecycle.sh check $USER_ID GRIEVANCE_ESCALATED_NOTIFICATION"
}

do_check() {
  local user_id="$1" expected_type="$2"
  echo "Checking for $expected_type notification for USER_ID=$user_id ..."
  check_notification "$expected_type notification" "$user_id" "$expected_type"
}

echo "Action: $ACTION | Target: $BASE_URL"
echo

case "$ACTION" in
  submit)
    do_submit
    ;;
  check)
    USER_ID_ARG="${2:?Usage: check <user_id> <notification_type>}"
    NOTIFICATION_TYPE_ARG="${3:?Usage: check <user_id> <notification_type>}"
    do_check "$USER_ID_ARG" "$NOTIFICATION_TYPE_ARG"
    ;;
esac

echo
echo "Summary: $PASS_COUNT passed, $FAIL_COUNT failed."
[ "$FAIL_COUNT" -eq 0 ]
