#!/usr/bin/env bash
# Simple dev tool for exercising the consent lifecycle against a running instance:
# give consent (record_consent), withdraw it (withdraw_consent), or initiate erasure
# (erasure_request) -- one action at a time, or all three back-to-back. After each
# action it confirms the matching notification landed for the principal via
# list_notifications.
#
# This is a synchronous, one-shot curl+jq tool -- unlike the polling examples under
# examples/integration/notifications/ and examples/integration/purge/, there's no need
# for a long-lived Java client just to fire a request and check the result.
#
# Requires: curl, jq.
#
# Usage:
#   BASE_URL=http://localhost:8080 API_KEY=<uuid> API_SECRET=<secret> POLICY_ID=<policy_id> \
#   ./test-consent-lifecycle.sh <give|withdraw|erase|all> [user_id]
#
# Examples:
#   ./test-consent-lifecycle.sh give                  # gives consent for a freshly generated principal, prints its USER_ID
#   ./test-consent-lifecycle.sh withdraw test-principal-123   # withdraws consent for an existing principal
#   ./test-consent-lifecycle.sh erase test-principal-123      # initiates erasure for an existing principal
#   ./test-consent-lifecycle.sh all                   # runs give -> withdraw -> erase for one freshly generated principal
#
# BASE_URL defaults to http://localhost:8080. API_KEY, API_SECRET, and POLICY_ID are
# required -- generate an App API key via the admin console ("generate_api_key") and
# use any active policy_id under that App fiduciary.
#
# user_id is optional for "give"/"all" (a fresh "test-principal-<timestamp>" is
# generated and printed so you can reuse it). It is required for "withdraw"/"erase" run
# on their own -- pass the USER_ID printed by an earlier "give" run.
#
# Note: record_consent always resolves the policy with an empty version string
# server-side (Consent.java), so POLICY_ID must refer to a policy created with the
# default blank version -- true for any policy created via the DPO console's
# "Create New Policy" flow.

set -uo pipefail

usage() {
  sed -n '2,35p' "$0" | sed 's/^# \{0,1\}//'
}

ACTION="${1:-}"
case "$ACTION" in
  give|withdraw|erase|all) ;;
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
USER_ID_ARG="${2:-}"

BASE_URL="${BASE_URL:-http://localhost:8080}"
API_KEY="${API_KEY:?Set API_KEY to an App API key (UUID)}"
API_SECRET="${API_SECRET:?Set API_SECRET to that App API secret}"
POLICY_ID="${POLICY_ID:?Set POLICY_ID to an active policy under this App fiduciary}"

if [ -n "$USER_ID_ARG" ]; then
  USER_ID="$USER_ID_ARG"
elif [ "$ACTION" = "give" ] || [ "$ACTION" = "all" ]; then
  USER_ID="test-principal-$(date +%s)"
else
  echo "USER_ID is required for '$ACTION' -- pass it as the second argument," >&2
  echo "using the value printed by an earlier 'give' run." >&2
  exit 1
fi

CONSENT_URL="$BASE_URL/api/v1/client/consent"
NOTIFICATION_URL="$BASE_URL/api/v1/client/notification"

for cmd in curl jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

PASS_COUNT=0
FAIL_COUNT=0

# Posts a JSON payload to the consent endpoint, asserts the expected HTTP status,
# and prints the response body either way. Sets $BODY for the caller to inspect.
call_consent() {
  local label="$1" payload="$2" expected_status="$3"
  local response http_code
  response=$(curl -sS -w '\n%{http_code}' -X POST "$CONSENT_URL" \
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
# exists for USER_ID. The notification insert is fire-and-forget server-side, so a
# short retry loop tolerates a small amount of lag rather than racing it.
check_notification() {
  local label="$1" expected_type="$2"
  local attempt found body
  for attempt in 1 2 3 4 5; do
    body=$(curl -sS -X POST "$NOTIFICATION_URL" \
      -H 'Content-Type: application/json' \
      -H "X-API-Key: $API_KEY" \
      -H "X-API-Secret: $API_SECRET" \
      -d "{\"_func\":\"list_notifications\",\"recipient_type\":\"PRINCIPAL\",\"recipient_id\":\"$USER_ID\"}")
    found=$(echo "$body" | jq --arg t "$expected_type" '[.[] | select(.notification_type == $t)] | length' 2>/dev/null || echo 0)
    if [ "$found" -gt 0 ] 2>/dev/null; then
      echo "[OK]   $label ($expected_type notification found)"
      PASS_COUNT=$((PASS_COUNT + 1))
      return
    fi
    sleep 1
  done
  echo "[FAIL] $label -- no $expected_type notification found for $USER_ID after 5 attempts"
  echo "       Last response: $body"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

do_give() {
  echo "Giving consent for USER_ID=$USER_ID ..."
  local payload now
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  payload=$(cat <<JSON
{
  "_func": "record_consent",
  "user_id": "$USER_ID",
  "policy_id": "$POLICY_ID",
  "language_selected": "en",
  "data_point_consents": [
    {"data_point_id": "purpose_demo_alpha", "consent_granted": true,  "purpose_agreed_to": "Demo Purpose Alpha", "timestamp_updated": "$now"},
    {"data_point_id": "purpose_demo_beta",  "consent_granted": false, "purpose_agreed_to": "Demo Purpose Beta",  "timestamp_updated": "$now"}
  ]
}
JSON
)
  call_consent "record_consent" "$payload" "201"
  check_notification "CONSENT_GIVEN notification" "CONSENT_GIVEN_NOTIFICATION"
}

do_withdraw() {
  echo "Withdrawing consent for USER_ID=$USER_ID ..."
  local payload
  payload=$(cat <<JSON
{
  "_func": "withdraw_consent",
  "user_id": "$USER_ID",
  "policy_id": "$POLICY_ID",
  "reason": "test-consent-lifecycle.sh check"
}
JSON
)
  call_consent "withdraw_consent" "$payload" "200"
  check_notification "WITHDRAWAL_ACKNOWLEDGMENT notification" "WITHDRAWAL_ACKNOWLEDGMENT"
}

do_erase() {
  echo "Initiating erasure for USER_ID=$USER_ID ..."
  local payload
  payload=$(cat <<JSON
{
  "_func": "erasure_request",
  "user_id": "$USER_ID",
  "policy_id": "$POLICY_ID",
  "reason": "test-consent-lifecycle.sh check"
}
JSON
)
  call_consent "erasure_request" "$payload" "200"
  check_notification "ERASURE_REQUESTED notification" "ERASURE_REQUESTED_NOTIFICATION"
}

echo "Action: $ACTION | USER_ID: $USER_ID | Target: $BASE_URL"
echo

case "$ACTION" in
  give)     do_give ;;
  withdraw) do_withdraw ;;
  erase)    do_erase ;;
  all)      do_give; do_withdraw; do_erase ;;
esac

echo
echo "USER_ID=$USER_ID (reuse this for the next step, e.g. withdraw/erase)"
echo "Summary: $PASS_COUNT passed, $FAIL_COUNT failed."
[ "$FAIL_COUNT" -eq 0 ]
