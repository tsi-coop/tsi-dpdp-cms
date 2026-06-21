#!/usr/bin/env bash
# Compiles and runs NotificationListener.java, which polls /api/v1/notification and
# prints every notification (PRINCIPAL, DPO, and APP recipients alike) for the
# fiduciary tied to the given App API key to stdout. No fiduciary/recipient/policy/
# user config needed — generate notifications however you like (e.g. via the console
# UI) and this just watches and prints them.
#
# Requires: javac/java (JDK 15+), and json-simple-1.1.1.jar on disk somewhere under
# the repo (the WAR build already vendors it under target/.../WEB-INF/lib).
#
# Usage:
#   BASE_URL=http://localhost:8080 API_KEY=<uuid> API_SECRET=<secret> \
#   POLL_SECONDS=10 ./notification-listener.sh
#
# All env vars except API_KEY/API_SECRET are optional (defaults shown above/below).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

BASE_URL="${BASE_URL:-http://localhost:8080}"
API_KEY="${API_KEY:?Set API_KEY to an App's API key (UUID)}"
API_SECRET="${API_SECRET:?Set API_SECRET to that App's API secret}"
POLL_SECONDS="${POLL_SECONDS:-30}"

JSON_SIMPLE_JAR="${JSON_SIMPLE_JAR:-}"
if [ -z "$JSON_SIMPLE_JAR" ]; then
  JSON_SIMPLE_JAR="$(find "$REPO_ROOT" -iname 'json-simple-*.jar' 2>/dev/null | head -n 1)"
fi
if [ -z "$JSON_SIMPLE_JAR" ] || [ ! -f "$JSON_SIMPLE_JAR" ]; then
  echo "Could not find json-simple-*.jar under $REPO_ROOT. Set JSON_SIMPLE_JAR=/path/to/json-simple-1.1.1.jar and retry." >&2
  exit 1
fi

BUILD_DIR="$SCRIPT_DIR/build"
mkdir -p "$BUILD_DIR"

if [ ! -f "$BUILD_DIR/examples/integration/notifications/NotificationListener.class" ] \
   || [ "$SCRIPT_DIR/NotificationListener.java" -nt "$BUILD_DIR/examples/integration/notifications/NotificationListener.class" ]; then
  echo "Compiling NotificationListener.java..."
  javac -cp "$JSON_SIMPLE_JAR" -d "$BUILD_DIR" "$SCRIPT_DIR/NotificationListener.java"
fi

exec java -cp "$BUILD_DIR:$JSON_SIMPLE_JAR" examples.integration.notifications.NotificationListener \
  "$BASE_URL" "$API_KEY" "$API_SECRET" "$POLL_SECONDS"
