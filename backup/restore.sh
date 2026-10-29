#!/usr/bin/env bash
# TSI DPDP CMS restore script.
#
# Default (safe): restores the backup into a throwaway Postgres container, applies
# the database encryption key, runs sanity checks, then discards it. The live
# deployment is never touched. Use it as a periodic restore drill.
#
# --live: restores into the real running database (DROPs and recreates objects;
# the reports volume, if an archive is found/given, is moved aside into
# '.pre-restore-<ts>' and replaced). Requires typed confirmation.
#
# --extract-secrets <bundle.tar.gz.enc> <dir>: decrypts the secrets bundle into <dir>
# (.env, keystore.p12). Never overwrites anything in the live deployment.
#
# Usage:
#   ./backup/restore.sh <backup.sql.gz> [exports.tar.gz] [--live]
#   ./backup/restore.sh --extract-secrets <bundle.tar.gz.enc> <dir>
#
# DB_ENCRYPTION_KEY (env var, backup/backup.env, the repo .env, or the running app container) must be
# found: it is re-applied as the database's app.enc_key, which pg_dump does not carry over.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/backup.env" ]; then
  set -a; source "$SCRIPT_DIR/backup.env"; set +a
fi

DB_CONTAINER="${DB_CONTAINER:-tsi_dpdp_cms_db}"
POSTGRES_DB="${POSTGRES_DB:-tsi_cms}"
POSTGRES_USER="${POSTGRES_USER:-tsi_admin}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:15-alpine}"
EXPORTS_VOLUME="${EXPORTS_VOLUME:-tsi-dpdp-cms_tsi_reports_data}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# ---- secrets extraction mode ----
if [ "${1:-}" = "--extract-secrets" ]; then
  BUNDLE="${2:-}"; OUTDIR="${3:-}"
  [ -f "$BUNDLE" ] && [ -n "$OUTDIR" ] || die "Usage: $0 --extract-secrets <bundle.tar.gz.enc> <dir>"
  if [ -z "${BACKUP_PASSPHRASE:-}" ] && [ -n "${BACKUP_PASSPHRASE_FILE:-}" ]; then
    BACKUP_PASSPHRASE="$(head -n1 "$BACKUP_PASSPHRASE_FILE")"
  fi
  if [ -z "${BACKUP_PASSPHRASE:-}" ]; then read -r -s -p "Passphrase: " BACKUP_PASSPHRASE; echo; fi
  mkdir -p "$OUTDIR"; chmod 700 "$OUTDIR"
  BACKUP_PASSPHRASE="$BACKUP_PASSPHRASE" openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass env:BACKUP_PASSPHRASE -in "$BUNDLE" \
    | tar xzf - -C "$OUTDIR" || die "Decryption failed (wrong passphrase or corrupt bundle)."
  log "Secrets extracted to '$OUTDIR'. Copy .env / keystore.p12 into place yourself."
  exit 0
fi

BACKUP_FILE=""; UPLOADS_FILE=""; MODE=""
for arg in "$@"; do
  case "$arg" in
    --live) MODE="--live" ;;
    *.tar.gz) UPLOADS_FILE="$arg" ;;
    *) BACKUP_FILE="$arg" ;;
  esac
done
[ -n "$BACKUP_FILE" ] && [ -f "$BACKUP_FILE" ] || die "Usage: $0 <backup.sql.gz> [exports.tar.gz] [--live]"
[ -z "$UPLOADS_FILE" ] || [ -f "$UPLOADS_FILE" ] || die "exports file '$UPLOADS_FILE' not found."
gzip -t "$BACKUP_FILE" || die "'$BACKUP_FILE' is not a valid gzip file."

# Pick up the matching exports archive next to the dump.
if [ -z "$UPLOADS_FILE" ]; then
  B="$(basename "$BACKUP_FILE")"
  if [[ "$B" =~ ^tsi_dpdp_cms_([0-9]{8}_[0-9]{6})\.sql\.gz$ ]]; then
    C="$(cd "$(dirname "$BACKUP_FILE")" && pwd)/tsi_dpdp_cms_exports_${BASH_REMATCH[1]}.tar.gz"
    if [ -f "$C" ]; then UPLOADS_FILE="$C"; echo "Found matching exports archive: $C"; fi
  fi
fi

# DB_ENCRYPTION_KEY: env, else the repo .env.
if [ -z "${DB_ENCRYPTION_KEY:-}" ] && [ -f "$SCRIPT_DIR/../.env" ]; then
  DB_ENCRYPTION_KEY="$(grep -E '^DB_ENCRYPTION_KEY=' "$SCRIPT_DIR/../.env" | head -n1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//' || true)"
fi
# Last resort: the key the running app container is using (covers installs that rely on the compose default).
if [ -z "${DB_ENCRYPTION_KEY:-}" ]; then
  DB_ENCRYPTION_KEY="$(docker exec "${APP_CONTAINER:-tsi_dpdp_cms_server}" printenv DB_ENCRYPTION_KEY 2>/dev/null || true)"
fi
[ -n "${DB_ENCRYPTION_KEY:-}" ] || die "DB_ENCRYPTION_KEY not found (checked the environment, ../.env and the running app container). Set it, then retry: without it the restored database cannot decrypt personal data."
case "$DB_ENCRYPTION_KEY" in *"'"*) die "DB_ENCRYPTION_KEY contains a single quote; set app.enc_key manually.";; esac

# $1=container $2=db $3=user
apply_enc_key() {
  docker exec -u postgres "$1" psql -U "$3" -d "$2" -v ON_ERROR_STOP=1 -q -c \
    "ALTER DATABASE \"$2\" SET app.enc_key = '${DB_ENCRYPTION_KEY}';" >/dev/null
}

run_checks() {
  local c="$1" db="$2" u="$3"
  log "Checking restored data in '$c'..."
  docker exec -u postgres "$c" psql -U "$u" -d "$db" -t -A -c \
    "SELECT 'tables: ' || count(*) FROM information_schema.tables WHERE table_schema='public';"
  for t in fiduciaries data_principal consent_policies consent_records audit_logs breach_incidents ropa_entries webhook_deliveries; do
    docker exec -u postgres "$c" psql -U "$u" -d "$db" -t -A -c "SELECT '$t: ' || count(*) || ' rows' FROM $t;" 2>/dev/null \
      || echo "  $t: table not found"
  done
  # app.enc_key must be live in a NEW session, as the app sees it.
  local got
  got="$(docker exec -u postgres "$c" psql -U "$u" -d "$db" -t -A -c "SELECT current_setting('app.enc_key', true) IS NOT NULL AND current_setting('app.enc_key', true) <> '';")"
  [ "$got" = "t" ] && echo "  app.enc_key: set" || { echo "  app.enc_key: MISSING" >&2; return 1; }
}

if [ "$MODE" = "--live" ]; then
  echo "!! This will DROP and RECREATE all objects in the LIVE '$POSTGRES_DB' database in '$DB_CONTAINER'"
  echo "!! using: $BACKUP_FILE"
  if [ -n "$UPLOADS_FILE" ]; then
    echo "!! It will also REPLACE the contents of volume '$EXPORTS_VOLUME' with: $UPLOADS_FILE"
    echo "!! (current contents are moved to '.pre-restore-<timestamp>' inside the volume, not deleted)"
  else
    echo "!! No exports archive found/given - volume '$EXPORTS_VOLUME' is left untouched."
  fi
  echo "!! Consider 'docker compose stop jetty_app' first so nothing writes mid-restore."
  read -r -p "Type RESTORE to continue: " CONFIRM
  [ "$CONFIRM" = "RESTORE" ] || { echo "Aborted."; exit 1; }
  docker inspect -f '{{.State.Running}}' "$DB_CONTAINER" >/dev/null 2>&1 || die "container '$DB_CONTAINER' is not running."

  log "Restoring into live database '$POSTGRES_DB'..."
  gunzip -c "$BACKUP_FILE" | docker exec -i "$DB_CONTAINER" psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -q >/dev/null
  apply_enc_key "$DB_CONTAINER" "$POSTGRES_DB" "$POSTGRES_USER"
  run_checks "$DB_CONTAINER" "$POSTGRES_DB" "$POSTGRES_USER"

  if [ -n "$UPLOADS_FILE" ]; then
    docker volume inspect "$EXPORTS_VOLUME" >/dev/null 2>&1 || die "volume '$EXPORTS_VOLUME' does not exist."
    RTS="$(date +%Y%m%d_%H%M%S)"
    UDIR="$(cd "$(dirname "$UPLOADS_FILE")" && pwd)"; UBASE="$(basename "$UPLOADS_FILE")"
    log "Moving aside current volume contents into '.pre-restore-${RTS}'..."
    docker run --rm -v "${EXPORTS_VOLUME}:/data" alpine sh -c "
      set -e; mkdir -p /data/.pre-restore-${RTS}
      for f in /data/*; do [ -e \"\$f\" ] || continue
        case \"\$(basename \"\$f\")\" in .pre-restore-*) continue ;; esac
        mv \"\$f\" /data/.pre-restore-${RTS}/; done"
    log "Extracting exports archive..."
    docker run --rm -v "${EXPORTS_VOLUME}:/data" -v "${UDIR}:/backup:ro" alpine tar xzf "/backup/${UBASE}" -C /data
    docker run --rm -v "${EXPORTS_VOLUME}:/data:ro" alpine sh -c 'echo "  files in volume: $(find /data -type f -not -path "/data/.pre-restore-*" | wc -l)"'
  fi
  log "Live restore complete. Restart the app: docker compose restart jetty_app"
else
  CHK="tsi_dpdp_cms_restore_check"
  docker rm -f "$CHK" >/dev/null 2>&1 || true
  UCHK=""
  cleanup() { docker rm -f "$CHK" >/dev/null 2>&1 || true; [ -z "$UCHK" ] || rm -rf "$UCHK"; }
  trap cleanup EXIT

  log "Starting throwaway Postgres '$CHK'..."
  docker run -d --name "$CHK" -e POSTGRES_DB=verify -e POSTGRES_USER="$POSTGRES_USER" -e POSTGRES_PASSWORD=verify "$POSTGRES_IMAGE" >/dev/null
  for _ in $(seq 1 30); do
    # the entrypoint restarts postgres once after init; wait for a real query to succeed
    docker exec "$CHK" psql -U "$POSTGRES_USER" -d verify -tAc "select 1" >/dev/null 2>&1 && break
    sleep 1
  done
  sleep 2

  log "Restoring '$BACKUP_FILE' into it..."
  gunzip -c "$BACKUP_FILE" | docker exec -i "$CHK" psql -U "$POSTGRES_USER" -d verify -v ON_ERROR_STOP=1 -q >/dev/null
  apply_enc_key "$CHK" verify "$POSTGRES_USER"
  run_checks "$CHK" verify "$POSTGRES_USER"

  if [ -n "$UPLOADS_FILE" ]; then
    UCHK="$(mktemp -d)"
    tar xzf "$UPLOADS_FILE" -C "$UCHK"
    echo "  exports archive files: $(find "$UCHK" -type f | wc -l)"
  else
    log "No exports archive found/given - skipping."
  fi
  log "Verification complete - backup is restorable. Throwaway container discarded, live deployment untouched."
fi
