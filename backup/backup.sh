#!/usr/bin/env bash
# TSI DPDP CMS backup script.
#
# Dumps the Postgres database (plain SQL, gzipped) from the running docker-compose
# stack, optionally archives the generated-reports volume, and optionally bundles
# .env + the signing keystore into an AES-256 encrypted archive. Everything is
# copied to a destination directory (NAS mount, external drive, ...). Run it
# manually or from your own cron/systemd - this script installs no scheduler.
#
# Usage:  ./backup/backup.sh
# Config: environment variables, or backup/backup.env (auto-loaded if present).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/backup.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$SCRIPT_DIR/backup.env"
  set +a
fi

DB_CONTAINER="${DB_CONTAINER:-tsi_dpdp_cms_db}"
POSTGRES_DB="${POSTGRES_DB:-tsi_cms}"
POSTGRES_USER="${POSTGRES_USER:-tsi_admin}"
LOCAL_BACKUP_DIR="${LOCAL_BACKUP_DIR:-$HOME/tsi-dpdp-cms-backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
INCLUDE_EXPORTS="${INCLUDE_EXPORTS:-true}"
EXPORTS_VOLUME="${EXPORTS_VOLUME:-tsi-dpdp-cms_tsi_reports_data}"
INCLUDE_SECRETS="${INCLUDE_SECRETS:-false}"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../.env}"
KEYSTORE_FILE="${KEYSTORE_FILE:-}"

if [ -z "${BACKUP_DEST_DIR:-}" ]; then
  BACKUP_DEST_DIR="$LOCAL_BACKUP_DIR"
  echo "WARNING: BACKUP_DEST_DIR not set - backups stay in '$LOCAL_BACKUP_DIR' only, not copied off-host." >&2
fi

TS="$(date +%Y%m%d_%H%M%S)"
DUMP_FILE="tsi_dpdp_cms_${TS}.sql.gz"
EXPORTS_FILE="tsi_dpdp_cms_exports_${TS}.tar.gz"
SECRETS_FILE="tsi_dpdp_cms_secrets_${TS}.tar.gz.enc"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# Passphrase for the secrets bundle: BACKUP_PASSPHRASE, or the first line of BACKUP_PASSPHRASE_FILE.
if [ "$INCLUDE_SECRETS" = "true" ]; then
  if [ -z "${BACKUP_PASSPHRASE:-}" ] && [ -n "${BACKUP_PASSPHRASE_FILE:-}" ]; then
    [ -r "$BACKUP_PASSPHRASE_FILE" ] || die "BACKUP_PASSPHRASE_FILE '$BACKUP_PASSPHRASE_FILE' is not readable."
    BACKUP_PASSPHRASE="$(head -n1 "$BACKUP_PASSPHRASE_FILE")"
  fi
  [ -n "${BACKUP_PASSPHRASE:-}" ] || die "INCLUDE_SECRETS=true needs BACKUP_PASSPHRASE or BACKUP_PASSPHRASE_FILE. Refusing to write secrets unencrypted."
  [ -f "$ENV_FILE" ] || die "ENV_FILE '$ENV_FILE' not found."
  [ -z "$KEYSTORE_FILE" ] || [ -f "$KEYSTORE_FILE" ] || die "KEYSTORE_FILE '$KEYSTORE_FILE' not found."
  if [ -z "$KEYSTORE_FILE" ]; then
    echo "WARNING: KEYSTORE_FILE not set - the signing keystore is NOT in this backup. Without it, previously signed certificates cannot be re-verified." >&2
  fi
  command -v openssl >/dev/null || die "openssl is required for INCLUDE_SECRETS=true."
fi

mkdir -p "$LOCAL_BACKUP_DIR"
[ -d "$BACKUP_DEST_DIR" ] || die "BACKUP_DEST_DIR '$BACKUP_DEST_DIR' does not exist. If it's a NAS mount, is the share mounted?"
docker inspect -f '{{.State.Running}}' "$DB_CONTAINER" >/dev/null 2>&1 || die "container '$DB_CONTAINER' is not running."

log "Dumping database '$POSTGRES_DB' from '$DB_CONTAINER'..."
# Write to a temp name first so a failed dump never leaves a truncated file that looks valid.
docker exec "$DB_CONTAINER" pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists \
  | gzip > "$LOCAL_BACKUP_DIR/$DUMP_FILE.part"
gzip -t "$LOCAL_BACKUP_DIR/$DUMP_FILE.part"
mv "$LOCAL_BACKUP_DIR/$DUMP_FILE.part" "$LOCAL_BACKUP_DIR/$DUMP_FILE"
FILES=("$DUMP_FILE")

if [ "$INCLUDE_EXPORTS" = "true" ]; then
  docker volume inspect "$EXPORTS_VOLUME" >/dev/null 2>&1 \
    || die "volume '$EXPORTS_VOLUME' does not exist. Set EXPORTS_VOLUME to match your compose project name, or INCLUDE_EXPORTS=false."
  log "Archiving reports volume '$EXPORTS_VOLUME'..."
  docker run --rm -v "${EXPORTS_VOLUME}:/data:ro" -v "$LOCAL_BACKUP_DIR:/backup" \
    alpine tar czf "/backup/$EXPORTS_FILE" -C /data .
  FILES+=("$EXPORTS_FILE")
fi

if [ "$INCLUDE_SECRETS" = "true" ]; then
  log "Bundling and encrypting .env${KEYSTORE_FILE:+ + keystore}..."
  STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
  cp "$ENV_FILE" "$STAGE/.env"
  [ -z "$KEYSTORE_FILE" ] || cp "$KEYSTORE_FILE" "$STAGE/keystore.p12"
  tar czf - -C "$STAGE" . \
    | BACKUP_PASSPHRASE="$BACKUP_PASSPHRASE" openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass env:BACKUP_PASSPHRASE \
    > "$LOCAL_BACKUP_DIR/$SECRETS_FILE"
  chmod 600 "$LOCAL_BACKUP_DIR/$SECRETS_FILE"
  FILES+=("$SECRETS_FILE")
fi

if [ "$(cd "$LOCAL_BACKUP_DIR" && pwd)" != "$(cd "$BACKUP_DEST_DIR" && pwd)" ]; then
  log "Copying to '$BACKUP_DEST_DIR'..."
  for f in "${FILES[@]}"; do cp -p "$LOCAL_BACKUP_DIR/$f" "$BACKUP_DEST_DIR/"; done
fi

log "Pruning backups older than $RETENTION_DAYS days..."
for d in "$LOCAL_BACKUP_DIR" "$BACKUP_DEST_DIR"; do
  find "$d" -maxdepth 1 -name 'tsi_dpdp_cms_*' -mtime "+$RETENTION_DAYS" -delete
done

log "Backup complete: ${FILES[*]}"
