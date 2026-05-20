#!/bin/bash
# Sets app.enc_key as a database-level default so 04_gaps.sql can use
# current_setting('app.enc_key') without a manual SET command.
# Runs after 03_ropa.sql and before 04_gaps.sql (alphabetical order).
set -e

ENC_KEY="${DB_ENCRYPTION_KEY:-local-dev-enc-key-do-not-use-in-production}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     --command "ALTER DATABASE \"${POSTGRES_DB}\" SET app.enc_key = '${ENC_KEY}';"

echo "app.enc_key configured for database ${POSTGRES_DB}"
