#!/bin/bash
# Rehearses the Docker production setup from docs/guides/production-deployment-guide.md
# on one machine, in a scratch copy of the repo, so your real .env and volumes are untouched.
#
#   tests/prod-setup-test.sh [bundled|external|both] [--keep]
#
#   bundled   Database in Docker (guide Steps 1-5, parts 2a/2b, Step 3 first override file)
#   external  Database on a different server (parts 2a/2c, Step 3 second override file).
#             A second Postgres container on its own Docker network plays the remote server.
#   both      Run bundled, then external (default)
#   --keep    Leave the containers and scratch folder in place for inspection
#
# Needs: docker compose, openssl, curl, tar, and target/tsi_dpdp_cms.war (run `mvn package` first).
# Test-only: uses throwaway secrets, host port 18080 and, for bundled, 15432.
set -uo pipefail

MODE=both; KEEP=0
for a in "$@"; do
  case "$a" in
    bundled|external|both) MODE=$a ;;
    --keep) KEEP=1 ;;
    *) echo "usage: $0 [bundled|external|both] [--keep]"; exit 2 ;;
  esac
done

REPO="$(cd "$(dirname "$0")/.." && pwd)"
APP_PORT=18080
DB_PORT=15432
FAILS=0
PASS_MSG() { echo "  PASS  $*"; }
FAIL_MSG() { echo "  FAIL  $*"; FAILS=$((FAILS+1)); }
check() { # check "<description>" <command...>
  local d=$1; shift
  if "$@" >/dev/null 2>&1; then PASS_MSG "$d"; else FAIL_MSG "$d"; fi
}

for c in docker openssl curl tar; do
  command -v "$c" >/dev/null || { echo "missing: $c"; exit 2; }
done
docker compose version >/dev/null 2>&1 || { echo "missing: docker compose"; exit 2; }
[ -f "$REPO/target/tsi_dpdp_cms.war" ] || { echo "target/tsi_dpdp_cms.war not found: run 'mvn package' first (the Dockerfile copies it)"; exit 2; }

COMPOSE_VER=$(docker compose version --short 2>/dev/null | sed 's/^v//')
SUPPORTS_RESET=0
if [ "$(printf '%s\n2.24.0\n' "$COMPOSE_VER" | sort -V | head -1)" = "2.24.0" ]; then SUPPORTS_RESET=1; fi

run_mode() {
  local mode=$1
  local proj="prodtest-$mode"
  local work; work=$(mktemp -d "${TMPDIR:-/tmp}/tsi-prodtest-$mode.XXXXXX")
  local remote_db="prodtest_remote_db_$mode" remote_net="prodtest_remote_net_$mode"
  local pgpass; pgpass=$(openssl rand -hex 16)
  echo; echo "=== $mode: scratch copy in $work ==="

  cleanup() {
    if [ "$KEEP" = 1 ]; then echo "  (kept: cd $work && docker compose -p $proj ...)"; return; fi
    (cd "$work" && docker compose -p "$proj" down -v --remove-orphans >/dev/null 2>&1)
    docker rm -f "$remote_db" >/dev/null 2>&1
    docker volume rm "${remote_db}_data" >/dev/null 2>&1
    docker network rm "$remote_net" >/dev/null 2>&1
    docker run --rm -v "$work:/w" alpine rm -rf /w/keystore /w/certs >/dev/null 2>&1   # root-owned files
    rm -rf "$work"
  }
  trap cleanup RETURN

  tar -C "$REPO" --exclude=.git --exclude=.env --exclude=keystore --exclude=certs \
      --exclude=docker-compose.override.yml -cf - . | tar -C "$work" -xf -
  cd "$work" || return

  # Step 1: .env with throwaway secrets
  local ks_pass; ks_pass=$(openssl rand -hex 12)
  cat > .env <<EOF
POSTGRES_DB=tsi_cms
POSTGRES_USER=tsi_admin
POSTGRES_PASSWD=$pgpass
JWT_SECRET=$(openssl rand -hex 32)
DB_ENCRYPTION_KEY=$(openssl rand -hex 32)
TSI_LOOKUP_SALT=$(openssl rand -hex 32)
TSI_BOOTSTRAP_TOKEN=$(openssl rand -hex 32)
TSI_KEYSTORE_PASS=$ks_pass
TSI_KEYSTORE_PATH=/etc/tsi/keystore.p12
TSI_KEYSTORE_ALIAS=tsi_fiduciary
ALLOWED_ORIGINS=https://localhost
TSI_DPDP_CMS_ENV=production
APP_PORT_MAP=127.0.0.1:$APP_PORT:8080
EOF
  chmod 600 .env
  if [ "$mode" = bundled ]; then echo "DB_PORT_MAP=127.0.0.1:$DB_PORT:5432" >> .env
  else echo "DB_HOST=$remote_db" >> .env; fi
  check "Step 1: no <placeholder> left in .env" test "$(grep -c '<' .env)" = 0

  # Step 2a: signing keystore (host keytool, else a Java container)
  mkdir -p keystore
  if command -v keytool >/dev/null; then
    keytool -genkeypair -alias tsi_fiduciary -keyalg RSA -keysize 3072 -sigalg SHA256withRSA \
      -dname "CN=Prod Test" -storetype PKCS12 -keystore keystore/keystore.p12 \
      -storepass "$ks_pass" -keypass "$ks_pass" -validity 30 >/dev/null 2>&1
  else
    docker run --rm -v "$PWD/keystore:/ks" jetty:jdk17 keytool -genkeypair -alias tsi_fiduciary \
      -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -dname "CN=Prod Test" -storetype PKCS12 \
      -keystore /ks/keystore.p12 -storepass "$ks_pass" -keypass "$ks_pass" -validity 30 >/dev/null 2>&1
  fi
  docker run --rm -v "$PWD/keystore:/ks" alpine sh -c 'chown 999:999 /ks/keystore.p12 && chmod 600 /ks/keystore.p12'
  check "Step 2a: keystore created" test -f keystore/keystore.p12

  # Database certificate (2b for bundled; the 'remote server' needs one too in external mode)
  mkdir -p certs
  openssl req -new -x509 -days 30 -nodes -subj "/CN=postgres_db" \
    -keyout certs/server.key -out certs/server.crt >/dev/null 2>&1
  docker run --rm -v "$PWD/certs:/certs" postgres:15-alpine sh -c 'chown 70:70 /certs/* && chmod 600 /certs/server.key'

  if [ "$mode" = bundled ]; then
    # Step 3: override file, Database in Docker
    cat > docker-compose.override.yml <<'EOF'
services:
  jetty_app:
    container_name: prodtest_bundled_app
    user: "999:999"
    volumes:
      - ./keystore:/etc/tsi:ro
  postgres_db:
    container_name: prodtest_bundled_db
    volumes:
      - ./certs:/certs:ro
    command: >
      postgres -c ssl=on
      -c ssl_cert_file=/certs/server.crt
      -c ssl_key_file=/certs/server.key
EOF
  else
    # Step 2c: a second Postgres plays the remote server (own network, no published port)
    docker network create "$remote_net" >/dev/null
    docker run -d --name "$remote_db" --network "$remote_net" \
      -e POSTGRES_PASSWORD="$pgpass-admin" -v "$PWD/certs:/certs:ro" -v "${remote_db}_data:/var/lib/postgresql/data" \
      postgres:15-alpine postgres -c ssl=on -c ssl_cert_file=/certs/server.crt -c ssl_key_file=/certs/server.key >/dev/null
    local i; for i in $(seq 1 30); do
      docker exec "$remote_db" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 2
    done
    docker exec -e PGPASSWORD="$pgpass-admin" "$remote_db" psql -U postgres -v ON_ERROR_STOP=1 \
      -c "CREATE USER tsi_admin WITH PASSWORD '$pgpass';" -c "CREATE DATABASE tsi_cms OWNER tsi_admin;" \
      -c "ALTER DATABASE tsi_cms SET app.enc_key = '$(grep '^DB_ENCRYPTION_KEY=' .env | cut -d= -f2)';" >/dev/null 2>&1
    # The schema-load loop from the guide, run from a container on the remote network
    docker run --rm --network "$remote_net" -v "$PWD/db:/work/db:ro" -v "$PWD/.env:/work/.env:ro" \
      -w /work postgres:15-alpine sh -c '
        set -a; . ./.env; set +a
        export PGPASSWORD="$POSTGRES_PASSWD" PGSSLMODE=require
        PSQL="psql -h '"$remote_db"' -U $POSTGRES_USER -d $POSTGRES_DB -v ON_ERROR_STOP=1"
        for f in db/*.sql; do echo "== $f"; $PSQL -f "$f" || exit 1; done' > schema-load.log 2>&1
    check "Step 2c: schema loaded without ERROR (see $work/schema-load.log)" test "$?" = 0
    check "Step 2c: app.enc_key stored in the database" \
      docker exec -e PGPASSWORD="$pgpass" "$remote_db" psql -h localhost -U tsi_admin -d tsi_cms -tAc "SHOW app.enc_key;"

    # Step 3: override file, Database on a different server
    local depends='    depends_on: !reset []'
    [ "$SUPPORTS_RESET" = 1 ] || depends=''
    cat > docker-compose.override.yml <<EOF
services:
  jetty_app:
    container_name: prodtest_external_app
    user: "999:999"
    volumes:
      - ./keystore:/etc/tsi:ro
    environment:
      POSTGRES_HOST: "jdbc:postgresql://\${DB_HOST}:5432"
$depends
    networks:
      - tsi_internal
      - remote
  postgres_db:
    profiles: ["bundled-db"]
networks:
  remote:
    name: $remote_net
    external: true
EOF
  fi
  check "Step 3: compose config is valid" docker compose -p "$proj" config

  # Step 4: reports volume permissions
  docker compose -p "$proj" run --rm --user root --entrypoint sh jetty_app \
    -c 'chown -R 999:999 $TSI_EXPORT_PATH' >/dev/null 2>&1

  # Step 5: start and check
  local up=(docker compose -p "$proj" up -d --build)
  [ "$mode" = external ] && [ "$SUPPORTS_RESET" = 0 ] && up=(docker compose -p "$proj" up -d --build --no-deps jetty_app)
  "${up[@]}" >/dev/null 2>&1 || FAIL_MSG "Step 5: docker compose up failed"
  local app; app=$(docker compose -p "$proj" ps -q jetty_app)
  local ok=0
  for i in $(seq 1 60); do
    docker logs "$app" 2>&1 | grep -q "Service started" && { ok=1; break; }; sleep 3
  done
  [ "$ok" = 1 ] && PASS_MSG "Step 5: app started" || FAIL_MSG "Step 5: app did not start in 3 minutes (docker logs $app)"
  check "Step 5.1: app runs as the jetty user (uid 999)" sh -c "docker exec $app id | grep -q 'uid=999'"
  check "Step 5.3: started in production environment" sh -c "docker logs $app 2>&1 | grep -q 'Service started in production environment'"

  if [ "$mode" = bundled ]; then
    local db; db=$(docker compose -p "$proj" ps -q postgres_db)
    check "Step 5.2: database SSL is on" sh -c "docker exec $db psql -U tsi_admin -d tsi_cms -tAc 'SHOW ssl;' | grep -q on"
    check "Step 5.4: database port bound to 127.0.0.1 only" sh -c "docker port $db 5432 | grep -q '^127.0.0.1:' && ! docker port $db 5432 | grep -q '0.0.0.0'"
  else
    check "Step 5.2: remote database SSL is on" \
      docker exec -e PGPASSWORD="$pgpass" "$remote_db" psql "host=localhost user=tsi_admin dbname=tsi_cms sslmode=require" -tAc "SHOW ssl;"
    check "Step 5.4: remote database publishes no port to the host" test -z "$(docker port "$remote_db")"
    check "Step 5: bundled database was not started" test -z "$(docker compose -p "$proj" ps -q postgres_db)"
  fi
  check "Step 5: console answers 200 on 127.0.0.1:$APP_PORT" \
    sh -c "[ \"\$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:$APP_PORT/console/setup/init.html)\" = 200 ]"
  cd "$REPO" || true
}

case "$MODE" in
  bundled)  run_mode bundled ;;
  external) run_mode external ;;
  both)     run_mode bundled; run_mode external ;;
esac

echo
if [ "$FAILS" = 0 ]; then echo "All checks passed."; else echo "$FAILS check(s) failed."; fi
exit "$FAILS"
