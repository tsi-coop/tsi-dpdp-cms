# Production Deployment Guide

**Document Version:** 1.0
**Audience:** DevOps / system administrators taking a TSI DPDP CMS install from evaluation to production.

---

## Overview

The Docker and Binary installation steps in the main [README](../README.md) get you running for evaluation. A production instance holds real personal data - DPDP-regulated PII, consent records, and the immutable audit/compliance ledger - so it needs additional hardening before go-live. The five guardrails below apply whether you deploy via Docker or as a binary; each is shown for both.

## Docker

1.  **Keep secrets out of images.** Never bake credentials into the `Dockerfile` or commit them. Create your own `.env` and lock it down:
    ```bash
    cp .example .env
    chmod 600 .env
    ```
    `docker-compose.yml` falls back to **eval-only** defaults (`secure_dev_password`, `local-dev-enc-key-do-not-use-in-production`, `tsi-dpdp-cms-local-dev-secret-do-not-use-in-production`, `changeit`) whenever a variable is missing from `.env` - their names say it plainly. Before going live, confirm `.env` sets real values for **every one** of `POSTGRES_PASSWD`, `JWT_SECRET`, `DB_ENCRYPTION_KEY`, `TSI_LOOKUP_SALT`, `TSI_KEYSTORE_PASS`, and `ALLOWED_ORIGINS` - generate the random ones with `openssl rand -hex 32` as `.example` documents. Note that `DB_ENCRYPTION_KEY` can never be changed after first use without losing access to encrypted data, so back it up immediately (see guardrail 5).

2.  **Never run as root.** The `Dockerfile` already declares `USER jetty`, but the published `docker-compose.yml` overrides it with `user: "root"` (a workaround added to fix ownership of the `tsi_reports_data` volume). For production, override it back to the image's built-in low-privilege account with a `docker-compose.override.yml` (Compose merges this automatically, no need to edit the shipped file):
    ```yaml
    # docker-compose.override.yml
    services:
      jetty_app:
        user: "999:999"   # the 'jetty' user's uid:gid inside jetty:jdk17
    ```
    Then fix the volume's ownership once - this is the permission issue `user: "root"` was papering over:
    ```bash
    docker compose run --rm --user root --entrypoint sh jetty_app \
      -c "chown -R 999:999 \$TSI_EXPORT_PATH"
    ```
    Restart with `docker compose up -d` and confirm with `docker compose exec jetty_app id` - it should report `uid=999(jetty)`, not `uid=0(root)`. Running as a low-privilege user means a container compromise can't pivot to root-level access on the host.

3.  **Encrypt the host disk.** This is a host/OS-level control, not a Docker setting - enable full-disk encryption (LUKS) when provisioning the server (e.g. tick "Encrypt the new Ubuntu installation for security" in the Ubuntu Server installer), or turn on your cloud provider's disk encryption with customer-managed keys (AWS EBS encryption, Azure Disk Encryption, GCP CMEK). Docker stores named volumes - including `postgres_data` and `tsi_reports_data` - under `/var/lib/docker/volumes/` on this same disk, so encrypting it scrambles the database, exported reports, and signing keystore at rest. This complements, but doesn't replace, the column-level `pgcrypto` encryption already driven by `DB_ENCRYPTION_KEY`.

4.  **Isolate the data tier.** `docker-compose.yml` already places both services on a private bridge network (`tsi_internal`), so `jetty_app` reaches Postgres over the internal hostname `postgres_db` - nothing else needs the database port published to the host. The default `${DB_PORT_MAP:-5432:5432}` *does* publish it on every interface (useful for local `psql` while evaluating). For production, either bind it to loopback only in `.env`:
    ```
    DB_PORT_MAP=127.0.0.1:5432:5432
    ```
    or drop the publish entirely via the same override file:
    ```yaml
    # docker-compose.override.yml
    services:
      postgres_db:
        ports: []
    ```
    Verify nothing is reachable from outside: `ss -tlnp | grep 5432` on the host should show at most a loopback binding, and `nc -zv <host-ip> 5432` from another machine should fail. Treat host firewall rules (ufw, cloud security groups) as defense-in-depth, not a substitute - Docker manipulates `iptables` directly and can bypass them.

5.  **Automate offsite backups.** What needs to leave the building daily: the `postgres_data` volume (the database, including the immutable audit/compliance ledger that is your DPDP evidence of record), the `tsi_reports_data` volume (generated RoPA and compliance reports), `.env` (without `DB_ENCRYPTION_KEY` the encrypted PII columns are unrecoverable), and the file at `TSI_KEYSTORE_PATH` (without it, previously-signed compliance evidence can no longer be verified). A daily cron job using `docker compose exec` (stable regardless of the Compose project name) might look like:
    ```bash
    #!/bin/bash
    # /opt/tsi-backup/backup.sh
    set -euo pipefail
    STAMP=$(date +%Y%m%d_%H%M%S)
    OUT=/var/backups/tsi-dpdp-cms; mkdir -p "$OUT"
    cd /path/to/tsi-dpdp-cms

    # 1. Consistent logical DB dump (don't tar a live data directory)
    docker compose exec -T postgres_db pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -F c \
      > "$OUT/db_${STAMP}.dump"

    # 2. Generated reports volume
    docker compose exec -T jetty_app tar czf - -C "$TSI_EXPORT_PATH" . \
      > "$OUT/reports_${STAMP}.tar.gz"

    # 3. Secrets and signing keystore - required to ever restore or re-verify evidence
    tar czf "$OUT/secrets_${STAMP}.tar.gz" .env "$TSI_KEYSTORE_PATH"

    # 4. Encrypt the bundle before it leaves this host
    tar cz "$OUT"/*_"${STAMP}"* | gpg --symmetric --cipher-algo AES256 \
      -o "$OUT/bundle_${STAMP}.tar.gz.gpg"
    rm "$OUT"/{db,reports,secrets}_"${STAMP}"*

    # 5. Ship to immutable, offsite storage (e.g. S3 with Object Lock in Compliance mode)
    aws s3 cp "$OUT/bundle_${STAMP}.tar.gz.gpg" s3://your-offsite-bucket/tsi-dpdp-cms/ \
      --object-lock-mode COMPLIANCE \
      --object-lock-retain-until-date "$(date -d '+30 days' --iso-8601=seconds)"

    find "$OUT" -type f -mtime +7 -delete
    ```
    Schedule it with `crontab -e`:
    ```
    0 2 * * * /opt/tsi-backup/backup.sh >> /var/log/tsi-backup.log 2>&1
    ```
    An immutable, object-locked destination protects backups from corruption or ransomware that also reaches your live host. Test restores periodically - a backup that's never been restored is a guess, not a guarantee.

## Binary

The same five guardrails, mapped onto the bare-metal Jetty deployment described in the README's Build section:

1.  **Keep secrets out of binaries/configs.** `server/.env` is already excluded from Git (`server/.gitignore`). Lock it down (`chmod 600 server/.env`), generate strong random values the same way (`openssl rand -hex 32`), and never commit a filled-in `.env` - including files like `production.env`, which should only ever hold placeholders.

2.  **Never run as root.** Create a dedicated, low-privilege system account to own and run the Jetty process - don't invoke `serve.sh` as root or via `sudo`:
    ```bash
    sudo useradd --system --home /opt/tsi-dpdp-cms --shell /usr/sbin/nologin tsicms
    sudo chown -R tsicms:tsicms /opt/tsi-dpdp-cms "$JETTY_BASE" "$TSI_EXPORT_PATH"
    sudo -u tsicms ./serve.sh
    ```
    For a persistent setup, wrap it in a `systemd` unit with `User=tsicms` rather than leaving it in a terminal session.

3.  **Encrypt the host disk.** Identical to the Docker case - enable LUKS full-disk encryption or your cloud provider's managed disk encryption when provisioning the server. The Postgres data directory, `$JETTY_BASE`, `$TSI_EXPORT_PATH`, and the `.p12` keystore at `$TSI_KEYSTORE_PATH` all live on this disk, so encrypting it protects all of them at rest.

4.  **Isolate the data tier.** Bind PostgreSQL to a private interface only - set `listen_addresses = 'localhost'` in `postgresql.conf` and restrict `pg_hba.conf` to the application host's address - then firewall off the port from the internet (e.g. `sudo ufw deny 5432/tcp`). If Postgres runs on a separate host, place it on a private subnet with no public IP, reachable only from the application server's private address.

5.  **Automate offsite backups.** Same approach, using `pg_dump` and the relevant filesystem paths directly:
    ```bash
    #!/bin/bash
    # /opt/tsi-backup/backup.sh
    set -euo pipefail
    STAMP=$(date +%Y%m%d_%H%M%S)
    OUT=/var/backups/tsi-dpdp-cms; mkdir -p "$OUT"

    pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -F c -f "$OUT/db_${STAMP}.dump"
    tar czf "$OUT/exports_${STAMP}.tar.gz" "$TSI_EXPORT_PATH"
    tar czf "$OUT/secrets_${STAMP}.tar.gz" /path/to/server/.env "$TSI_KEYSTORE_PATH"

    tar cz "$OUT"/*_"${STAMP}"* | gpg --symmetric --cipher-algo AES256 -o "$OUT/bundle_${STAMP}.tar.gz.gpg"
    rm "$OUT"/{db,exports,secrets}_"${STAMP}"*

    aws s3 cp "$OUT/bundle_${STAMP}.tar.gz.gpg" s3://your-offsite-bucket/tsi-dpdp-cms/ \
      --object-lock-mode COMPLIANCE --object-lock-retain-until-date "$(date -d '+30 days' --iso-8601=seconds)"

    find "$OUT" -type f -mtime +7 -delete
    ```
    Schedule it the same way via `crontab -e`, ship the encrypted bundle to immutable offsite/object storage, and test restores periodically.
