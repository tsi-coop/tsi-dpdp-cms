# Production Deployment Guide

**Document Version:** 1.0
**Audience:** Whoever is taking a TSI DPDP CMS install from evaluation to production - you don't need to be a senior DevOps engineer to follow this.

---

## Overview

The Docker and Binary steps in the main [README](../README.md) are enough to get the system running for evaluation. But a production instance holds real personal data - names, contact details, consent records, and the audit ledger that proves compliance - so before you point real users at it, there are five things worth locking down.

None of these are exotic. They're standard practice for any production system, not something specific to this project, and each one below comes with the exact commands to run and a way to check you got it right. Take them one at a time - you don't have to do all five in one sitting.

| # | Guardrail | In one sentence |
|---|---|---|
| 1 | Keep secrets out of the repo | Replace the example passwords/keys with your own before going live. |
| 2 | Don't run as root | Run the app as a low-privilege user, so a bug in it can't take over the whole server. |
| 3 | Encrypt the disk | Turn on full-disk encryption when you set up the server (most cloud providers do this in one click). |
| 4 | Keep the database private | Make sure Postgres isn't reachable from the internet - only your app should be able to talk to it. |
| 5 | Back up automatically, offsite | Schedule a daily backup that leaves the server, so you don't lose everything if it does. |

The steps below show each guardrail for both Docker and Binary deployments - use whichever section matches how you installed the system.

## Docker

### 1. Keep secrets out of the repo

**Why:** `docker-compose.yml` ships with placeholder passwords (like `secure_dev_password`) so evaluation works out of the box. Those placeholders are fine for trying the system out, but they're published in this public repo, so anyone can guess them - they must never be used in production.

**Do this:**

```bash
cp .example .env
chmod 600 .env
```

Then open `.env` and set real values for all of `POSTGRES_PASSWD`, `JWT_SECRET`, `DB_ENCRYPTION_KEY`, `TSI_LOOKUP_SALT`, `TSI_KEYSTORE_PASS`, `TSI_BOOTSTRAP_TOKEN`, and `ALLOWED_ORIGINS`. For the random ones, generate a strong value with:

```bash
openssl rand -hex 32
```

`.example` shows which fields need this. One thing to know up front: `DB_ENCRYPTION_KEY` can never be changed later without losing access to already-encrypted data, so back it up as soon as you set it (guardrail 5 covers how).

`TSI_BOOTSTRAP_TOKEN` has no built-in default, unlike the others - leave it unset and the one-time Super-Admin setup endpoint (`/console/setup/init.html`) refuses every request instead of falling back to a guessable value. After `docker compose up -d`, open that URL, enter the same value you put in `.env` as the Setup Token, and create your admin account. You can unset or rotate `TSI_BOOTSTRAP_TOKEN` afterward - it's only checked while `operators` has no admin row yet.

### 2. Don't run as root

**Why:** The container image already defines a low-privilege `jetty` user, but the shipped `docker-compose.yml` overrides it to run as `root` (a workaround for a file-permission issue). Running as `root` means that if the app were ever compromised, the attacker would have full control of the container, not just the app - not a risk worth taking in production.

**Do this:** Create a small override file (Compose merges this automatically - you don't edit the shipped file):

```yaml
# docker-compose.override.yml
services:
  jetty_app:
    user: "999:999"   # the built-in 'jetty' user's numeric ID
```

Then fix the ownership of the volume that `root` was working around, one time:

```bash
docker compose run --rm --user root --entrypoint sh jetty_app \
  -c "chown -R 999:999 \$TSI_EXPORT_PATH"
```

Restart, and check it worked:

```bash
docker compose up -d
docker compose exec jetty_app id
```

**You're looking for:** `uid=999(jetty)` in the output, not `uid=0(root)`.

### 3. Encrypt the disk

**Why:** If the physical or virtual disk is ever lost, stolen, or improperly decommissioned, an unencrypted disk means the data on it is just... readable. Encryption makes that data useless without the key.

**Do this:** This happens at the server level, not in Docker - turn it on when you provision the machine:

- Self-managed server: enable LUKS (Linux's built-in full-disk encryption) - most Linux installers have a checkbox for this, e.g. "Encrypt the new Ubuntu installation for security" in the Ubuntu Server installer.
- Cloud provider: turn on their managed disk encryption (AWS EBS encryption, Azure Disk Encryption, GCP CMEK) - usually also a checkbox at server-creation time.

That's it for this one - Docker automatically stores its data (the database, reports, and signing keystore) on this same disk, so encrypting the disk covers all of them. This is in addition to, not instead of, the database-level encryption you already set up in guardrail 1 via `DB_ENCRYPTION_KEY`.

### 4. Keep the database private

**Why:** Your app already reaches the database over Docker's internal network, so nothing else needs to. But the default setup also publishes the database port to the whole machine (handy for connecting a local database tool while you're evaluating) - in production, that's an open door you don't need.

**Do this:** Pick one - either restrict it to the local machine only:

```
DB_PORT_MAP=127.0.0.1:5432:5432
```

in `.env`, or remove the port publishing entirely:

```yaml
# docker-compose.override.yml
services:
  postgres_db:
    ports: []
```

**Check it worked:** From the server itself, `ss -tlnp | grep 5432` should show at most a `127.0.0.1` binding. From another machine, `nc -zv <host-ip> 5432` should fail to connect. (A host firewall is a good extra layer too, but don't rely on it alone - Docker can bypass firewall rules, so this port-publishing change is the one that actually matters.)

### 5. Back up automatically, offsite

**Why:** If this server is ever lost, corrupted, or hit by ransomware, an offsite backup is what gets you back up and running - and, for this system specifically, it's what preserves your compliance evidence (the audit ledger) even if the original is gone.

**What needs to go offsite every day:**

- The database (includes the audit/compliance ledger)
- The generated reports folder
- `.env` (without `DB_ENCRYPTION_KEY`, the encrypted data in the backup is unreadable)
- The signing keystore file (without it, previously-signed compliance evidence can't be re-verified)

**Do this:** Here's a daily backup script that covers all four, encrypts the bundle, and ships it offsite:

```bash
#!/bin/bash
# /opt/tsi-backup/backup.sh
set -euo pipefail
STAMP=$(date +%Y%m%d_%H%M%S)
OUT=/var/backups/tsi-dpdp-cms; mkdir -p "$OUT"
cd /path/to/tsi-dpdp-cms

# 1. Dump the database (safer than copying its files while it's running)
docker compose exec -T postgres_db pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -F c \
  > "$OUT/db_${STAMP}.dump"

# 2. Copy the generated reports
docker compose exec -T jetty_app tar czf - -C "$TSI_EXPORT_PATH" . \
  > "$OUT/reports_${STAMP}.tar.gz"

# 3. Copy the secrets file and signing keystore
tar czf "$OUT/secrets_${STAMP}.tar.gz" .env "$TSI_KEYSTORE_PATH"

# 4. Bundle everything into one encrypted file before it leaves this server
tar cz "$OUT"/*_"${STAMP}"* | gpg --symmetric --cipher-algo AES256 \
  -o "$OUT/bundle_${STAMP}.tar.gz.gpg"
rm "$OUT"/{db,reports,secrets}_"${STAMP}"*

# 5. Upload it somewhere that can't be modified or deleted for 30 days
aws s3 cp "$OUT/bundle_${STAMP}.tar.gz.gpg" s3://your-offsite-bucket/tsi-dpdp-cms/ \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date "$(date -d '+30 days' --iso-8601=seconds)"

find "$OUT" -type f -mtime +7 -delete
```

Schedule it to run every night:

```bash
crontab -e
# add this line:
0 2 * * * /opt/tsi-backup/backup.sh >> /var/log/tsi-backup.log 2>&1
```

An "immutable, object-locked" destination (step 5) just means: once uploaded, that backup can't be deleted or overwritten for 30 days - even by someone with your S3 credentials. That protects it from ransomware that also reaches this server. One habit worth building: actually try restoring from a backup once in a while. A backup you've never restored is a guess, not a guarantee.

## Binary

Same five guardrails, same reasons - here's what each looks like on a bare-metal Jetty deployment instead of Docker.

### 1. Keep secrets out of the repo

`server/.env` is already excluded from Git, so you're covered there. Lock it down and generate real values the same way as the Docker section:

```bash
chmod 600 server/.env
openssl rand -hex 32   # for each random secret .example asks for
```

Never commit a filled-in `.env` - and treat files like `production.env` the same way; they should only ever hold placeholders.

### 2. Don't run as root

**Do this:** Create a dedicated, low-privilege system account for the app, instead of running it as your own user or root:

```bash
sudo useradd --system --home /opt/tsi-dpdp-cms --shell /usr/sbin/nologin tsicms
sudo chown -R tsicms:tsicms /opt/tsi-dpdp-cms "$JETTY_BASE" "$TSI_EXPORT_PATH"
sudo -u tsicms ./serve.sh
```

For anything long-running, wrap this in a `systemd` unit with `User=tsicms`, rather than leaving it in a terminal session that closes when you log out.

### 3. Encrypt the disk

Exactly the same as the Docker section - enable LUKS or your cloud provider's managed disk encryption when you set up the server. That one setting covers the Postgres data directory, `$JETTY_BASE`, `$TSI_EXPORT_PATH`, and the keystore file, since they all live on the same disk.

### 4. Keep the database private

**Do this:** Tell Postgres to only listen on the local machine, and firewall the port off from the internet:

```
# postgresql.conf
listen_addresses = 'localhost'
```

Restrict `pg_hba.conf` to the application server's address, then:

```bash
sudo ufw deny 5432/tcp
```

If Postgres runs on a separate machine from the app, put it on a private subnet with no public IP - reachable only from the app server's private address, not from the internet at all.

### 5. Back up automatically, offsite

Same idea as Docker, just talking to Postgres and the filesystem directly instead of through `docker compose exec`:

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

Schedule it the same way via `crontab -e`, and test a restore every so often once you're live.

---

That's the whole list. Once you've done this for one deployment, it's a checklist you can reuse for the next one - most of it is copy-paste plus your own values.
