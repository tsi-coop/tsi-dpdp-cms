# Production Deployment Guide

**Document Version:** 1.1
**Audience:** Whoever is taking a TSI DPDP CMS install from evaluation to production.

---

## What this guide gets you

The Docker and Binary steps in the main [README](../README.md) get the system running for evaluation. A production instance holds real personal data (names, contact details, consent records and the audit ledger that proves compliance), so this guide walks you through the settings that make it safe to point real users at.

Follow the steps in order, and do the **checkpoint** at the end of each one before you move on. Each checkpoint tells you what you should see. Pick the section that matches how you installed the system:

- [Docker](#docker): the standard install.
- [Binary](#binary): Jetty running directly on the server.

It takes about an hour the first time. Afterwards it is a checklist you can reuse.

## Before you start

You need three things in place first. All of them happen outside this project:

1. **An encrypted disk.** If a disk is ever lost, stolen or sold, encryption is what keeps the data on it unreadable. Turn it on when you create the server:
   - Your own server: enable LUKS (the Linux installer has a checkbox, e.g. "Encrypt the new Ubuntu installation").
   - A cloud server: tick the managed disk encryption option when creating it (AWS EBS encryption, Azure Disk Encryption, GCP CMEK).

   This covers the database, the reports and the signing keystore, because they all live on that disk. It is in addition to the database encryption you set up in Step 1.
2. **HTTPS in front of the application.** In production the console's login cookie is marked secure, so logins only work over `https://`. Put a reverse proxy (for example nginx or Caddy) with a certificate in front of port 8080. Setting that up is outside this guide.
3. **A server that only you can reach.** Open only the ports your users need (normally 443). The database port must not be open to the internet; Step 3 makes sure of that.

---

## Docker

### First, decide where your database runs

| | Where PostgreSQL runs | Typical use |
|---|---|---|
| **Database in Docker** | In a container started by this project's `docker-compose.yml`, on the same server as the app. | The standard install. |
| **Database on a different server** | On another machine you manage, or a managed service (AWS RDS, Azure Database, Cloud SQL). | You already have a database server, or want the data off the application server. |

Parts of the steps below apply to only one of the two. They are labelled **Database in Docker** or **Database on a different server**: do the one that matches you and skip the other. Anything without a label applies to both.

### Step 1: Create your `.env` and set real secrets

The shipped `docker-compose.yml` has placeholder passwords (like `secure_dev_password`) so evaluation works out of the box. They are published in this public repo, so they must never be used in production.

1. Create the file and make it private:

   ```bash
   cp .example .env
   chmod 600 .env
   ```

2. Generate a random value for each secret. Run this once per secret and copy each result:

   ```bash
   openssl rand -hex 32
   ```

3. Open `.env` in an editor and set these:

   | Setting | What to put |
   |---|---|
   | `POSTGRES_PASSWD` | A strong password. With a database on a different server, use the password of the database user you create in Step 2. |
   | `JWT_SECRET` | A random value |
   | `DB_ENCRYPTION_KEY` | A random value. **Never change it later:** data already encrypted with it becomes unreadable. |
   | `TSI_LOOKUP_SALT` | A random value |
   | `TSI_BOOTSTRAP_TOKEN` | A random value. You use it once, in Step 6. |
   | `TSI_KEYSTORE_PASS` | A strong password (not `changeit`). Used in Step 2. |
   | `TSI_KEYSTORE_PATH` | `/etc/tsi/keystore.p12` |
   | `TSI_KEYSTORE_ALIAS` | `tsi_fiduciary` |
   | `ALLOWED_ORIGINS` | Your public address, e.g. `https://consent.example.com` |
   | `DB_PORT_MAP` | **Database in Docker only.** `127.0.0.1:5432:5432` (add this line: it keeps the database off the network) |
   | `DB_HOST` | **Database on a different server only.** Its address, e.g. `10.0.1.20` (add this line) |
   | `TSI_DPDP_CMS_ENV` | `production` (the example file says `local`) |

   `TSI_DPDP_CMS_ENV=production` switches on the production safeguards. The Rights Portal stops accepting the demo `DUMMY_OTP` login, and evidence certificates are signed with your own keystore instead of a throwaway key. It also makes the application insist on an SSL database connection, which is Step 2.

4. **Save a copy of `.env` somewhere safe now** (a password manager or encrypted vault). Without `DB_ENCRYPTION_KEY`, your backups cannot be read.

> **Checkpoint:** run `grep -c "<" .env`. It should print `0`, meaning no `<placeholder>` values are left. Also confirm `TSI_DPDP_CMS_ENV=production` is in the file.

### Step 2: Create the keystore and prepare the database

The signing keystore is needed in both cases. After it, follow **only** the part for your database. Files created here stay on the server and are never committed to Git.

#### 2a. The signing keystore (everyone)

It signs the evidence certificates. Without it, certificates cannot be verified later.

```bash
mkdir -p keystore
keytool -genkeypair -alias tsi_fiduciary -keyalg RSA -keysize 3072 \
  -sigalg SHA256withRSA -dname "CN=Your Organisation Name" \
  -storetype PKCS12 -keystore keystore/keystore.p12 \
  -validity 3650
```

When `keytool` asks for a password, enter the same value you set for `TSI_KEYSTORE_PASS`. (If `keytool` is not installed, install a Java runtime, or run the command inside any Java container.) The alias `tsi_fiduciary` must match `TSI_KEYSTORE_ALIAS`.

Give the keystore to the `jetty` user in the app image (use `sudo`, or the `docker run` form shown in 2b if you have no `sudo`):

```bash
sudo chown 999:999 keystore/keystore.p12
chmod 600 keystore/keystore.p12
```

#### 2b. Database in Docker: create the database certificate

The application connects to the database over SSL in production, and the bundled Postgres has SSL turned off by default. This creates a certificate for it. A self-signed one is fine here, because the connection is inside Docker's private network.

```bash
mkdir -p certs
openssl req -new -x509 -days 3650 -nodes -subj "/CN=postgres_db" \
  -keyout certs/server.key -out certs/server.crt
```

Now give the right owners, so the containers can read the files:

```bash
sudo chown 70:70 certs/server.key certs/server.crt       # the 'postgres' user in the database image
chmod 600 certs/server.key
```

No `sudo` on this machine? This does the same thing through Docker:

```bash
docker run --rm -v "$PWD/certs:/certs" postgres:15-alpine sh -c 'chown 70:70 /certs/* && chmod 600 /certs/server.key'
docker run --rm -v "$PWD/keystore:/ks" alpine sh -c 'chown 999:999 /ks/keystore.p12 && chmod 600 /ks/keystore.p12'
```

> **Checkpoint:** `ls -ln certs keystore` shows `70` as the owner of the two certs files and `999` as the owner of `keystore.p12`.

#### 2c. Database on a different server: prepare it and load the schema

Skip 2b: you do not need a database certificate.

**Prepare the database server**

- Postgres 13 or later, with SSL on. The application connects with `sslmode=require` in production and refuses a database without SSL. It encrypts the connection but does not check the certificate's issuer, so a self-signed certificate is fine. A managed service normally has SSL on already.
- Create the database and a user that owns it (run as a Postgres admin). Use the same names and password as `POSTGRES_USER`, `POSTGRES_DB` and `POSTGRES_PASSWD` in your `.env`:

  ```sql
  CREATE USER tsi_admin WITH PASSWORD '<POSTGRES_PASSWD from .env>';
  CREATE DATABASE tsi_cms OWNER tsi_admin;
  ALTER DATABASE tsi_cms SET app.enc_key = '<DB_ENCRYPTION_KEY from .env>';
  ```

  The last line stores the encryption key as a database setting. It is what `db/03z_enc_key.sh` does for the database in Docker. It must be run by a Postgres admin: the database owner is refused (`permission denied to set parameter "app.enc_key"`). Use the exact `DB_ENCRYPTION_KEY` value from your `.env`, and never change it later.
- Allow only the application server. In `postgresql.conf` set `listen_addresses` to the server's private address, and in `pg_hba.conf` add one line (the address is the application server's):

  ```
  hostssl  tsi_cms  tsi_admin  10.0.1.15/32  scram-sha-256
  ```

  Then reload Postgres. On a managed service, do the same with its security group or firewall rule. Keep the server on a private subnet with no public IP, and never open port 5432 to the internet.

**Load the schema (once)**

The database in Docker loads the `db/` scripts by itself on first start. A separate database does not, so load them from the application server (as the `tsi_admin` user, after the admin step above). Run this from the project folder (replace `<db-host>`):

```bash
set -a; source .env; set +a
export PGPASSWORD="$POSTGRES_PASSWD" PGSSLMODE=require
PSQL="psql -h <db-host> -U $POSTGRES_USER -d $POSTGRES_DB -v ON_ERROR_STOP=1"

for f in db/*.sql; do echo "== $f"; $PSQL -f "$f"; done
```

The scripts create the `pgcrypto` and `uuid-ossp` extensions. If your managed service does not let the database owner create them, ask an admin to run `CREATE EXTENSION pgcrypto; CREATE EXTENSION "uuid-ossp";` first.

> **Checkpoint:** the loop ends without an `ERROR`, and a new `psql` connection as `tsi_admin` prints your key for `SHOW app.enc_key;`. Run the loop only once: if it fails halfway, fix the cause and get help before re-running it on a half-loaded database.

### Step 3: Create the override file

You do not edit the shipped `docker-compose.yml`. Instead, create a file next to it called `docker-compose.override.yml`. Docker Compose merges it in automatically. Use the file for your database.

**Database in Docker:**

```yaml
# docker-compose.override.yml
services:
  jetty_app:
    user: "999:999"            # run the app as the low-privilege 'jetty' user, not root
    volumes:
      - ./keystore:/etc/tsi:ro # the signing keystore from Step 2a

  postgres_db:
    volumes:
      - ./certs:/certs:ro      # the database certificate from Step 2b
    command: >
      postgres -c ssl=on
      -c ssl_cert_file=/certs/server.crt
      -c ssl_key_file=/certs/server.key
```

**Database on a different server:**

```yaml
# docker-compose.override.yml
services:
  jetty_app:
    user: "999:999"            # run the app as the low-privilege 'jetty' user, not root
    volumes:
      - ./keystore:/etc/tsi:ro # the signing keystore from Step 2a
    environment:
      POSTGRES_HOST: "jdbc:postgresql://${DB_HOST}:5432"   # DB_HOST from your .env; change the port if yours differs
    depends_on: !reset []      # do not wait for the bundled database

  postgres_db:
    profiles: ["bundled-db"]   # the bundled database is never started
```

`!reset` needs Docker Compose 2.24 or later (`docker compose version`). On an older version, leave out the `depends_on` line and start the app with `docker compose up -d --no-deps jetty_app` instead of `docker compose up -d` in Step 5.

What each part does:

- **`user: "999:999"`:** the shipped file runs the app as `root` to work around a file-permission issue. If the app were ever compromised, `root` would give an attacker control of the whole container. This runs it as the unprivileged `jetty` user instead (Step 4 fixes the permission issue properly).
- **The keystore mount:** makes your keystore visible to the app at `/etc/tsi/keystore.p12`, read-only.
- **The Postgres settings (Database in Docker):** turn SSL on with your certificate.
- **The database port (Database in Docker):** already limited to this machine by `DB_PORT_MAP` in Step 1.
- **`POSTGRES_HOST` and `profiles` (Database on a different server):** point the app at your database and stop the bundled one from starting.

Add the two new folders to `.gitignore` so they are never committed:

```bash
printf '/certs/\n/keystore/\n' >> .gitignore
```

> **Checkpoint:** `docker compose config > /dev/null && echo OK` prints `OK`. If it prints an error, check the indentation in the override file (use spaces, not tabs).

### Step 4: Fix the reports folder permissions (once)

The reports volume was created for `root`. Give it to the `jetty` user so the app can write to it:

```bash
docker compose run --rm --user root --entrypoint sh jetty_app \
  -c "chown -R 999:999 \$TSI_EXPORT_PATH"
```

This also starts the database container, which is fine.

### Step 5: Start the system and check it

```bash
docker compose up -d
```

Wait about 30 seconds, then run these checks one by one.

**1. The app runs as the `jetty` user, not root:**

```bash
docker compose exec jetty_app id
```

> You should see `uid=999(jetty)`, not `uid=0(root)`.

**2. The database has SSL on:**

*Database in Docker:*

```bash
docker compose exec postgres_db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SHOW ssl;"
```

> You should see `on`. (Load your `.env` first with `set -a; source .env; set +a` if `$POSTGRES_USER` is empty.)

*Database on a different server:*

```bash
psql "host=$DB_HOST user=$POSTGRES_USER dbname=$POSTGRES_DB sslmode=require" -c "SHOW ssl;"
```

> You should see `on`.

**3. The app started in production mode:**

```bash
docker compose logs jetty_app | grep "Service started"
```

> You should see `... Service started in production environment`. If you see `[WARNING]` about the environment, or `local environment`, check `TSI_DPDP_CMS_ENV` in `.env`.

**4. The database is not reachable from outside:**

*Database in Docker:*

```bash
ss -tlnp | grep 5432
```

> You should see only `127.0.0.1:5432`, never `0.0.0.0:5432`. From another machine, `nc -zv <server-ip> 5432` should fail to connect.

*Database on a different server:* from a machine that is **not** the application server, `nc -zv <db-host> 5432` should fail to connect.

**If every request shows an error page**, run `docker compose logs jetty_app | tail -30`. The line `The server does not support SSL` means the database does not have SSL on. *Database in Docker:* Step 3's Postgres settings were not applied, so run `docker compose up -d` again and repeat check 2. *Database on a different server:* turn SSL on there (Step 2c). If the log shows `Connection refused`, `timed out` or `no pg_hba.conf entry`, the firewall, `listen_addresses` or the `pg_hba.conf` line is blocking the application server.

### Step 6: Create the admin account

This only works once, and only with the token you set in Step 1.

1. Open `https://<your-address>/console/setup/init.html`.
2. Enter the `TSI_BOOTSTRAP_TOKEN` value as the **Setup Token**, then create your Super-Admin account.
3. Sign in to the console.
4. Go to **Settings** and, for every organisation, set the OTP delivery mode to **Email OTP** or **Mobile OTP** (the code is delivered by your OTP webhook). In production, an organisation still on `DUMMY_OTP` cannot log its principals in. The Rights Portal is an evaluation tool for implementers, not something to give your data principals: they use your own application, which calls the CMS API with opaque principal IDs.

You can now remove or change `TSI_BOOTSTRAP_TOKEN`. It is only checked until the first admin exists.

> **Checkpoint:** you can sign in to the console over `https://`.

### Step 7: Set up backups

Do this on day one, not later. It takes about 20 minutes, and the [Backup and Restore Guide](backup-and-restore-guide.md) walks you through it step by step. In short:

```bash
./backup/backup.sh                              # take a backup now
./backup/restore.sh <the-backup-file>.sql.gz    # prove it can be restored (safe, touches nothing live)
```

Then schedule it nightly, store a copy off the server, and keep an encrypted copy of your `.env` and keystore. All three are explained in that guide.

*Database on a different server:* `backup/backup.sh` backs up the database in Docker only. Use the `pg_dump` approach in [Binary Step 6](#step-6-set-up-backups) with `-h <db-host>`, or your provider's managed snapshots plus a `pg_dump` copy.

> **Checkpoint:** the restore check ends with `Verification complete - backup is restorable.`

**You are done with the Docker setup.** For upgrades, see [Upgrading to a new release](#upgrading-to-a-new-release) below.

---

## Binary

These steps are the same ones as above, for Jetty running directly on the server. First decide where Postgres runs:

- **Database on this server (localhost):** Postgres is installed on the same machine as Jetty.
- **Database on a different server:** Postgres is on another machine, or is a managed service (AWS RDS, Azure Database, Cloud SQL).

Only Step 1 and Step 4 differ. They are labelled for each case.

### Step 1: Set real secrets

`server/.env` is already excluded from Git.

```bash
chmod 600 server/.env
openssl rand -hex 32     # run once per secret, and copy each result
```

Open `server/.env` and set real values for `POSTGRES_PASSWD`, `JWT_SECRET`, `DB_ENCRYPTION_KEY` (never change it later: data already encrypted with it becomes unreadable), `TSI_LOOKUP_SALT`, `TSI_BOOTSTRAP_TOKEN`, `TSI_KEYSTORE_PASS` (not `changeit`) and `ALLOWED_ORIGINS`. Set `TSI_DPDP_CMS_ENV=production`. Set `POSTGRES_HOST`: `jdbc:postgresql://localhost:5432` for a database on this server, or `jdbc:postgresql://<db-host>:5432` for one on a different server. Treat files such as `production.env` the same way: never commit real values. **Save a copy of the file somewhere safe now**, since without `DB_ENCRYPTION_KEY` your backups cannot be read.

> **Checkpoint:** no `<placeholder>` values are left in `server/.env`, and `TSI_DPDP_CMS_ENV=production` is set.

### Step 2: Create the signing keystore

```bash
sudo mkdir -p /etc/tsi
sudo keytool -genkeypair -alias tsi_fiduciary -keyalg RSA -keysize 3072 \
  -sigalg SHA256withRSA -dname "CN=Your Organisation Name" \
  -storetype PKCS12 -keystore /etc/tsi/keystore.p12 -validity 3650
```

Enter the same password as `TSI_KEYSTORE_PASS`. Set `TSI_KEYSTORE_PATH=/etc/tsi/keystore.p12` and `TSI_KEYSTORE_ALIAS=tsi_fiduciary` in `server/.env`. Step 3 gives the `tsicms` user access to this file.

### Step 3: Run the app as its own low-privilege user

Do not run it as root or as your own login.

```bash
sudo useradd --system --home /opt/tsi-dpdp-cms --shell /usr/sbin/nologin tsicms
sudo chown -R tsicms:tsicms /opt/tsi-dpdp-cms "$JETTY_BASE" "$TSI_EXPORT_PATH"
sudo chown tsicms:tsicms /etc/tsi/keystore.p12 && sudo chmod 600 /etc/tsi/keystore.p12
sudo -u tsicms ./serve.sh
```

For a long-running service, wrap this in a `systemd` unit with `User=tsicms`, so it keeps running after you log out.

> **Checkpoint:** `ps -o user= -C java` shows `tsicms`.

### Step 4: Make the database private, and turn on SSL

#### Database on this server (localhost)

In `postgresql.conf`, make Postgres listen only on this machine and turn on SSL:

```
listen_addresses = 'localhost'
ssl = on
ssl_cert_file = '/etc/postgresql/server.crt'
ssl_key_file  = '/etc/postgresql/server.key'
```

Create the certificate (or use one from your CA). A self-signed one is fine, since the app only requires an encrypted connection and does not check who issued the certificate:

```bash
sudo openssl req -new -x509 -days 3650 -nodes -subj "/CN=localhost" \
  -keyout /etc/postgresql/server.key -out /etc/postgresql/server.crt
sudo chown postgres:postgres /etc/postgresql/server.key /etc/postgresql/server.crt
sudo chmod 600 /etc/postgresql/server.key
```

In `pg_hba.conf`, use `hostssl` instead of `host` for the application's entry, so non-SSL connections are rejected. Then restart Postgres and block the port from the internet:

```bash
sudo systemctl restart postgresql
sudo ufw deny 5432/tcp
```

> **Checkpoint:** `psql -c "SHOW ssl;"` prints `on`, and `ss -tlnp | grep 5432` shows only `127.0.0.1`.

#### Database on a different server

Put the database on a private subnet with no public IP, reachable only from the application server. Prepare and load it exactly as in [Docker Step 2c](#2c-database-on-a-different-server-prepare-it-and-load-the-schema): create the database and user, allow only the application server in `pg_hba.conf` with a `hostssl` line, and load the schema. The `psql` commands are the same. Then:

- Make sure `POSTGRES_HOST` in `server/.env` points to it (Step 1).
- On the database server, open port 5432 only to the application server, for example `sudo ufw allow from <app-server-ip> to any port 5432 proto tcp`. On a managed service, use its security group or firewall rule. Never open it to the internet.

> **Checkpoint:** from the application server, `psql "host=<db-host> user=<user> dbname=<db> sslmode=require" -c "SHOW ssl;"` prints `on`, and `nc -zv <db-host> 5432` from any other machine fails to connect. A managed Postgres service normally has SSL on already.

### Step 5: Start, create the admin, and check

Start the application as in Step 3. Check the log for `Service started in production environment`. Then create the admin account and set each organisation's OTP mode, exactly as in Docker Step 6 (open `/console/setup/init.html` with your `TSI_BOOTSTRAP_TOKEN`).

> **Checkpoint:** you can sign in to the console over `https://`.

### Step 6: Set up backups

The scripts in `backup/` are written for Docker. On a Binary install, use the same ideas with the commands below. Save this as `/opt/tsi-backup/backup.sh`:

```bash
#!/bin/bash
set -euo pipefail
STAMP=$(date +%Y%m%d_%H%M%S)
OUT=/var/backups/tsi-dpdp-cms; mkdir -p "$OUT"

pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -F c -f "$OUT/db_${STAMP}.dump"
tar czf "$OUT/exports_${STAMP}.tar.gz" "$TSI_EXPORT_PATH"
tar czf "$OUT/secrets_${STAMP}.tar.gz" /path/to/server/.env "$TSI_KEYSTORE_PATH"

# Encrypt everything into one file before it leaves the server (you will be asked for a passphrase: store it in a password manager)
tar cz "$OUT"/*_"${STAMP}"* | gpg --symmetric --cipher-algo AES256 -o "$OUT/bundle_${STAMP}.tar.gz.gpg"
rm "$OUT"/{db,exports,secrets}_"${STAMP}"*

# Copy it off the server (here: S3 with Object Lock, so it cannot be deleted for 30 days, even with your credentials)
aws s3 cp "$OUT/bundle_${STAMP}.tar.gz.gpg" s3://your-offsite-bucket/tsi-dpdp-cms/ \
  --object-lock-mode COMPLIANCE --object-lock-retain-until-date "$(date -d '+30 days' --iso-8601=seconds)"

find "$OUT" -type f -mtime +7 -delete
```

Schedule it nightly with `crontab -e`:

```
0 2 * * * /opt/tsi-backup/backup.sh >> /var/log/tsi-backup.log 2>&1
```

> **Checkpoint:** run it once by hand, then actually restore from the result on a spare machine. A backup you have never restored is a guess, not a guarantee.

---

## Upgrading to a new release

The scripts in `db/` run automatically only when the database is first created. When you upgrade an existing install, you apply the new ones yourself, once. The [release notes](../../RELEASE_NOTES.md) say which. They are written to be safe to run again.

**Docker**

1. Back up first: `./backup/backup.sh`
2. Pull the new image and restart:

   ```bash
   docker compose pull && docker compose up -d
   ```

3. Apply the scripts the release notes name. This example is for v0.5.4; `POSTGRES_USER` and `POSTGRES_DB` are the values from your `.env`:

   ```bash
   set -a; source .env; set +a
   for f in db/14_policy_version_backfill.sql db/15_breach_deadline.sql db/16_webhook_deliveries.sql db/17_notification_log.sql; do
     docker compose exec -T postgres_db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 < "$f"
   done
   ```

**Binary:** back up, deploy the new WAR, then run each script with `psql -h <host> -U <user> -d <db> -v ON_ERROR_STOP=1 -f db/<file>.sql` and restart Jetty.

### Upgrading to v0.6

Apply `db/18` to `db/27`, in this order. Each is safe to run again; run them as the database owner or a superuser.

```bash
set -a; source .env; set +a
for f in db/18_audit_ledger_integrity.sql db/19_operator_access.sql db/20_roles.sql db/21_consent_capture.sql \
         db/22_grievance_enhancements.sql db/23_rights_requests.sql db/24_nominations_and_purposes.sql \
         db/25_purge_and_legal_holds.sql db/26_breach_board_intimation.sql db/27_purge_processor_obligation.sql; do
  docker compose exec -T postgres_db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 < "$f"
done
```

(Binary: `psql -h <host> -U <user> -d <db> -v ON_ERROR_STOP=1 -f db/<file>.sql` for each.)

- `db/18` makes the audit trail append-only and numbers the existing rows; on a large audit table allow a few minutes. Take the backup first.
- Before you deploy, make sure `.env` has real secrets: production now refuses to start on a placeholder, or a `JWT_SECRET` shorter than 32 characters.
- Optional settings (all described in `production.env`; leave them unset for the defaults): `ACCESS_CONTROL_MODE`, `MFA_ENFORCE`, `CONSENT_CAPTURE_MODE`, `TOKEN_TTL_MINUTES`, `TRUSTED_PROXY`, `ACCESS_SLA_DAYS`, `CORRECTION_SLA_DAYS`, `PURGE_COMPLETION_SLA_DAYS`, `POLICY_CACHE_TTL_SECONDS`. If you run behind nginx or another proxy, set `TRUSTED_PROXY` to its address.

**After upgrading to v0.6, check:**

- **MFA:** every ADMIN, DPO and AUDITOR is asked to enrol an authenticator app at their next login (production). Tell them beforehand, and keep one ADMIN's phone details safe, since a lost authenticator needs another ADMIN to reset it.
- **Everyone is signed in again**, because sessions use the new format.
- **Shadow mode:** after a normal week of use, read the `ACCESS_SHADOW_DENY` and `ACCESS_SHADOW_TENANT` events in the audit page, then decide whether to set `ACCESS_CONTROL_MODE=enforce` ([rollout guide](../security/access-control-rollout.md)).
- **Consent capture warnings:** read `CONSENT_CAPTURE_WARNING` events, fix the integrations, then consider `CONSENT_CAPTURE_MODE=strict`.
- **Audit chain:** the daily check writes its result to the audit page; the first run should report the chain as intact.
- **Security controls outside the CMS:** fill in the table in [Key management](../security/KEY_MANAGEMENT.md) (disk encryption, encrypted backups, TLS, restore rehearsal).

**After upgrading, check:**

- The output of `db/14_policy_version_backfill.sql`. It prints a `NOTICE` for any policy it could not safely renumber, and a final count of consent rows still without a version.
- Each organisation's OTP mode in **Settings -> Rights Management App**. In production, an organisation still on `DUMMY_OTP` cannot log its principals in until it is switched to Email or Mobile OTP.
