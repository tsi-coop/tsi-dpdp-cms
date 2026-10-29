# Backup and Restore Guide

**Document Version:** 1.1
**Audience:** Whoever runs a TSI DPDP CMS install and is responsible for not losing its data.

---

## What this guide gets you

After following it you will have:

1. a backup of your database and reports, taken with one command,
2. proof that the backup can be restored,
3. a nightly schedule, with a copy stored off the server,
4. (optional) an encrypted copy of your keys, so you can rebuild from nothing.

It takes about 20 minutes. The scripts are in the [`backup/`](../../backup/) folder and work with the standard Docker install. For hardening the rest of the server, see the [Production Deployment Guide](production-deployment-guide.md).

**Before you start**, check that:

- the system is running (`docker compose ps` shows `tsi_dpdp_cms_db` as running), and
- you are in the project folder (the one containing `docker-compose.yml`).

---

## Step 1: Take your first backup

```bash
./backup/backup.sh
```

You should see something like this:

```
[2026-10-28 02:00:01] Dumping database 'tsi_cms' from 'tsi_dpdp_cms_db'...
[2026-10-28 02:00:02] Archiving reports volume 'tsi-dpdp-cms_tsi_reports_data'...
[2026-10-28 02:00:02] Backup complete: tsi_dpdp_cms_20261028_020001.sql.gz tsi_dpdp_cms_exports_20261028_020001.tar.gz
```

It also prints a warning that `BACKUP_DEST_DIR` is not set. That is fine for now; Step 4 fixes it.

Your backup files are in `~/tsi-dpdp-cms-backups/`:

| File | What it holds |
|---|---|
| `tsi_dpdp_cms_<date>.sql.gz` | The database, including the audit ledger |
| `tsi_dpdp_cms_exports_<date>.tar.gz` | Generated reports |

**If it fails**, the message says why. The common ones:

| Message | Fix |
|---|---|
| `container 'tsi_dpdp_cms_db' is not running` | Start the system: `docker compose up -d` |
| `volume ... does not exist` | Your project folder has a different name. Run `docker volume ls`, find the one ending in `tsi_reports_data`, and put its full name in Step 4's `EXPORTS_VOLUME`. |

---

## Step 2: Check that the backup can be restored

A backup you have never restored is only a guess. This check is safe: it restores into a temporary database and throws it away. **Your live system is not touched.**

```bash
./backup/restore.sh ~/tsi-dpdp-cms-backups/tsi_dpdp_cms_<date>.sql.gz
```

Replace `<date>` with the real file name (type `~/tsi-dpdp-cms-backups/` and press Tab to complete it). It takes under a minute. A good result ends like this:

```
tables: 24
fiduciaries: 2 rows
data_principal: 4 rows
consent_policies: 5 rows
consent_records: 7 rows
audit_logs: 84 rows
...
  app.enc_key: set
Verification complete - backup is restorable.
```

**What to check:** the row counts should be close to what you see in the system. And `app.enc_key: set` must be present. If the last line is not `Verification complete`, the backup is not usable: do not rely on it.

---

## Step 3: Set where backups are stored

Right now the backups sit on the same server as the system. If that server is lost, the backups go with it. Choose a folder that lives somewhere else, such as a mounted network drive (NAS), an external drive or a synced cloud folder.

1. Create your settings file:

   ```bash
   cp backup/backup.env.example backup/backup.env
   ```

2. Open `backup/backup.env` in an editor and change this line (remove the `#` at the start):

   ```bash
   BACKUP_DEST_DIR=/mnt/nas/tsi-dpdp-cms
   ```

   The folder must already exist. If it is a network drive, make sure it is mounted.

3. Run `./backup/backup.sh` again. The warning disappears, and the files now appear in both places.

Old backups are deleted automatically after 14 days. Change `RETENTION_DAYS` in the same file if you want longer.

---

## Step 4: Run it every night

```bash
crontab -e
```

Add this line at the bottom (change the path to your project folder), then save:

```
0 2 * * * /path/to/tsi-dpdp-cms/backup/backup.sh >> /path/to/backup.log 2>&1
```

This runs the backup at 2 AM every day and writes what happened to `backup.log`.

**Check it tomorrow:** open `backup.log` and look for `Backup complete`. Check again after a week. Also repeat Step 2 now and then (monthly is a good habit) using a recent backup.

---

## Step 5 (recommended): Back up your keys

The database backup alone is not enough to rebuild the system:

- **`DB_ENCRYPTION_KEY`** (in your `.env`): personal data is encrypted with it. Without it, a restored database cannot be read.
- **The signing keystore:** certificates signed with it can only be verified with the same key.

This step puts both into one encrypted file, which is only useful to someone who has your passphrase.

1. Create a passphrase file:

   ```bash
   openssl rand -base64 32 > ~/.tsi-backup-passphrase
   chmod 600 ~/.tsi-backup-passphrase
   ```

2. **Copy that passphrase into your password manager now.** Keep it somewhere other than the backups. If you lose it, the encrypted file cannot be opened by anyone.

3. In `backup/backup.env`, set:

   ```bash
   INCLUDE_SECRETS=true
   BACKUP_PASSPHRASE_FILE=/home/<you>/.tsi-backup-passphrase
   KEYSTORE_FILE=/path/to/keystore.p12
   ```

   `KEYSTORE_FILE` is the keystore file on the server (the one your configuration points `TSI_KEYSTORE_PATH` at). If you are only evaluating and have no keystore yet, leave that line out: the backup will warn you and carry on.

4. Run `./backup/backup.sh`. A third file, `tsi_dpdp_cms_secrets_<date>.tar.gz.enc`, now appears next to the others.

If you turn on `INCLUDE_SECRETS` without a passphrase, the script refuses to run rather than saving your keys unprotected.

---

## If something goes wrong: recovering

### A. Restore the database and reports

This **replaces everything** currently in the system. Use it only for real recovery.

```bash
docker compose stop jetty_app
./backup/restore.sh ~/tsi-dpdp-cms-backups/tsi_dpdp_cms_<date>.sql.gz --live
docker compose restart jetty_app
```

The script asks you to type `RESTORE` before it does anything. If a reports archive with the same date is next to the database file, it is restored too, and the old reports are moved into a `.pre-restore-<time>` folder, not deleted.

After it finishes, sign in and check that recent consents and policies are there.

### B. Rebuild on a new server

1. Install Docker, get the project folder, and start it: `docker compose up -d`. This creates an empty system.
2. Get your keys back (next section) and put `.env` in the project folder.
3. Copy your backup files to the new server and do A above.

### C. Get your keys back from the encrypted file

```bash
BACKUP_PASSPHRASE_FILE=~/.tsi-backup-passphrase \
  ./backup/restore.sh --extract-secrets tsi_dpdp_cms_secrets_<date>.tar.gz.enc /tmp/recovered
```

If your passphrase file is gone, leave out the first line and it will ask you to type the passphrase instead.

You then have `/tmp/recovered/.env` and `/tmp/recovered/keystore.p12`. Nothing in your live system is changed: you copy them where they belong. Delete `/tmp/recovered` afterwards.

---

## Quick reference

| I want to... | Run |
|---|---|
| Take a backup now | `./backup/backup.sh` |
| Check a backup works (safe) | `./backup/restore.sh <backup>.sql.gz` |
| Recover into the live system | `./backup/restore.sh <backup>.sql.gz --live` |
| Get my keys back | `./backup/restore.sh --extract-secrets <file>.enc <folder>` |

Every setting and what it does: [`backup/README.md`](../../backup/README.md).

## Common problems

| Problem | Fix |
|---|---|
| `BACKUP_DEST_DIR ... does not exist` | The drive is not mounted, or the path is wrong. Mount it and retry. |
| `Decryption failed` | Wrong passphrase, or the file is damaged. Try a different day's file. |
| `DB_ENCRYPTION_KEY not found` | Put it in `.env`, or run `export DB_ENCRYPTION_KEY=<the key>` first. It must be the key the data was encrypted with. |
| `role "..." does not exist` | You are using a different database user than the backup was taken with. Set `POSTGRES_USER` in `backup/backup.env` to the original user. |
| Backup works by hand but not from cron | Cron has a minimal environment. Use full paths everywhere, and check `backup.log`. |
