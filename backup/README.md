# Backup and restore

Step-by-step walkthrough: [Backup and Restore Guide](../docs/guides/backup-and-restore-guide.md).

Operational scripts for a Docker deployment. Nothing here runs automatically: run them yourself or from your own cron/systemd.

## What gets backed up

| Item | File | Notes |
|---|---|---|
| Database | `tsi_dpdp_cms_<ts>.sql.gz` | Plain SQL from `pg_dump --clean --if-exists`, gzip-tested before it is kept. Includes the audit ledger. |
| Reports volume | `tsi_dpdp_cms_exports_<ts>.tar.gz` | Generated reports / evidence exports. On by default. |
| Secrets (optional) | `tsi_dpdp_cms_secrets_<ts>.tar.gz.enc` | `.env` and the signing keystore, AES-256 encrypted. Off by default. |

Without `DB_ENCRYPTION_KEY` (in `.env`) the encrypted personal data in the database cannot be read, and without the keystore previously signed certificates cannot be re-verified. Back them up, but never store the passphrase with the backups.

## Setup

```bash
cp backup/backup.env.example backup/backup.env    # gitignored
```

| Variable | Default | Description |
|---|---|---|
| `DB_CONTAINER` | `tsi_dpdp_cms_db` | Postgres container |
| `POSTGRES_DB` / `POSTGRES_USER` | `tsi_cms` / `tsi_admin` | Must match your deployment |
| `LOCAL_BACKUP_DIR` | `~/tsi-dpdp-cms-backups` | Staging directory |
| `BACKUP_DEST_DIR` | falls back to `LOCAL_BACKUP_DIR` | Copy destination (NAS, external drive). Must exist. Unset = nothing leaves this host, and the script warns. |
| `RETENTION_DAYS` | `14` | Applied to both directories |
| `INCLUDE_EXPORTS` / `EXPORTS_VOLUME` | `true` / `tsi-dpdp-cms_tsi_reports_data` | Reports volume (`<compose project>_tsi_reports_data`) |
| `INCLUDE_SECRETS` | `false` | Add the encrypted secrets bundle |
| `BACKUP_PASSPHRASE_FILE` or `BACKUP_PASSPHRASE` | | Required when `INCLUDE_SECRETS=true`. The script refuses to write secrets unencrypted. |
| `ENV_FILE` | `../.env` | `.env` to include |
| `KEYSTORE_FILE` | unset | Host path of the file mounted at `TSI_KEYSTORE_PATH`. If unset, the keystore is not backed up and the script warns. |

## Run

```bash
./backup/backup.sh
```

Exits non-zero if the destination is missing (share not mounted), the DB container is down, or the passphrase is missing. Daily at 2 AM:

```
0 2 * * * /path/to/tsi-dpdp-cms/backup/backup.sh >> /path/to/backup.log 2>&1
```

## Restore

`DB_ENCRYPTION_KEY` is found automatically: from the environment, then `.env` in the repo root, then the running app container. `pg_dump` does not carry the database-level `app.enc_key` setting, so `restore.sh` re-applies it from this key.

### Verify (default, safe)

Restores into a throwaway Postgres container, applies the key, prints table and row counts (`fiduciaries`, `data_principal`, `consent_policies`, `consent_records`, `audit_logs`, `breach_incidents`, `ropa_entries`, `webhook_deliveries`) and confirms `app.enc_key` is set, then discards the container. The live system is never touched.

```bash
./backup/restore.sh /path/to/tsi_dpdp_cms_20261028_020000.sql.gz
```

The matching `..._exports_<ts>.tar.gz` next to the dump is picked up automatically.

### Live restore (destructive)

Replaces all data in the live database after you type `RESTORE`. The reports volume's current contents are moved to `.pre-restore-<ts>` inside the volume, not deleted. Stop the app first, restart it after.

```bash
docker compose stop jetty_app
./backup/restore.sh /path/to/tsi_dpdp_cms_<ts>.sql.gz --live
docker compose restart jetty_app
```

### Recover the secrets

Decrypts into a directory you choose; it never overwrites anything live.

```bash
BACKUP_PASSPHRASE_FILE=/path/to/passphrase ./backup/restore.sh --extract-secrets tsi_dpdp_cms_secrets_<ts>.tar.gz.enc /safe/dir
```
