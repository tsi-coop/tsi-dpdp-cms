# Key management

Who holds which secret, what it protects, and what happens if it is lost or leaked.
Fill in the **Owner** column for your deployment; a secret nobody owns is a secret nobody backs up.

## 1. Principal IDs and what protects them

Implementers should send **opaque principal IDs** (a customer number or UUID), not email addresses or phone numbers
(see the [system integration guide](../guides/system-integration-guide.md#choosing-the-principal-id)), prefixed with the kind of principal (`c-1234`, `e-2345`) so IDs from different systems cannot collide, and with a prefix that reveals nothing sensitive. An opaque ID identifies nobody
on its own, but it is still personal data because you can link it to a person. The CMS therefore relies on your **deployment** to
protect it at rest and in transit. Principal IDs are stored as plain text in the database and in the audit log. The CMS does not
encrypt them in the database columns; that is an optional hardening step (see `docs/plan/principal-data-protection-evaluation.md`).

## 2. Application secrets

| Secret | Layer | What it protects | If lost | If leaked | Rotation | Owner |
|---|---|---|---|---|---|---|
| `DB_ENCRYPTION_KEY` (also stored in the database as `app.enc_key`) | Application, selected columns only | Values encrypted with pgcrypto: operator, fiduciary and app contact details, operator MFA secrets, webhook secrets, nominee name and contact | Those values cannot be read again; backups cannot be restored usefully | A copy of the database can be decrypted | **Not rotatable today.** Changing it makes existing encrypted data unreadable; a re-encrypt migration would be needed | |
| `TSI_LOOKUP_SALT` | Application | Deterministic hashes: the IP address stored with each consent record, the audit-trail lookup used for evidence certificates, and the account key in recovery rate limits | Hashes already stored (consent IP addresses) can no longer be matched, and certificate lookups of old audit rows stop matching | Stored IP hashes become easier to guess (there are few possible addresses) | **Not rotatable today**, same reason | |
| `JWT_SECRET` | Application | Login and session tokens | Everyone is logged out; no data is lost | Anyone can forge a login token: rotate at once | Safe to rotate at any time (everyone logs in again) | |
| `TSI_KEYSTORE_PASS` and the keystore file (`TSI_KEYSTORE_PATH`) | Application | Signature on evidence certificates | New certificates cannot be signed; old ones cannot be verified | Certificates can be forged | Issue a new key and record the date; certificates signed earlier stay valid under the old key | |
| `TSI_BOOTSTRAP_TOKEN` | Application | First-time admin setup | Setup cannot be repeated | A stranger could create the first admin if setup is open | Replace after setup | |
| `POSTGRES_PASSWD` | Database | Access to all data | The application cannot connect | Full data access | Rotate in the database and `.env` together | |

`DB_ENCRYPTION_KEY` is **not a disk encryption key**. It protects only the columns listed above. Anyone with administrator access to
the live database can read it (it is the database setting `app.enc_key`), so it guards against a stolen dump or a read-only
user, not against a database administrator.

## 3. Rules for storing secrets

* Real values live in the environment or a secrets manager, never in the repository, logs, tickets or chat. `.env` and `production.env`
  hold placeholders only in the repo.
* Use different values in every environment.
* The application refuses to start in production on a placeholder or a too-short `JWT_SECRET`, and warns on a short
  `DB_ENCRYPTION_KEY` or `TSI_LOOKUP_SALT` (`util/SecretGuard`).
* Keep the **backup of the secrets apart from the backup of the database**. A backup that holds both the data and its key
  defeats the encryption. Keep an encrypted copy of `.env` and the keystore in a password manager or vault.
* Once a year, restore a backup into a scratch database using only the stored secrets, to prove they work.

## 4. Infrastructure controls (required, outside the repository)

These are not enforced by the CMS. Each needs a named owner and evidence.

| Control | What it means | Owner | Confirmed by / date | Evidence |
|---|---|---|---|---|
| Disk or volume encryption | The database server's disk, replicas and snapshots are encrypted (LUKS, or the cloud's managed disk encryption) | | | |
| Encrypted backups | Backup files and off-server copies are encrypted | | | |
| TLS to the CMS | The application is reached over HTTPS only | | | |
| TLS to the database | Enforced by the application in production (`sslmode=require`); a database without SSL is refused | | | |
| Restricted database access | Only the application and named administrators can connect; the database port is not public | | | |
| Restore rehearsal | A backup is restored to a scratch database and verified (`backup/restore.sh`) | | | |

The [production deployment guide](../guides/production-deployment-guide.md) shows how to set each of these up.

## 5. If a secret is suspected leaked

* `JWT_SECRET`: rotate and restart; all sessions end. Review the audit log for the period.
* `DB_ENCRYPTION_KEY` or a database copy: treat encrypted contact details and webhook secrets as exposed; rotate webhook secrets and
  operator MFA enrolments; assess whether a personal data breach must be reported (use the Breach module).
* Keystore: stop issuing certificates, replace the key, note the date.
* `POSTGRES_PASSWD`: rotate immediately and review database access logs.

## 6. Losing `DB_ENCRYPTION_KEY`

Encrypted columns become unreadable and a restored database cannot decrypt them. Principal IDs, consent records and the audit log are
not encrypted with this key, so the consent evidence itself survives, but operator logins, webhook configuration and nominee details
would have to be re-created. Keep the key backed up as described above.
