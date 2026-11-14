# Plan: OpenJDK 21 and PostgreSQL 17 on Docker Compose

**Status:** Proposed. Open decisions in section 8. Nothing here has been built or tested yet; the compatibility statements below are what the code and configuration suggest and must be confirmed by the test pass in section 6.
**Goal:** the Docker Compose stack runs on OpenJDK 21 (Jetty) and PostgreSQL 17 by default, with a safe upgrade path for existing deployments.

## 1. Where we are

| Item | Today | Where |
|---|---|---|
| App runtime image | `jetty:jdk17` (floating tag) | `Dockerfile:2` |
| Compile target | `maven.compiler.source/target` 15, compiler plugin 3.11.0 | `pom.xml:17-18,162` |
| Documented JDK | "17 or higher" (Temurin) | `docs/guides/local-development-guide.md:29,47,241` |
| Database image | `postgres:15-alpine` | `docker-compose.yml:12` |
| Same image elsewhere | restore verification default; `chown` helper in the production guide | `backup/restore.sh:32`, `docs/guides/production-deployment-guide.md` (step 2b) |
| JDBC driver | `postgresql` 42.7.3 | `pom.xml:23` |
| Documented PostgreSQL | "15 or higher" (Path B), "13 or later" (production, external DB) | local development and production guides |
| Extensions and settings | `pgcrypto`, `uuid_generate_v4()`, database-level `app.enc_key` set by `db/03z_enc_key.sh` | `db/01_init.sql`, `db/04_gaps.sql`, `db/03z_enc_key.sh` |

## 2. What the code suggests about compatibility

**Java 21**
- No use of `sun.*`, `SecurityManager`, `Unsafe`, `setAccessible`, scripting engines, or removed `javax.*` modules in `src/`.
- The only deprecated API found is `finalize()` in `CsvWriter` and `CsvReader`. It still works on 21 (deprecated for removal, not removed). Optional cleanup, not a blocker.
- Dependencies (jjwt 0.11.5, commons-dbcp2, Jackson 2.17.1, OpenPDF 1.3.30, jbcrypt, json-simple, dnsjava, HikariCP) have no known JDK 21 problem, but OpenPDF (fonts) and the keystore code (`Legal.java`) are the areas most likely to differ at runtime, so they get explicit tests.
- Jetty comes from the base image, not from `pom.xml`. The `Dockerfile` enables `ee10-deploy`; the pom declares servlet API 5.0.0 while ee10 is Servlet 6. This works today and is not part of this change.

**PostgreSQL 17**
- `pgcrypto` ships with the standard images, and the init scripts use only plain SQL, so no incompatibility is expected from 15 to 17. This is confirmed by running every `db/*.sql` on an empty 17 volume.
- JDBC 42.7.3 predates PostgreSQL 17. Move to the latest 42.7.x patch and test, rather than assume.
- **A PostgreSQL 15 data directory cannot be opened by a 17 server.** Changing the image tag on an existing `postgres_data` volume makes the container refuse to start. Existing deployments must dump and restore (section 5). This is the main risk of the whole change.
- Keep the **alpine** variant. Switching to the Debian image changes the `postgres` user id (70 to 999), which breaks the certificate ownership steps in the production guide, and changes libc and collation behaviour.

## 3. Scope

**In scope**
- `Dockerfile` on a pinned JDK 21 Jetty image.
- `docker-compose.yml` on PostgreSQL 17, with the image configurable through `.env`.
- `pom.xml`: compile settings, JDBC driver patch bump.
- `backup/restore.sh` default image, production guide helper command, local development guide prerequisites.
- Upgrade procedure for existing PostgreSQL 15 deployments.
- Full regression run on the new stack, release notes.

**Out of scope**
- Moving the compile target to 21 (decision 1).
- Jetty or servlet API version changes beyond what the new base image brings.
- Replacing `finalize()` in the CSV classes.
- Managed or external PostgreSQL: the production guide already says 13 or later; only the tested range is updated.
- Non-Docker (Path B) installs beyond updating the stated supported versions.

## 4. Changes

### 4.1 Java 21 (app image)
1. `Dockerfile`: replace `FROM jetty:jdk17` with a pinned tag such as `jetty:12.0-jdk21` (exact tag to be confirmed against Docker Hub and the Jetty version the current image resolves to). Pin a version rather than a floating tag so rebuilds are reproducible and a Jetty minor change does not slip in unnoticed. Update the comment on line 1.
2. `pom.xml`: replace `maven.compiler.source/target` 15 with `maven.compiler.release` (decision 1). The compiler plugin 3.11.0 already supports `release` and JDK 21, so no plugin change is needed.
3. Optional runtime flag: container-aware memory sizing (`-XX:MaxRAMPercentage`) via `JAVA_OPTIONS`, only if the memory test in section 6 shows a need.
4. Re-verify the earlier security fixes on the new base image. `docs/security-fixes/2.md` documents behaviour that comes from Jetty's bundled `webdefault-ee10.xml` (directory listing on `/console/setup/`), so the check must be repeated on the new image.

### 4.2 PostgreSQL 17 (compose)
1. `docker-compose.yml`: `image: "${POSTGRES_IMAGE:-postgres:17-alpine}"`. The variable name matches the one `backup/restore.sh` already uses, so one setting controls both. Existing deployments can pin `POSTGRES_IMAGE=postgres:15-alpine` in `.env` to stay put.
2. `backup/restore.sh:32`: default to `postgres:17-alpine`; the verification container should match the live image.
3. `docs/guides/production-deployment-guide.md` step 2b: update the `postgres:15-alpine` helper command. The `70:70` ownership stays correct because we keep alpine.
4. `pom.xml`: bump `postgresql.version` to the latest 42.7.x.
5. `.env` example and `production.env`: add a commented `POSTGRES_IMAGE` line with a note about the upgrade procedure.

### 4.3 Docs
- `local-development-guide.md`: JDK "17 to 21 (21 recommended)", PostgreSQL "15 to 17", Docker path uses the compose defaults.
- `README.md` and the production guide: state the tested versions in one place.
- `RELEASE_NOTES.md`: one line per change, plus a prominent upgrade warning (see 5).

## 5. Upgrade path for existing deployments

Fresh installs need nothing: the init scripts run on an empty volume and `03z_enc_key.sh` sets `app.enc_key` from `DB_ENCRYPTION_KEY`.

**Existing PostgreSQL 15 deployments must not just pull the new compose file.** The 17 container would refuse to start on the old volume. This fails safe (no data is damaged), but it stops the service. Steps, using the scripts already in the repo:

1. `./backup/backup.sh`, and confirm the dump file exists.
2. `docker compose down`. Keep the old `postgres_data` volume; do not delete it.
3. Take the new compose file and `.env`, and bring up an **empty** new volume (rename the old volume or use a new project/volume name) so PostgreSQL 17 initialises from `db/`.
4. `./backup/restore.sh` the dump into the new database. It already re-applies `app.enc_key` from `DB_ENCRYPTION_KEY`, which `pg_dump` does not carry.
5. Start the app, run the smoke checks in section 6.
6. Keep the old volume for a rollback window (suggest 14 days, the existing `RETENTION_DAYS`), then remove it.

**Rollback:** restore the old compose file and `.env` pin, and start the old volume with `postgres:15-alpine`. Data written on 17 after the cut-over is not carried back; a 17 dump may not restore into 15.

**Staying on 15:** set `POSTGRES_IMAGE=postgres:15-alpine` in `.env`. Fully supported until the next review.

The app image (JDK 21) has no data impact and can be updated on its own at any time by pulling the new image.

## 6. Testing

Run on the new default stack (JDK 21 + PG 17), and repeat the essentials on JDK 21 + PG 15 (the pinned-existing case):

1. **Fresh install:** empty volume, all `db/*.sql` run without errors, `app.enc_key` is set, the setup page completes.
2. **Full regression:** the existing regression suite (`tests/regression-test-cases.md`).
3. **Java-sensitive paths:**
   - PDF generation (legal evidence certificate, ROPA PDF), including fonts, in the container.
   - Keystore load and certificate signing in `Legal.java`, with a keystore created by the older and by the JDK 21 `keytool`.
   - JWT login and password hashing.
   - Webhook delivery and retry (HTTP client, DNS lookup, SSRF checks).
   - Scheduled jobs (CES batch, purge).
4. **Database-sensitive paths:** PII encryption and decryption (`pgcrypto`), reports and CSV exports, audit ledger, anything using `uuid_generate_v4()`.
5. **Production profile:** `TSI_DPDP_CMS_ENV=production` with the SSL-enabled bundled Postgres, `sslmode=require`, certificate ownership as in the production guide.
6. **Upgrade drill:** take a populated 15 deployment, follow section 5, compare row counts and decrypt a PII column; then a rollback drill.
7. **Backup and restore:** `backup.sh` then `restore.sh` on the 17 stack, including the verification-container path.
8. **Security re-check:** the findings in `docs/security-fixes/` still hold on the new base image (directory listing, console auth gate).
9. **Resource check:** memory and startup time before and after, to decide on 4.1 item 3.

## 7. Risks

| Risk | Mitigation |
|---|---|
| Existing deployment pulls the new compose file and the database does not start | Fails safe. Loud release note, `.env` pin for 15, tested upgrade steps (section 5). |
| Dump taken from 17 cannot be restored into 15 on rollback | Keep the old volume and the pre-upgrade dump through the rollback window. |
| Floating or wrong Jetty tag changes the Jetty version | Pin the tag; record the resolved Jetty version in the release notes. |
| OpenPDF font or rendering differences on the new image | Explicit PDF test (section 6, item 3). |
| JDBC driver behaviour with PG 17 | Bump to latest 42.7.x; full regression. |
| Keystore compatibility between `keytool` versions | Test both directions (section 6, item 3). |
| Security-fix regressions from a different Jetty base | Re-run the security checks (section 6, item 8). |

## 8. Open decisions

1. **Compile target.** Options: `release=17` (matches the documented JDK 17 minimum; Docker runs 21; Path B users on 17 keep working) or `release=21` (drops 17). Recommended: **17 now**, move to 21 in a later release once Path B users are on 21. Today the pom says 15 while the docs say 17, so this also removes that inconsistency.
2. **Compose default for existing users.** Option A, default `postgres:17-alpine` with a pin variable (recommended: new installs get 17; existing users read the release note and pin or migrate). Option B, keep 15 as the default and make 17 opt-in (safest for upgrades, but new installs stay on 15).
3. **Supported matrix to document.** Proposed: Docker default JDK 21 and PG 17; also tested JDK 17 and PG 15. Anything else best effort.
4. **Pin the Jetty tag exactly** (for example 12.0.x-jdk21) or use the minor-version tag (`12.0-jdk21`). Recommended: the minor-version tag, so patch security fixes arrive on rebuild.
5. **`finalize()` cleanup** in the CSV classes now or later. Recommended: later.

## 9. Delivery plan

| Step | Work | Size |
|---|---|---|
| 1 | Dockerfile, pom, compose, restore script defaults, JDBC bump | S |
| 2 | Test pass (section 6), fixes found | M |
| 3 | Upgrade and rollback drill, backup and restore check | S |
| 4 | Docs, `.env` examples, release notes | S |

Step 2 is where the effort is. Do not publish the new `tsicoop/tsi-dpdp-cms` image tag until steps 2 and 3 pass.
