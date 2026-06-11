# TSI DPDP Consent Management System

An open-source consent management system compliant with India's DPDP Act, 2023.

## Introduction

[Launch Note](https://techadvisory.substack.com/p/tsi-dpdp-cms-an-open-source-consent)

[The Big Picture - Video](https://youtu.be/caQFjwrZj9w)

[System Design](https://github.com/tsi-coop/tsi-dpdp-cms/blob/296d41274d0bf449de295e89c1cf3c92a7f81259/docs/design/TSI%20DPDP%20Consent%20Management%20System%20-%20System%20Design5.pdf)

[Functional Overview - Video](https://youtu.be/d85ye4BoFbM)

[ROPA Definition & Reporting - Video](https://youtu.be/7XGQIDDAw28)

[User Rights Management - Video](https://youtu.be/_bdVqDmtWEI)

[Managing the Data Lifecycle](https://techadvisory.substack.com/p/managing-the-data-lifecycle-a-first)

[Consent Enforcement Service - Video](https://youtu.be/_i9znxthbOA)

[DPO Console - Video](https://youtu.be/QPXHg4bQhf8)

[Solving Consent Fatigue via Portable Consent Artifacts (PCA) - A Proposal](https://techadvisory.substack.com/p/dpdpa-solving-consent-fatigue-via)

[DPDP Wallet Demonstration - Video](https://youtu.be/1N4TYXfamsw)

[Verifiable Parent Consent - Video](https://youtu.be/kz4idKMBLXk)

[Standardized Erasure Interface for DPDP Consent Managers - A Proposal](https://techadvisory.substack.com/p/the-need-for-standardized-erasure)

[Securing Court-Ready Evidence under BSA Section 62](https://techadvisory.substack.com/p/dpdp-consent-manager-securing-court)

[DPDP Inclusion: Interactive Voice Consent using Sarvam AI](https://techadvisory.substack.com/p/dpdp-inclusion-voice-consent-gateway)

[Partner White Labeling - Video](https://youtu.be/DyU4GI_3-DY)

## Release Notes

See [RELEASE_NOTES.md](RELEASE_NOTES.md) for the full version history.

## Installation

### Docker

1.  **Clone the repository to a separate folder**
    ```bash
    git clone https://github.com/tsi-coop/tsi-dpdp-cms.git tsi-dpdp-cms-eval
    ```
2.  **Start the TSI DPDP CMS service**
    ```bash
    cd tsi-dpdp-cms-eval
    sudo docker compose up -d
    ```

### Binary

Check out [v0.4.7 release](https://github.com/tsi-coop/tsi-dpdp-cms/releases/tag/v0.4.7)

## Post-Installation Steps

The system includes a pre-configured interactive tour designed for evaluators and administrators.

**Access the Tour**: Open your browser and navigate to:
http://localhost:8080/tour

Follow the Guided Journey:

1. System Setup: Initialize your environment and configure master admin credentials.

2. Org Configuration: Onboard your Fiduciaries, link Apps, and publish Multilingual Data Policies.

3. ROPA Definition and Reporting: Define Records of Processing Activities for every data processing purpose, validate DPO accountability fields, and generate compliance reports. 

4. User Rights Management: Notice & capture, purpose-limited verification, and exercise of rights: view artifacts, withdraw, and grievances.

5. Consent Verifier: Test real-time API validation used by Data Processors to ensure purpose-limited processing.

6. Enforcement Logic: View the visual logic for technical data deletion, retention periods, and audit trail integrity.

7. DPO Console Tour: Comprehensive video walkthrough of the administrative console for managing compliance workflows.

8. System Integration: API specifications for Data Fiduciaries and Processors to integrate CMS logic into backend technical stacks.

9. Verifiable Parental Consent: Experience the Section 9 workflow: verifiable parental consent with OTP-based guardian identification for learners under 18.

10. DPDP Wallet Demo: Experience portable privacy. Checkout the [DPDP Wallet](https://techadvisory.substack.com/p/dpdpa-solving-consent-fatigue-via) concept, then download your PCA from the User Dashboard to manage your processing rights independently.

11. Password Recovery: Explore the "break-glass" account recovery mechanism using secure Master Recovery Keys.

12. Legal Module: Explore the crystallization of immutable audit trails into cryptographically signed, BSA Section 62-compliant digital evidence artifacts for court and regulatory submission.

13. Voice Consent Gateway: Experience hands-free, granular consent collection using Sarvam AI (TTS/STT) to obtain informed voice affirmations for processing purposes.

14. Partner White Labeling: See how the `BRAND_NAME` environment variable rebrands the console, rights portal, tour, and report footers for partner deployments.

## Implementation Guide

[TSI DPDP CMS Implementation Guide](docs/implementation-guide.md) - end-to-end walkthrough covering data discovery, RoPA authoring, JSON schema compilation, DPIA, and production deployment.

## Developers

### Prerequisites

Before you begin, ensure you have the following software installed on your development machine or server:

* **Java Development Kit (JDK) 17 or higher**: Required to build and run the Java application.
    * **Installation Steps:**
        * **Linux (Ubuntu/Debian):**
            ```bash
            sudo apt update
            sudo apt install openjdk-17-jdk
            ```
        * **Windows:** Download the JDK 17 installer from Oracle (requires account) or Adoptium (Eclipse Temurin, recommended open-source distribution) and follow the installation wizard. Ensure `JAVA_HOME` environment variable is set and `%JAVA_HOME%\bin` is in your system's `Path`.
    * **Verification:**
        ```bash
        java -version
        javac -version
        ```

* **Apache Maven 3.6.0 or higher**: Project build automation tool.
    * **Installation Steps:**
        * **Linux (Ubuntu/Debian):**
            ```bash
            sudo apt install maven
            ```
        * **Windows:** Download the Maven binary zip from the Apache Maven website, extract it, and add the `bin` directory to your system's `Path` environment variable.
    * **Verification:**
        ```bash
        mvn -v
        ```

* **Docker Desktop (For Docker based development)**: Essential for containerizing and running the application and database locally.
    * **Installation Steps:**
        * **Windows:** Download and install Docker Desktop from the [official Docker website](https://www.docker.com/products/docker-desktop/).
        * **Linux:** Follow the official Docker Engine installation guide for your specific distribution (e.g., [Docker Docs](https://docs.docker.com/engine/install/)). Install Docker Compose separately if using Docker Engine.
    * **Configuration & Verification (Windows Specific):**
        * Ensure **WSL 2** is enabled and configured. Open PowerShell as Administrator and run `wsl --install` or `wsl --update`.
        * Verify **virtualization (Intel VT-x / AMD-V)** is enabled in your computer's BIOS/UEFI settings.
        * Start Docker Desktop and wait for the whale icon in the system tray to turn solid.
    * **Verification:**
        ```bash
        docker --version
        docker compose version # Or docker compose --version for older installations
        ```

* **Git**: For cloning the repository.
    * **Installation Steps:**
        * **Linux (Ubuntu/Debian):**
            ```bash
            sudo apt install git
            ```
        * **Windows:** Download the Git for Windows installer from [git-scm.com](https://git-scm.com/download/win) and follow the installation wizard.
    * **Verification:**
        ```bash
        git --version
        ```

* **Jetty (For Non Docker Development)**:Navigate to the Eclipse Jetty Downloads page.

    * Download the Jetty 11 (Standard) distribution (e.g., jetty-home-11.x.x.tar.gz or .zip).

    * Extract the archive to a permanent directory:

        Linux/macOS: /opt/jetty-home

        Windows: C:\jetty-home

### Build 

#### Using Docker

Follow these steps to get the TSI DPDP CMS solution running on your local machine using Docker Compose:

1.  **Change Docker to Dev mode:**

    To build from local source, uncomment the block below in docker-compose.yml
    ```bash
    build:
      context: .
      dockerfile: Dockerfile
    ```

2.  **Clone the Repository:**
    ```bash
    git clone https://github.com/tsi-coop/tsi-dpdp-cms.git
    cd tsi-dpdp-cms
    ```

3.  **Create `.env` File:**
    This file stores sensitive configurations (passwords, API keys, etc.) and is **NOT** committed to Git.
    ```bash
    cp .example .env
    ```
    Now, **edit the newly created `.env` file** and fill in the placeholder values.

4.  **Build the Java WAR File:**
    Navigate to the project root and build your Java application.
    ```bash
    mvn clean package
    ```
    This will create `target/tsi_dpdp_cms.war`

5.  **Initialize PostgreSQL Database Schema:**
    The `postgres` Docker image only runs initialization scripts on its *first* startup when the data directory is empty. To ensure your schema is loaded:
    ```bash
    docker compose down -v 
    ```

6.  **Build and Start Docker Services:**
    This command will build your application's Docker image and start both the PostgreSQL database and the Jetty application.
    ```bash
    docker compose up --build -d
    ```
    * `--build`: Ensures Docker images are rebuilt, picking up any changes in your Java code or Dockerfile.
    * `-d`: Runs the containers in detached mode (in the background).

7.  **Verify Services and Check Logs:**
    * Check if containers are running: `docker ps`
    * Monitor PostgreSQL logs for schema initialization: `docker compose logs -f postgres_db`
    * Monitor Jetty application logs for successful deployment: `docker compose logs -f jetty_app`

#### Using Scripts (without docker)

These steps describe how to install and run the TSI DPDP CMS solution directly on a Linux/Windows server without using Docker.

1.   **Clone the Repository:**
     ```bash
     git clone https://github.com/tsi-coop/tsi-dpdp-cms.git
     cd tsi-dpdp-cms
     ```

2.  **PostgreSQL Database Setup:**
    * Log in as the PostgreSQL superuser (e.g., `postgres` user on Linux).
    ```bash
    sudo -i -u postgres psql
    ```
    * Create the database and user:
    ```sql
    CREATE DATABASE <<your-db-name-here>>;
    CREATE USER <<your-db-user-here>> WITH ENCRYPTED PASSWORD '<<your_db_password_here>>';
    ```
    * Connect to the new database and grant permissions: (Note: These steps are required for PostgreSQL 15+ compatibility)
    ```sql
    \c <<your-db-name-here>>
    ALTER SCHEMA public OWNER TO <<your-db-user-here>>;
    GRANT ALL PRIVILEGES ON SCHEMA public TO <<your-db-user-here>>;
    GRANT ALL PRIVILEGES ON DATABASE <<your-db-name-here>> TO <<your-db-user-here>>;
    ```
    * Exit the postgres user: `exit`
    * **Initialize Schema:** Execute the `db/init.sql` script to create the necessary tables.
    ```bash
    psql -U <<your-db-user-here>> -d <<your-db-name-here>> -h localhost -f /path/to/tsi-dpdp-cms/db/init.sql
    ```

3.  **Build WAR:**
    ```bash
    cd /path/to/tsi-dpdp-cms
    mvn clean package
    ```
    This will generate `target/tsi-dpdp-cms.war`.

4.  **Deploy Solution (linux):**
    ```bash
    cd /path/to/tsi-dpdp-cms/server
    cp .example .env
    ```
    Now, **edit the newly created `.env` file** and fill in the placeholder values.

    ```bash
    ./set-base.sh #Sets the jetty base directory
    ./serve.sh # Copies the target/tsi-dpdp-cms.war to $JETTY_BASE/webapps/ROOT.war. Starts the server in 8080
    ```
5. **Deploy Solution (windows):**
   ```bash
   cd /path/to/tsi-dpdp-cms/server
   copy .example .env
   ```
   Now, **edit the newly created `.env` file** and fill in the placeholder values.

   ```bash
   set-base.bat #Sets the jetty base directory
   serve.bat # Copies the target/tsi_dpdp_cms.war to %JETTY_BASE%/webapps/ROOT.war. Starts the server in 8080
   ```
6. **Validation Step:**
   To confirm server status.
   ```bash
   curl -I http://localhost:8080
   ```

## Production Deployment

The steps above get you running for evaluation. A production instance holds real personal data - DPDP-regulated PII, consent records, and the immutable audit/compliance ledger - so it needs additional hardening before go-live. The five guardrails below apply whether you deploy via Docker or as a binary; each is shown for both.

### Docker

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

### Binary

The same five guardrails, mapped onto the bare-metal Jetty deployment described above:

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

### White-Labeling for Partners & Resellers

Partners and resellers can rebrand the entire UI - console, login screens, the data-principal rights portal, the evaluator tour, and report footers - with a single environment variable:

```bash
BRAND_NAME=Acme Privacy
```

`BRAND_NAME` is capped at **12 characters**, the exact length of the default brand "TSI DPDP CMS". The cap is intentional: it guarantees any compliant partner name is a drop-in replacement that fits every layout (sidebar widths, title bars, report footers) without redesign or risk of overflow. If `BRAND_NAME` is set but exceeds the limit, the application refuses to start with a clear error - the same fail-fast behavior as `JWT_SECRET` and `DB_ENCRYPTION_KEY`. Leave it unset to keep the default branding; nothing else changes.


## License & Contributions

This project is fully open-source and distributed under the **Apache 2.0 License**. You are completely free to fork, modify, and customize the codebase to fit your specific technical or enterprise needs without any restriction.

### Contributing Back to the Main Project
If you have built an optimization, bug fix, or feature extension that you believe would add value to the core platform, we would love to review it. To ensure the main repository remains highly stable and securely managed, direct commits to the `main` branch are restricted.

If you wish to give back your changes to the project, please follow this process:

* **Email the Repository Owner:** Send a brief summary of your modifications and a link to your code branch directly to **admin@tsicoop.org**.

Every contribution is manually evaluated for architectural alignment, readability, and long-term maintenance impact before integration. Thank you for respecting this workflow and helping us maintain a clean, resilient core!

