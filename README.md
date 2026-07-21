# TSI DPDP Consent Management System

An open-source consent management system compliant with India's DPDP Act, 2023.

This system serves two categories of adopters:

- **Data Fiduciaries**, who can deploy the CMS directly (Single Mode) to manage consent for their own Data Principals, without depending on a third party.
- **Consent Managers and Consent Aggregators**, who can deploy the CMS (Aggregator Mode) to manage consent on behalf of one or more Data Fiduciaries as a managed service.

See Section 1.2 (Configure Consent Manager) of the System Design document, linked below, for details on both deployment modes.

## Introduction

[Launch Note](https://techadvisory.substack.com/p/tsi-dpdp-cms-an-open-source-consent)

[The Big Picture - Video](https://youtu.be/caQFjwrZj9w)

[System Design](https://github.com/tsi-coop/tsi-dpdp-cms/blob/main/docs/design/TSI%20DPDP%20Consent%20Management%20System%20-%20System%20Design5.pdf)

### Future Forward Proposals

[Solving Consent Fatigue via Portable Consent Artifacts (PCA) - A Proposal](https://techadvisory.substack.com/p/dpdpa-solving-consent-fatigue-via)

[Standardized Erasure Interface for DPDP Consent Managers - A Proposal](https://techadvisory.substack.com/p/the-need-for-standardized-erasure)


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

Check out [v0.4.9 release](https://github.com/tsi-coop/tsi-dpdp-cms/releases/tag/v0.4.9)

## Post-Installation Steps

The system includes a pre-configured interactive tour designed for evaluators and administrators.

**Access the Tour**: Open your browser and navigate to:
http://localhost:8080/tour

Follow the Guided Journey:

1. System Setup: Initialize your environment and configure master admin credentials.

2. Fiduciary Provisioning: Onboard your Fiduciaries, link Apps, and publish Multilingual Data Policies. [Watch Video](https://youtu.be/216gZPlokuM)

3. ROPA Definition and Policy Creation: Define Records of Processing Activities for every data processing purpose, validate DPO accountability fields, and generate compliance reports. [Watch Video](https://youtu.be/O_yhxu2o4Mc)

4. User Rights Management: Notice & capture, purpose-limited verification, and exercise of rights: view artifacts, withdraw, and grievances. [Watch Video](https://youtu.be/nlthzXlBc1M)

5. Consent Verifier: Test real-time API validation used by Data Processors to ensure purpose-limited processing.

6. Enforcement Logic: View the visual logic for technical data deletion, retention periods, and audit trail integrity. [Managing the Data Lifecycle](https://techadvisory.substack.com/p/managing-the-data-lifecycle-a-first)

7. Compliance Management: Comprehensive video walkthrough of the administrative console for managing compliance workflows. [Watch Video](https://youtu.be/TE27zu859_s)

8. Grievance Management: Section 13: Review, assign, and resolve grievances raised by Data Principals within statutory timelines. [Watch Video](https://youtu.be/OGrfJgHgmJg)

9. Breach Notification: Section 8(6): Report a breach, notify affected Principals, generate the PDF record, and bulk-notify via CSV upload through the Job Manager. [Watch Video](https://youtu.be/lHOAQSIrxh8)

10. Legal Module: Explore the crystallization of immutable audit trails into cryptographically signed, BSA Section 62-compliant digital evidence artifacts for court and regulatory submission. [Watch Video](https://youtu.be/neS4x46erHA) | [Securing Court-Ready Evidence under BSA Section 62](https://techadvisory.substack.com/p/dpdp-consent-manager-securing-court)

11. System Integration: API specifications for Data Fiduciaries and Processors to integrate CMS logic into backend technical stacks. [Watch Video](https://youtu.be/P6kY9aBc_gM)

12. Verifiable Parental Consent: Experience the Section 9 workflow: verifiable parental consent with OTP-based guardian identification for learners under 18. [Watch Video](https://youtu.be/kz4idKMBLXk)

13. DPDP Wallet Demo: Experience portable privacy. Checkout the [DPDP Wallet](https://techadvisory.substack.com/p/dpdpa-solving-consent-fatigue-via) concept, then download your PCA from the User Dashboard to manage your processing rights independently. [Watch Video](https://youtu.be/1N4TYXfamsw)

14. Password Recovery: Explore the "break-glass" account recovery mechanism using secure Master Recovery Keys. [Watch Video](https://youtu.be/LYouy1cqiGE)

15. Voice Consent Gateway: Experience hands-free, granular consent collection using Sarvam AI (TTS/STT) to obtain informed voice affirmations for processing purposes. [Watch Video](https://youtu.be/d6WuPd0mr9U) | [DPDP Inclusion: Interactive Voice Consent using Sarvam AI](https://techadvisory.substack.com/p/dpdp-inclusion-voice-consent-gateway)

16. Partner White Labeling: See how the `BRAND_NAME` environment variable rebrands the console, rights portal, tour, and report footers for partner deployments. [Watch Video](https://youtu.be/DyU4GI_3-DY)

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

The steps above get you running for evaluation. A production instance holds real personal data - DPDP-regulated PII, consent records, and the immutable audit/compliance ledger - so it needs additional hardening before go-live.

See [Section 6: Infrastructure Hardening for Production](docs/implementation-guide.md#6-infrastructure-hardening-for-production) in the Implementation Guide for the five Docker and Binary deployment guardrails (secrets management, running as a non-root user, disk encryption, data-tier isolation, and offsite backups).

## White-Labeling for Partners & Resellers

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

