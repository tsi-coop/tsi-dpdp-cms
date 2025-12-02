# TSI DPDP Consent Management System

An open-source consent management system compliant with India's DPDP Act, 2023

Note: The solution is currently under preview stage. We encourage developers to use this solution for their sandbox testing and drop us an email if there are any questions.

## User Guide

[System Design](https://github.com/tsi-coop/tsi-dpdp-cms/blob/5379e96519caed23a14763c29d6f004907d8c8be/docs/design/TSI%20DPDP%20Consent%20Management%20System%20-%20System%20Design.pdf)

## Prerequisites

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

* **Docker Desktop (or Docker Engine + Docker Compose)**: Essential for containerizing and running the application and database locally.
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
        docker compose version # Or docker-compose --version for older installations
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

## Installation Steps (Docker)

Follow these steps to get the TSI Aadhaar Vault Plus solution running on your local machine using Docker Compose:

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/tsi-coop/tsi-dpdp-cms.git
    cd tsi-dpdp-cms
    ```

2.  **Create `.env` File:**
    This file stores sensitive configurations (passwords, API keys, etc.) and is **NOT** committed to Git.
    ```bash
    cp .example .env
    ```
    Now, **edit the newly created `.env` file** and fill in the placeholder values.

3.  **Build the Java WAR File:**
    Navigate to the project root and build your Java application.
    ```bash
    mvn clean package
    ```
    This will create `target/tsi_dpdp_cms.war`

4.  **Initialize PostgreSQL Database Schema:**
    The `postgres` Docker image only runs initialization scripts on its *first* startup when the data directory is empty. To ensure your schema is loaded:
    ```bash
    docker-compose down -v 
    ```

5.  **Build and Start Docker Services:**
    This command will build your application's Docker image and start both the PostgreSQL database and the Jetty application.
    ```bash
    docker-compose up --build -d
    ```
    * `--build`: Ensures Docker images are rebuilt, picking up any changes in your Java code or Dockerfile.
    * `-d`: Runs the containers in detached mode (in the background).

6.  **Verify Services and Check Logs:**
    * Check if containers are running: `docker ps`
    * Monitor PostgreSQL logs for schema initialization: `docker-compose logs -f postgres_db`
    * Monitor Jetty application logs for successful deployment: `docker-compose logs -f jetty_app`

## Installation Steps (without Docker)

These steps describe how to install and run the TSI Aadhaar Vault Plus solution directly on a Linux/Windows server without using Docker.

1.   **Clone the Repository:**
     ```bash
     git clone https://github.com/tsi-coop/tsi-dpdp-cms.git
     cd tsi-aadhaar-vault-plus
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
    GRANT ALL PRIVILEGES ON DATABASE <<your-db-name-here>> TO <<your-db-user-here>>;
    ```
    * Exit the postgres user: `exit`
    * **Initialize Schema:** Execute the `db/init.sql` script to create the necessary tables.
    ```bash
    psql -U <<your-db-user-here>> -d <<your-db-name-here>> -h localhost -f /path/to/tsi-aadhaar-vault-plus/db/init.sql
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
    ./serve.sh # Copies the target/tsi-dpdp-cms.war to %JETTY_BASE%/webapps/ROOT.war. Starts the server in 8080
    ```
5. **Deploy Solution (windows):**
   ```bash
   cd /path/to/tsi-dpdp-cms/server
   copy .example .env
   ```
   Now, **edit the newly created `.env` file** and fill in the placeholder values.

   ```bash
   set-base.bat #Sets the jetty base directory
   serve.bat # Copies the target/tsi_aadhaar_vault_plus.war to %JETTY_BASE%/webapps/ROOT.wat. Starts the server in 8080
   ```


