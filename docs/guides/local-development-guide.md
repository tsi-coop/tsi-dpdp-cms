# Local Development Guide

**Document Version:** 1.1
**Audience:** Developers building the TSI DPDP CMS from source, with or without Docker.

---

## What this guide gets you

A running copy of the TSI DPDP CMS built from your own source code, with a database and an admin account, on your own machine. You choose one of two paths:

- **[Path A: Docker](#path-a-docker)** (recommended): Docker runs the database and the application for you. About 15 minutes.
- **[Path B: Without Docker](#path-b-without-docker)**: you install PostgreSQL and Jetty yourself. About 45 minutes.

If you only want to try the system and do not need to change the code, the [README](../../README.md#installation) has a faster route: `docker compose up -d` with the prebuilt image.

Do the **checkpoint** at the end of each step before moving on. It tells you what you should see.

> **Using this for production?** This guide is for development. Use the [Production Deployment Guide](production-deployment-guide.md) for real data.

---

## Step 0: Install the tools

You need these on your machine. Skip any you already have, and check each with its command.

| Tool | Version | Check | Needed for |
|---|---|---|---|
| JDK | 17 or higher | `java -version` and `javac -version` | Both paths |
| Apache Maven | 3.6 or higher | `mvn -v` | Both paths |
| Git | any | `git --version` | Both paths |
| Docker and Docker Compose | recent | `docker --version` and `docker compose version` | Path A |
| PostgreSQL | 15 or higher | `psql --version` | Path B |
| Jetty | **12.x** (not 11) | see Path B, Step 2 | Path B |

**Installing on Ubuntu or Debian:**

```bash
sudo apt update
sudo apt install openjdk-17-jdk maven git
```

Docker: follow the [official install guide](https://docs.docker.com/engine/install/) for your distribution.

**Installing on Windows:**

- JDK 17: install Eclipse Temurin from [adoptium.net](https://adoptium.net) and make sure `JAVA_HOME` is set and `%JAVA_HOME%\bin` is on your `Path`.
- Maven: download the binary zip from the Apache Maven site, extract it, and add its `bin` folder to your `Path`.
- Git: [git-scm.com](https://git-scm.com/download/win).
- Docker Desktop: install it, make sure **WSL 2** is enabled (`wsl --install` in an administrator PowerShell) and virtualization is on in the BIOS, then start it and wait for the whale icon to stop animating.

> **Checkpoint:** every command in the "Check" column for your path prints a version number.

---

## Path A: Docker

### Step 1: Get the code

```bash
git clone https://github.com/tsi-coop/tsi-dpdp-cms.git
cd tsi-dpdp-cms
```

### Step 2: Create your `.env` file

The `.env` file holds passwords and keys. It is never committed to Git.

```bash
cp .example .env
```

Open `.env` in an editor and replace every `<...>` placeholder:

| Setting | What to put |
|---|---|
| `POSTGRES_DB` | `tsi_cms` |
| `POSTGRES_USER` | `tsi_admin` |
| `POSTGRES_PASSWD` | Any password (local use only) |
| `JWT_SECRET`, `DB_ENCRYPTION_KEY`, `TSI_LOOKUP_SALT`, `TSI_BOOTSTRAP_TOKEN` | A different random value for each. Generate one with `openssl rand -hex 32`, run once per setting. |

Leave `TSI_DPDP_CMS_ENV=local`. That turns on the relaxed development behaviour (no SSL needed for the database, demo OTP allowed).

> **Checkpoint:** `grep -c "<" .env` prints `0`, meaning no placeholders are left.

### Step 3: Build the application

```bash
mvn clean package
```

This takes a minute or two the first time. It ends with `BUILD SUCCESS` and creates `target/tsi_dpdp_cms.war`.

> **Checkpoint:** `ls -l target/tsi_dpdp_cms.war` shows the file.

### Step 4: Start everything

```bash
docker compose up --build -d
```

- `--build` makes Docker build an image from the WAR you just made.
- `-d` runs the containers in the background.
- On the very first start, the database creates its tables automatically from the scripts in `db/`.

Wait about 30 seconds.

> **Checkpoint:** `docker compose ps` shows two containers, `tsi_dpdp_cms_db` (healthy) and `tsi_dpdp_cms_server` (running).

### Step 5: Check the logs

```bash
docker compose logs jetty_app | grep "Service started"
```

> You should see something like `TSI DPDP CMS v0.6.0 Service started in local environment`.

If it does not appear, look at the end of the log with `docker compose logs --tail 40 jetty_app`. The error is usually a missing `.env` value from Step 2.

### Step 6: Create the admin account

1. Open <http://localhost:8080/console/setup/init.html>.
2. Enter your `TSI_BOOTSTRAP_TOKEN` value as the **Setup Token**.
3. Create your Super-Admin account, then sign in.

> **Checkpoint:** you are signed in to the console. You can also explore the guided tour at <http://localhost:8080/tour>.

### After you change code

Rebuild and restart:

```bash
mvn clean package
docker compose up --build -d
```

### Starting over with an empty database

The database tables are only created the first time the database starts. If you need a clean slate (for example, after a change to a script in `db/`):

```bash
docker compose down -v
docker compose up --build -d
```

> **Warning:** `-v` deletes the database volume. All data in it is lost. That is what you want in development, but never run it against data you care about.

---

## Path B: Without Docker

### Step 1: Get the code

```bash
git clone https://github.com/tsi-coop/tsi-dpdp-cms.git
cd tsi-dpdp-cms
```

### Step 2: Install Jetty 12

The application needs **Jetty 12** (the `ee10` environment). Jetty 11 will not work.

1. Download a Jetty 12 "jetty-home" archive (`jetty-home-12.x.x.tar.gz` or `.zip`) from the Eclipse Jetty downloads page.
2. Extract it somewhere permanent: `/opt/jetty-home` on Linux, `C:\jetty-home` on Windows.
3. Create an empty folder for Jetty's working files, for example `/opt/jetty-base` (`C:\jetty-base` on Windows). You will need both paths in Step 5.

### Step 3: Create the database

Open a PostgreSQL shell as the superuser:

```bash
sudo -i -u postgres psql
```

Run these, changing the names and password to your own:

```sql
CREATE DATABASE tsi_cms;
CREATE USER tsi_admin WITH ENCRYPTED PASSWORD 'choose-a-password';
\c tsi_cms
ALTER SCHEMA public OWNER TO tsi_admin;
GRANT ALL PRIVILEGES ON SCHEMA public TO tsi_admin;
GRANT ALL PRIVILEGES ON DATABASE tsi_cms TO tsi_admin;
```

(The `ALTER SCHEMA` and `GRANT` lines are required for PostgreSQL 15 and later.)

Next, give the database its encryption key. Generate one with `openssl rand -hex 32`, **save it** (you will put the same value in `.env` in Step 5), and run:

```sql
ALTER DATABASE tsi_cms SET app.enc_key = 'paste-your-key-here';
\q
```

The key must be set **before** the tables are created, because the schema scripts use it.

Now load the tables. The scripts in `db/` must run in order, which the `*.sql` pattern guarantees:

```bash
for f in db/*.sql; do
  psql -U tsi_admin -d tsi_cms -h localhost -v ON_ERROR_STOP=1 -q -f "$f" || break
done
```

(`db/03z_enc_key.sh` is skipped because you set the key by hand above. It exists for Docker only.)

> **Checkpoint:** this prints `24`:
>
> ```bash
> psql -U tsi_admin -d tsi_cms -h localhost -tAc "select count(*) from information_schema.tables where table_schema='public'"
> ```

### Step 4: Build the application

```bash
mvn clean package
```

> **Checkpoint:** `target/tsi_dpdp_cms.war` exists.

### Step 5: Configure the server

**Linux:**

```bash
cd server
cp .example .env
```

**Windows:**

```bat
cd server
copy .example .env
```

Open `server\.env` and fill in the values:

| Setting | What to put |
|---|---|
| `JAVA_HOME` | Your JDK 17 folder |
| `JETTY_HOME` | The folder from Step 2, e.g. `/opt/jetty-home` |
| `JETTY_BASE` | Your empty working folder, e.g. `/opt/jetty-base` |
| `POSTGRES_HOST` | `jdbc:postgresql://localhost:5432` (the example says `5433`; use the port your PostgreSQL really listens on) |
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWD` | The values from Step 3 |
| `DB_ENCRYPTION_KEY` | The **same** key you gave the database in Step 3 |
| `JWT_SECRET`, `TSI_LOOKUP_SALT`, `TSI_BOOTSTRAP_TOKEN` | A random value for each (`openssl rand -hex 32`) |
| `TSI_DPDP_CMS_HOME` | The project folder, e.g. `/home/you/tsi-dpdp-cms` |
| `TSI_EXPORT_PATH` | A folder the application can write to, e.g. `/var/lib/tsi/exports/` (create it first) |

Leave `TSI_DPDP_CMS_ENV=local`.

> **Checkpoint:** `grep -c "<" .env` prints `0`, and the `TSI_EXPORT_PATH` folder exists.

### Step 6: Start the server

**Linux:**

```bash
./set-base.sh     # one time: prepares the Jetty working folder
./serve.sh        # copies the WAR into place and starts Jetty on port 8080
```

**Windows:**

```bat
set-base.bat
serve.bat
```

Leave that window open: it is the running server.

> **Checkpoint:** in a second window, `curl -I http://localhost:8080` returns a response (a `200` or a redirect), and the first window shows `Service started in local environment`.

### Step 7: Create the admin account

Same as Docker Step 6: open <http://localhost:8080/console/setup/init.html>, enter your `TSI_BOOTSTRAP_TOKEN` as the Setup Token, and create the Super-Admin.

> **Checkpoint:** you are signed in to the console.

### After you change code

Stop the server (Ctrl+C), run `mvn clean package` in the project folder, then `./serve.sh` again. It copies the new WAR into place on every start.

---

## About the version number

The application version lives in one place: the `<version>` in `pom.xml`. The build copies it into `version.properties`, and the running application reads it to stamp the startup log, evidence certificates, breach reports and CSV exports. To cut a release, change `pom.xml` only and never hardcode a version elsewhere in the code.

## Common problems

| Problem | Likely cause and fix |
|---|---|
| Login fails or the setup page refuses the token (Path B) | A value is missing from `server/.env`, usually `JWT_SECRET` or `TSI_BOOTSTRAP_TOKEN`. Fill it in and restart. |
| `JWT_SECRET environment variable must be set` in the log | Same as above. |
| `no pg_hba.conf entry` or password errors | The database user or password in `.env` does not match what you created. |
| Encrypted fields fail or the scripts error on `app.enc_key` | The database key was not set before loading the tables (Path B, Step 3), or it differs from `DB_ENCRYPTION_KEY`. |
| Port 8080 or 5432 already in use | Something else is using it. Stop that program, or change `APP_PORT_MAP` / `DB_PORT_MAP` in `.env` (Docker). |
| Tables missing after changing a `db/` script (Docker) | Scripts only run on the first start. Use the "Starting over" steps above. |
