# CVE Vulnerability Management System

CVMS is an academic Oracle 11g XE project for connecting public disclosures to the inventory and remediation work of a fictional organization. Python archives and stages source data, while Oracle owns the relational model, publication, business procedures, audit history and reports.

## Quick start with Docker

You need Git, Python 3, and a running Docker Engine with Docker Compose v2. The Oracle 11g XE image used here targets Linux x86-64. The database container includes SQL*Plus, and the loader container includes the Python Oracle driver and client libraries.

### 1. Clone the repository and configure it

Run these commands in Bash:

```bash
git clone https://github.com/SpitFiyah/CVMS.git
cd CVMS
cp -i .env.example .env
nano .env
```

Set `CVMS_DB_ADMIN_PASSWORD` and `ORACLE_PASSWORD` to two different local passwords. For this walkthrough, use letters and digits with no spaces or quotes. Leave `ORACLE_USER=cvms_dev` and `ORACLE_DSN=127.0.0.1:1521/XE` as shown in the example. The application login uses `ORACLE_PASSWORD`. Git ignores `.env`.

### 2. Start Oracle

```bash
docker compose up -d --wait oracle
docker compose ps
```

Wait until Oracle is healthy. If Docker reports permission denied on `/var/run/docker.sock` and you normally administer Docker with `sudo`, prefix each `docker compose` command below with `sudo`.

### 3. Install the schema on the fresh database

Define this helper in the same Bash session. It uses the application's credentials inside the container and streams SQL to SQL*Plus.

```bash
cvms_sql() (
  set -o pipefail
  python3 scripts/expand_sql.py "$@" |
    docker compose exec -T oracle sh -ec '
      {
        printf "%s\n" "whenever sqlerror exit sql.sqlcode rollback" "set define off"
        printf "connect %s/\"%s\"@//127.0.0.1:1521/XE\n" "$APP_USER" "$APP_USER_PASSWORD"
        cat
        printf "\nexit success\n"
      } | sqlplus -s -L /nolog
    '
)

cvms_sql sql/install_schema.sql sql/03_seed_data/01_seed_source.sql
```

Run the installer once per empty schema. On later starts, rerun only `docker compose up -d --wait oracle` before opening SQL*Plus.

### 4. Load the bundled CVE sample

```bash
python3 -m etl.normalizer data/processed/demo --snapshot data/samples/nvd-five-records.json
docker compose run --rm --build loader data/processed/demo
```

On a fresh database the loader should report five retrieved, five accepted, zero rejected, and five applied. Repeat only the loader command to verify replay. It should report zero applied. The normalizer requires a new output directory.

If you also want the fictional inventory, analyst assignments, findings, and tasks, run the demo seed after the CVEs load. The validation script runs the SQL and PL/SQL assertions and rolls back its test rows.

```bash
cvms_sql sql/03_seed_data/02_seed_fictional_demo.sql
cvms_sql scripts/validate_database.sql
```

### 5. Open the SQL terminal and view the data

In Bash, run:

```bash
docker compose exec -e SQLPATH=/workspace/scripts oracle sqlplus /nolog
```

At the `SQL>` prompt, type the following command on its own line. When asked for a password, enter the exact value of `ORACLE_PASSWORD` from `.env`.

```sql
CONNECT cvms_dev
```

After you see `Connected.`, run:

```sql
SHOW USER
SELECT table_name FROM user_tables ORDER BY table_name;
SELECT COUNT(*) AS total_cves FROM vulnerability;

SELECT cve_id, cvss_score, severity
FROM vulnerability
ORDER BY cve_id;

SELECT run_id, accepted_count, rejected_count, applied_count
FROM import_run
ORDER BY run_id;
```

Use `DESC vulnerability` to inspect its columns. If the formatting profile did not load automatically, run `@/workspace/scripts/login.sql` at the `SQL>` prompt. Type `EXIT` to return to Bash. When you are finished, `docker compose down` stops Oracle and preserves the database in its named volume. [Oracle XE container documentation](https://hub.docker.com/r/gvenzl/oracle-xe/)

## Use an existing Oracle database

To use an existing Oracle 11.2 XE instance, connect SQL*Plus to a dedicated empty schema and run `@sql/install_schema.sql` and `@sql/03_seed_data/01_seed_source.sql` from the project root. For a host-side import, install the Python `oracledb` package and compatible 64-bit Oracle Client libraries. Export `ORACLE_USER`, `ORACLE_PASSWORD`, and `ORACLE_DSN`, and run `python3 -m etl.importer data/processed/demo` after preparing the batch. The importer uses Thick mode.

## Live collection

Run `python3 -m etl.normalizer data/processed/live --max-records 30` in a terminal with NVD connectivity. Optional filters include `--cve-id` and `--cpe-name`. The client uses `NVD_API_KEY` when set. Keep the original batch paths available as audit evidence and run the importer against the staged batch. For a Compose database, use `docker compose run --rm --build loader data/processed/live`. The loader image supplies Python and Oracle Instant Client. To reprocess previously archived pages, pass the batch’s `raw/` directory to `--snapshot`.

Run `python3 -m etl.cpe_dictionary data/processed/cpe-check 'cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*'` to reconcile an inventory CPE against the official dictionary. The report lists exact dictionary entries and deprecation flags, indicates capped or changing result sets, and links checksummed raw pages. Dictionary identity supports inventory review. Applicability still depends on the corresponding CVE configuration.

See the [architecture](ARCHITECTURE.md), [Mermaid ER diagram](docs/er-diagram.md), [relational schema](docs/relational-schema.md), [database workflow](docs/database-workflow.md) and [test report](docs/test-report.md). See [project status](PROJECT_STATUS.md) for verified progress and outstanding work.
