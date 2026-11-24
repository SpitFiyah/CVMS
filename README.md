# CVE Vulnerability Management System

CVMS is an academic Oracle 11g XE project for connecting public disclosures to the inventory and remediation work of a fictional organization. Python archives and stages source data, while Oracle owns the relational model, publication, business procedures, audit history and reports.

## Local Oracle with Docker

From the project root, copy the example configuration once and fill in both passwords in `.env`. Then start Oracle 11g XE using Docker Compose.

```bash
cp -n .env.example .env
${EDITOR:-nano} .env
docker compose up -d --wait
docker compose exec oracle sqlplus -L 'cvms_dev@//localhost:1521/XE'
```

Use the development schema password from `ORACLE_PASSWORD` when SQL*Plus prompts. If you changed `ORACLE_USER`, use that username in the login command. At the `SQL>` prompt on the fresh schema, run:

```sql
@sql/install_schema.sql
@sql/03_seed_data/01_seed_source.sql
@scripts/validate_database.sql
```

The Compose service uses the Linux x86-64 Oracle XE image. It mounts the SQL scripts read-only and publishes Oracle on localhost. `docker compose down` stops the service and preserves the named database volume. The image creates the user and initializes passwords on the first start of an empty volume. [Oracle XE container documentation](https://hub.docker.com/r/gvenzl/oracle-xe/)

## Offline demonstration

1. If you skipped Docker setup, connect SQL*Plus to an empty, dedicated Oracle 11.2 XE development schema and run `@sql/install_schema.sql`, then `@sql/03_seed_data/01_seed_source.sql`.
2. Run `python3 -m etl.normalizer data/processed/demo --snapshot data/samples/nvd-five-records.json`. The output directory must be new.
3. Export `ORACLE_USER`, `ORACLE_PASSWORD` and `ORACLE_DSN` in the host terminal. Use the same values as in your local `.env` when using Compose. Install a Python `oracledb` release compatible with your interpreter and compatible 64-bit Oracle Client libraries on the host. The loader uses Thick mode with the system library search path.
4. Run `python3 -m etl.importer data/processed/demo`. Importing the same snapshot again should report five accepted rows and zero applied rows.
5. Run `@sql/03_seed_data/02_seed_fictional_demo.sql`. On the fresh demo schema this creates eight fictional assets, three analysts, two installations, two reviewed findings and two assigned tasks. Run the scripts in `sql/05_queries/` to inspect results. The seeded findings refer to a HIGH CVE under CVSS 2.0.
6. Run `@scripts/validate_database.sql` in a dedicated test session. The script rolls back its test rows. Run Python tests with `python3 -m unittest discover -s tests -v`.

## Live collection

Run `python3 -m etl.normalizer data/processed/live --max-records 30` in a terminal with NVD connectivity. Optional filters include `--cve-id` and `--cpe-name`. The client uses `NVD_API_KEY` when set. Keep the original batch paths available as audit evidence and run the importer against the staged batch.

Run `python3 -m etl.cpe_dictionary data/processed/cpe-check 'cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*'` to reconcile an inventory CPE against the official dictionary. The report lists exact dictionary entries and deprecation flags, indicates capped or changing result sets, and links checksummed raw pages. Dictionary identity supports inventory review. Applicability still depends on the corresponding CVE configuration.

See the [architecture](ARCHITECTURE.md), [Mermaid ER diagram](docs/er-diagram.md), [relational schema](docs/relational-schema.md), [database workflow](docs/database-workflow.md) and [test report](docs/test-report.md). See [project status](PROJECT_STATUS.md) for verified progress and outstanding work.
