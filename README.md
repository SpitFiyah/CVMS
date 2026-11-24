# CVE Vulnerability Management System

CVMS is an academic Oracle 11g XE project for connecting public disclosures to the inventory and remediation work of a fictional organization. Python archives and stages source data, while Oracle owns the relational model, publication, business procedures, audit history and reports.

## Offline demonstration

1. Connect SQL*Plus to an empty, dedicated Oracle 11.2 XE development schema. Run `@sql/install_schema.sql`, then `@sql/03_seed_data/01_seed_source.sql`.
2. Run `python3 -m etl.normalizer data/processed/demo --snapshot data/samples/nvd-one-record.json`. The output directory must be new.
3. Export the Oracle settings in [.env.example](.env.example). Install a Python `oracledb` release compatible with your interpreter and compatible 64-bit Oracle Client libraries on the host. The loader uses Thick mode with the system library search path.
4. Run `python3 -m etl.importer data/processed/demo`. Importing the same snapshot again should report one accepted row and zero applied rows.
5. Run `@sql/03_seed_data/02_seed_fictional_demo.sql`. On the fresh demo schema this creates eight fictional assets, three analysts, two installations, two reviewed findings and two assigned tasks. Run the scripts in `sql/05_queries/` to inspect results. The referenced CVE is HIGH under CVSS 2.0, so critical reports are empty for this sample.
6. Run `@scripts/validate_database.sql` in a dedicated test session. The script rolls back its test rows. Run Python tests with `python3 -m unittest discover -s tests -v`.

## Live collection

Run `python3 -m etl.normalizer data/processed/live --max-records 30` in a terminal with NVD connectivity. Optional filters include `--cve-id` and `--cpe-name`. The client uses `NVD_API_KEY` when set. Keep the original batch paths available as audit evidence and run the importer against the staged batch.

Run `python3 -m etl.cpe_dictionary data/processed/cpe-check 'cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*'` to reconcile an inventory CPE against the official dictionary. The report lists exact dictionary entries and deprecation flags, indicates capped or changing result sets, and links checksummed raw pages. Dictionary identity supports inventory review. Applicability still depends on the corresponding CVE configuration.

See the [architecture](ARCHITECTURE.md), [Mermaid ER diagram](docs/er-diagram.md), [relational schema](docs/relational-schema.md), [database workflow](docs/database-workflow.md) and [test report](docs/test-report.md). See [project status](PROJECT_STATUS.md) for verified progress and outstanding work.
