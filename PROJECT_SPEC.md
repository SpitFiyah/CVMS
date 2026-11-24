# Project specification

A team of two or three students will build a relational system that connects NVD CVE and CPE data to fictional assets, installed software, analyst assignments, remediation and audit history. Oracle 11g XE SQL and PL/SQL form the primary deliverable. Python will fetch, archive, parse and stage public records. SQL*Plus or SQL Developer will support installation and demonstrations.

## Expected outcomes

- Install in a dedicated development schema from documented scripts. Demonstrate constraints, sequences, indexes, joins, subqueries, aggregations, analytic functions, views, procedures and triggers.
- Import a small authentic dataset with repeatable current-state updates, source attribution and explicit rejections. Preserve missing CVSS as NULL and retain complete original applicability expressions.
- Seed fictional production and development assets, workstations, servers, installations and analysts. Distinguish potential, verified and refuted findings, and track resolution and accepted risk independently of verification.
- Demonstrate at least 20 reports, five required views, analyst assignment, task status changes, asset risk summaries and a transactional task status history. Preserve finding status when tasks complete.
- Execute Python and Oracle tests, report actual results and retain runnable setup and demo instructions. Maintain GitHub issues, milestones and reviewed pull requests once access is established.

See [requirements and acceptance](docs/requirements.md) and [the proposed relational model](docs/relational-schema.md).

## Proposed repository structure

| Path | Contents |
| --- | --- |
| Root and `docs/` | Project, architecture, ER model, normalization, dictionary, source attribution, change log, contribution guide and test evidence |
| `sql/00_schema/` through `sql/04_migrations/` | Tables and constraints, sequences, staging, seed scripts and incremental migrations |
| `sql/05_queries/` through `sql/09_tests/` | Reports, views, procedures, triggers and database tests |
| `etl/` and `scripts/` | Client, CPE/CVE parsing, normalization, validation, CSV, loader and setup entry points |
| `data/{raw,processed,synthetic,manifests}/` | Raw pages, generated exports, fictional fixtures and acquisition manifests |
| `tests/` and `.github/` | Python tests, hosted Python CI and issue/PR templates |

Keep generated bulk data, secrets and local environments out of Git. Small attributed source fixtures and synthetic examples may be checked in after review.
