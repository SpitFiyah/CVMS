# GitHub setup and issue drafts

The repository is `SpitFiyah/CVMS`. Its current default branch is `feature/cvms-implementation`. Run `./scripts/sync_github_milestones.sh` from an authenticated terminal to publish milestone verification issues and retain open live-data and report tasks. Discover the authenticated owner and inspect any existing default branch, conventions, issues and permissions before adopting these drafts. If the repository does not exist, confirm owner and visibility and obtain creation approval. Use `main` for stable releases, `develop` for integration and `feature/*` or `bugfix/*` for reviewed PRs. PRs should link an issue and include scope, files, tests, results and limitations.

## Milestones

| Milestone | Completion evidence |
| --- | --- |
| M1 — Project Foundation | Existing repository checked and reviewed requirements, architecture and data model tracked |
| M2 — Oracle Schema Implementation | Fresh Oracle 11g XE build with constraint and sequence test evidence |
| M3 — NVD Data Collection Pipeline | Small source archive, CSV and rejection output with Python tests |
| M4 — Data Population and Asset Mapping | Repeated import evidence, fictional inventory and auditable reviewed findings |
| M5 — SQL and PL/SQL Implementation | Reports, views, procedures and trigger run against controlled fixtures |
| M6 — Testing and Final Documentation | Clean-schema demonstration, CI and Oracle evidence, final status |

## Draft issues

| Issue and milestone | Objective and affected files | Acceptance and testing | Dependencies | Labels |
| --- | --- | --- | --- | --- |
| F1 Reconcile project foundation · M1 | Inspect repository and publish reviewed Phase 1 docs in root and `docs/` | Verify target and branches, render diagrams, review schema and requirements | Authenticated GitHub access | architecture, documentation |
| D1 Build schema and staging · M2 | Write Oracle 11g DDL, constraints, indexes and sequences in `sql/00_schema/`–`02_staging/` | Fresh setup, valid objects, rejected duplicate/orphan/check violations, generated IDs | F1, dedicated Oracle schema | database, oracle-sql |
| E1 Fetch and archive NVD pages · M3 | Implement NVD client, paging, pacing and raw manifests in `etl/` | Exercise end of pagination, retry limits and transient errors with mocked HTTP. Archive a small live sample | Shell NVD connectivity for live check | etl, nvd-api, testing |
| E2 Parse, validate and export · M3 | Map CVE, CVSS, CPE and references to CSV and rejects in `etl/` | Test compound configurations, escaped components, NULL CVSS, duplicate input and invalid rows | E1 response contract, D1 staging contract | etl, data-quality |
| P1 Publish staged batches · M4 | Implement validation, audit and repeatable loads in `sql/` and `etl/importer.py` | Reconcile counts and test identical replay, old and revised sources, and rollback after child failure | D1, E2 | database, plsql, data-quality |
| P2 Seed inventory and review findings · M4 | Add fictional fixtures, evidence and analyst assignments in `data/synthetic/` and `sql/03_seed_data/` | Trace verified rows, exercise unresolved compound conditions, check fixture replays | P1 | data-quality, database |
| S1 Implement reports and views · M5 | Add 20 queries and five views under `sql/05_queries/` and `06_views/` | Compare controlled outputs for distinct counts, rankings, NULLs, deadlines and empty assets | D1, P2 | oracle-sql, testing |
| S2 Implement procedures and history · M5 | Add assignment, transition, risk summary and history scripts under `sql/07_procedures/` and `08_triggers/` | Check invalid IDs/transitions, no-op status, actor, completion date, unaffected finding status and rollback | D1, S1 risk view | plsql, testing |
| Q1 Run integration tests and enable CI · M6 | Add Python CI, SQL assertions and evidence in `.github/workflows/`, `sql/09_tests/`, `tests/` and test report | Run Python CI and separate Oracle 11g integration tests. Record failures and fix regressions before closure | E2, P1, P2, S1, S2 | testing, data-quality |
| Q2 Deliver setup and demo · M6 | Finish setup, source attribution, contribution guide, change log and reproducibility docs | Recreate a clean development schema and demonstrate intake through reporting with recorded outputs | Q1 | documentation, testing |
