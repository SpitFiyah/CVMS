# Requirements and acceptance

| Area | Acceptance evidence |
| --- | --- |
| Schema | Fresh Oracle 11g XE installation compiles. Database tests exercise PK, FK, uniqueness, checks, sequences and NULL cases. ER model, relational schema, functional dependencies and dictionary agree with DDL. |
| ETL | Unit tests cover pagination, backoff, syntax, CPE escapes, nullable metrics, duplicates, CSV and rejections. A live small sample has source manifests and reconciled counts. |
| Ingestion | Run a batch twice, then an older extract and a newer revision. Check stable parent keys, no duplicate children, stale revision protection and rollback after a staged failure. |
| Matching | Trace each verified finding to inventory and evidence for the full applicability context. Test ambiguous version and compound conditions as review cases. |
| Reporting | Execute 20 queries, four each for basic, join, aggregate, subquery and advanced reports. Compare expected counts for empty assets, multiple evidence rows, NULL CVSS, ties and overdue/remediated tasks. |
| PL/SQL | Exercise assignment validation, task status transitions, completion dates, asset risk summaries, actor attribution and history rollback. |
| Delivery | Reproduce installation and demo from a clean development schema. Link actual Python CI and Oracle evidence separately. |

Required views are `V_CRITICAL_VULNERABILITIES`, `V_ASSET_RISK_SUMMARY`, `V_UNRESOLVED_VULNERABILITIES`, `V_ANALYST_WORKLOAD`, and `V_REMEDIATION_SUMMARY`.

The demonstration targets 30–50 authentic CVEs, 10–15 products, 5–8 vendors, 8–12 assets, 20–30 installations, 3–5 analysts, 30–60 verified findings, 15–25 remediation tasks and 30–50 references. Evidence quality takes priority over counts. Prefer CVSS 3.1 where available and carry score version and source through reporting.
