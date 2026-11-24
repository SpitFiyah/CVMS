# Project status

## Current phase

Local implementation and verification. Target remote is `https://github.com/SpitFiyah/CVMS.git`. The local feature branch was prepared independently while remote access was unavailable.

## Completed and checked

- Research and design documented in the project specification, architecture, relational model, normalization and data dictionary. Mermaid source and GitHub Markdown blocks are available.
- Implemented 16 core tables, five staging tables, ID sequences and triggers, a publication procedure, five views, three workflow entry points, a status history trigger, 20 reports and Oracle assertions.
- Implemented NVD retrieval, raw archiving, CSV generation, rejection accounting, snapshot replay and Oracle staging. Ten Python unit tests passed, including CPE Dictionary reconciliation using mocked API responses. Five authentic snapshot records were retrieved through the web path and replayed offline with five accepted and zero rejected. The batch preserves the revision used by the fictional seed.
- Prepared a fictional demo with eight assets, three analysts, two reviewed exact-CPE findings and two tasks. These are scripted expected counts pending actual Oracle execution.
- Prepared GitHub issue, milestone and pull request drafts and a Python Actions workflow.

## Pending and blocked

- GitHub authenticated lookup, repository reconciliation, remote branches, project items, publishing, PR and hosted CI. Terminal DNS fails for GitHub and the web path could not read the supplied repository. No remote change was made.
- Oracle 11g XE installation and execution evidence. No compatible client, configured DSN or accessible development server was identified. No database objects, fixture rows or CVE rows were created in a running Oracle database.
- A broader live NVD sample and live CPE Dictionary reconciliation. The terminal collector exhausted retries with a name resolution error. The bundled five-record sample supports an offline demonstration.
- Mermaid rendering and Oracle integration evidence. The publication assertion script exercises exact replay, stale records, equal-time conflicts, revised children, stable IDs and rollback.

## Next three priorities

1. Reconcile with the supplied remote as soon as authenticated GitHub access is available.
2. Execute schema, import and test scripts against a dedicated Oracle 11g XE runtime and fix any compatibility issues found.
3. Expand source and inventory coverage, verify additional findings with evidence, and record the observed demo and CI results.

See [test report](docs/test-report.md) for commands and observed results.
