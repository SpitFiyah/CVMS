# Proposed data dictionary

IDs use `NUMBER`. Business strings use bounded `VARCHAR2`; long payloads use `CLOB`. Source and audit timestamps use UTC; day-level planning fields use `DATE`. PKs, alternate keys and FK cardinalities appear in the [relational model](relational-schema.md).

| Relation | Non-key fields and rules |
| --- | --- |
| DATA_SOURCE | Source URL |
| IMPORT_RUN | Started and ended timestamps, dataset version, manifest locator, retrieved/accepted/rejected/applied counts, outcome and error summary |
| IMPORT_REJECT | Raw row locator within the run, optional external identifier and rejection reason |
| VULNERABILITY | English description CLOB, published and last-modified UTC timestamps, NVD status, revision SHA-256, selected CVSS score (0–10), metric version, source and severity. Missing values use NULL. |
| APPLICABILITY_CONFIG | Original configuration CLOB associated with the source ordinal |
| SOFTWARE | Display name and vendor name |
| VULN_SOFTWARE | Source CPE text, match criteria UUID, vulnerable flag, inclusive/exclusive start and end bounds. Keep one bound per side and preserve raw source on rejection. |
| VULN_REFERENCE | Source identifier and original URL, with tags drawn from source data |
| REFERENCE_TAG | One source tag per reference |
| ASSET | Asset type, synthetic IP, department and environment |
| ASSET_SOFTWARE | Installed version, installation date and available CPE attributes |
| ASSET_VULNERABILITY | Detected and last verified timestamps, lifecycle and verification status. A refuted finding maps to false positive. |
| FINDING_EVIDENCE | Source page/path, applicability and inventory snapshot, review timestamp, disposition and explanation |
| ANALYST | Name, canonical email and specialization |
| REMEDIATION | Action, assignment/due/completion dates, status. Require a completion date precisely when completed. |
| REMEDIATION_HISTORY | Old and new task status, actor, timestamp and optional remarks |

Lifecycle values are OPEN, IN_PROGRESS, RESOLVED, ACCEPTED_RISK and FALSE_POSITIVE. Verification values are PENDING, VERIFIED and REFUTED. Task statuses are PENDING, IN_PROGRESS, COMPLETED and BLOCKED. Establish the transition matrix before writing procedures. Reports define unresolved as OPEN or IN_PROGRESS and explicitly label the inclusion of pending findings.
