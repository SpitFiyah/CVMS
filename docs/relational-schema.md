# Proposed relational schema

[ER diagram](er-diagram.md) · [Data dictionary](data-dictionary.md) · [Normalization](normalization.md)

| Relation | Primary key | Alternate key | Foreign keys |
| --- | --- | --- | --- |
| DATA_SOURCE | source_id | source_name | |
| IMPORT_RUN | run_id | | source_id |
| IMPORT_REJECT | run_id, row_locator | | run_id |
| VULNERABILITY | vuln_id | cve_id | source_id, last_applied_run_id |
| APPLICABILITY_CONFIG | config_id | vuln_id, config_ordinal | vuln_id |
| SOFTWARE | software_id | cpe_part, cpe_vendor, cpe_product | |
| VULN_SOFTWARE | config_id, criterion_path | | config_id, software_id (optional) |
| VULN_REFERENCE | reference_id | vuln_id, reference_url, reference_source | vuln_id |
| REFERENCE_TAG | reference_id, tag | | reference_id |
| ASSET | asset_id | asset_name | |
| ASSET_SOFTWARE | installation_id | asset_id, software_id, installation_slot | asset_id, software_id |
| ASSET_VULNERABILITY | asset_vuln_id | asset_id, vuln_id | asset_id, vuln_id |
| FINDING_EVIDENCE | evidence_id | | asset_vuln_id, run_id, reviewed_by (optional) |
| ANALYST | analyst_id | email | |
| REMEDIATION | remediation_id | | asset_vuln_id, analyst_id (optional before assignment) |
| REMEDIATION_HISTORY | history_id | | remediation_id, changed_by (optional) |

## Corrections to the starting model

- CPE part joins vendor and product in the canonical key. Wildcard or ambiguous identifiers can remain unlinked criteria. Distinguish display names from canonical identifiers.
- A flattened range loses surrounding applicability conditions. Store the original configuration as CLOB and key projected criteria by their path within it. Criteria carry the vulnerable flag and their original boundaries.
- The asset/product pair cannot represent parallel installations. A stable inventory slot identifies an installation of the product on each asset even if its version changes.
- Reference URLs can be repeated across sources and can have multiple tags. Preserve source and use a separate tag relation.
- Import timing and version belong on the run. Preserve source and last applied run on each CVE, and check that they agree at publication. Run status distinguishes failure from a successful rerun with zero changes.
- Findings use separate lifecycle and verification states. Evidence retains the source locator and point-in-time inventory details so future inventory changes or criterion replacements cannot rewrite the basis of a review.
- Assigned analyst and status change actor are distinct. The update procedure supplies an explicit actor where known, and ordinary updates can record an unknown actor. History rows share the status update transaction.
