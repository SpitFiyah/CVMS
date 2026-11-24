# Oracle workflow

Use SQL*Plus to connect to a dedicated, empty CVMS development schema and run `@sql/install_schema.sql` from the project root. Oracle commits DDL implicitly, so inspect any failed installation for partially created objects and use a fresh development schema for reproducibility. The script checks runtime SQL errors and invalid compiled objects.

- `assign_analyst` validates the task and analyst. Reassigning to the same analyst preserves the assignment date.
- `update_remediation_status` locks the task while checking and applying a transition. PENDING can move to IN_PROGRESS or BLOCKED, IN_PROGRESS can move to BLOCKED or COMPLETED, and BLOCKED can move to IN_PROGRESS. COMPLETED is terminal. Use another remediation attempt to track subsequent work. Reapplying the same status creates no history.
- `generate_asset_risk_summary` validates the asset and returns a cursor based on the risk view. Finding counts include pending verification, and the output exposes a separate pending review count.
- `au_remediation_history` records real status changes with the actor passed to the procedure, when available. Direct updates record an unknown actor. Completion dates, status history and the task change share one caller-owned transaction. Finding lifecycle updates require a separate decision.
- Task due dates are treated as calendar dates. An unfinished task becomes overdue the day after its due date, using the database server calendar.
- `publish_nvd_run` locks the run and source, validates staging counts and applies newer records as a batch. It preserves CVE and software identifiers. An exact replay or older revision leaves the current row untouched. A conflicting source or same-time hash records a rejection. The loader owns commit and rollback and records failed runs separately.
