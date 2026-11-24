CREATE TABLE data_source (
    source_id NUMBER PRIMARY KEY,
    source_name VARCHAR2(100 CHAR) NOT NULL UNIQUE,
    source_url VARCHAR2(500 CHAR) NOT NULL
);

CREATE TABLE import_run (
    run_id NUMBER PRIMARY KEY,
    source_id NUMBER NOT NULL REFERENCES data_source,
    started_at TIMESTAMP(3) DEFAULT SYS_EXTRACT_UTC(SYSTIMESTAMP) NOT NULL,
    ended_at TIMESTAMP(3),
    dataset_version VARCHAR2(100 CHAR),
    manifest_locator VARCHAR2(1000 BYTE) NOT NULL,
    retrieved_count NUMBER(12,0) DEFAULT 0 NOT NULL,
    accepted_count NUMBER(12,0) DEFAULT 0 NOT NULL,
    rejected_count NUMBER(12,0) DEFAULT 0 NOT NULL,
    applied_count NUMBER(12,0) DEFAULT 0 NOT NULL,
    status VARCHAR2(15 BYTE) DEFAULT 'RUNNING' NOT NULL,
    error_summary VARCHAR2(1000 CHAR),
    CONSTRAINT uq_run_source UNIQUE (run_id, source_id),
    CONSTRAINT ck_run_status CHECK (status IN ('RUNNING','SUCCEEDED','FAILED')),
    CONSTRAINT ck_run_finished CHECK (
        (status = 'RUNNING' AND ended_at IS NULL)
        OR (status <> 'RUNNING' AND ended_at IS NOT NULL AND ended_at >= started_at)),
    CONSTRAINT ck_run_counts CHECK (
        retrieved_count >= 0 AND accepted_count >= 0 AND rejected_count >= 0
        AND applied_count BETWEEN 0 AND accepted_count
        AND (status <> 'SUCCEEDED' OR retrieved_count = accepted_count + rejected_count))
);

CREATE TABLE import_reject (
    run_id NUMBER REFERENCES import_run,
    row_locator VARCHAR2(250 BYTE),
    external_id VARCHAR2(100 BYTE),
    reason VARCHAR2(1000 CHAR) NOT NULL,
    PRIMARY KEY (run_id, row_locator)
);

CREATE TABLE vulnerability (
    vuln_id NUMBER PRIMARY KEY,
    cve_id VARCHAR2(25 BYTE) NOT NULL UNIQUE,
    description CLOB,
    cvss_version VARCHAR2(10 BYTE),
    cvss_score NUMBER(3,1),
    cvss_source VARCHAR2(150 BYTE),
    severity VARCHAR2(20 BYTE),
    published_date TIMESTAMP(3),
    last_modified_date TIMESTAMP(3) NOT NULL,
    revision_hash CHAR(64 BYTE) NOT NULL,
    nvd_status VARCHAR2(50 CHAR),
    source_id NUMBER NOT NULL REFERENCES data_source,
    last_applied_run_id NUMBER NOT NULL,
    CONSTRAINT fk_vuln_source_run FOREIGN KEY (last_applied_run_id, source_id)
        REFERENCES import_run (run_id, source_id),
    CONSTRAINT ck_vuln_cve CHECK (REGEXP_LIKE(cve_id, '^CVE-[0-9]{4}-[0-9]{4,}$', 'c')),
    CONSTRAINT ck_vuln_score CHECK (cvss_score BETWEEN 0 AND 10),
    CONSTRAINT ck_vuln_metric CHECK (
        (cvss_score IS NULL AND cvss_version IS NULL AND cvss_source IS NULL)
        OR (cvss_score IS NOT NULL AND cvss_version IS NOT NULL AND cvss_source IS NOT NULL))
);

CREATE TABLE applicability_config (
    config_id NUMBER PRIMARY KEY,
    vuln_id NUMBER NOT NULL REFERENCES vulnerability,
    config_ordinal NUMBER(10,0) NOT NULL CHECK (config_ordinal >= 0),
    original_config CLOB NOT NULL,
    CONSTRAINT uq_config_ordinal UNIQUE (vuln_id, config_ordinal)
);

CREATE TABLE software (
    software_id NUMBER PRIMARY KEY,
    software_name VARCHAR2(200 CHAR),
    vendor VARCHAR2(150 CHAR),
    cpe_part CHAR(1 BYTE) NOT NULL CHECK (cpe_part IN ('a','h','o')),
    cpe_vendor VARCHAR2(150 BYTE) NOT NULL,
    cpe_product VARCHAR2(200 BYTE) NOT NULL,
    CONSTRAINT uq_software_cpe UNIQUE (cpe_part, cpe_vendor, cpe_product)
);

CREATE TABLE vuln_software (
    config_id NUMBER REFERENCES applicability_config,
    criterion_path VARCHAR2(250 BYTE),
    software_id NUMBER REFERENCES software,
    cpe_uri VARCHAR2(1000 BYTE) NOT NULL,
    match_criteria_id VARCHAR2(36 BYTE),
    vulnerable_flag CHAR(1 BYTE) NOT NULL CHECK (vulnerable_flag IN ('Y','N')),
    version_start_incl VARCHAR2(100 BYTE),
    version_start_excl VARCHAR2(100 BYTE),
    version_end_incl VARCHAR2(100 BYTE),
    version_end_excl VARCHAR2(100 BYTE),
    PRIMARY KEY (config_id, criterion_path),
    CONSTRAINT ck_criterion_start CHECK (version_start_incl IS NULL OR version_start_excl IS NULL),
    CONSTRAINT ck_criterion_end CHECK (version_end_incl IS NULL OR version_end_excl IS NULL)
);

CREATE TABLE vuln_reference (
    reference_id NUMBER PRIMARY KEY,
    vuln_id NUMBER NOT NULL REFERENCES vulnerability,
    reference_url VARCHAR2(1000 BYTE) NOT NULL,
    reference_source VARCHAR2(200 BYTE) NOT NULL,
    CONSTRAINT uq_vuln_reference UNIQUE (vuln_id, reference_url, reference_source)
);

CREATE TABLE reference_tag (
    reference_id NUMBER REFERENCES vuln_reference,
    tag VARCHAR2(100 BYTE),
    PRIMARY KEY (reference_id, tag)
);

CREATE TABLE asset (
    asset_id NUMBER PRIMARY KEY,
    asset_name VARCHAR2(150 CHAR) NOT NULL UNIQUE,
    asset_type VARCHAR2(50 CHAR) NOT NULL,
    ip_address VARCHAR2(45 BYTE),
    department VARCHAR2(100 CHAR),
    environment VARCHAR2(30 BYTE) NOT NULL
);

CREATE TABLE asset_software (
    installation_id NUMBER PRIMARY KEY,
    asset_id NUMBER NOT NULL REFERENCES asset,
    software_id NUMBER NOT NULL REFERENCES software,
    installation_slot VARCHAR2(100 BYTE) NOT NULL,
    installed_version VARCHAR2(100 BYTE),
    installation_date DATE,
    observed_cpe VARCHAR2(1000 BYTE),
    CONSTRAINT uq_install_slot UNIQUE (asset_id, software_id, installation_slot)
);

CREATE TABLE asset_vulnerability (
    asset_vuln_id NUMBER PRIMARY KEY,
    asset_id NUMBER NOT NULL REFERENCES asset,
    vuln_id NUMBER NOT NULL REFERENCES vulnerability,
    detected_date TIMESTAMP(3) DEFAULT SYS_EXTRACT_UTC(SYSTIMESTAMP) NOT NULL,
    status VARCHAR2(30 BYTE) DEFAULT 'OPEN' NOT NULL,
    verification_status VARCHAR2(30 BYTE) DEFAULT 'PENDING' NOT NULL,
    last_verified_date TIMESTAMP(3),
    CONSTRAINT uq_asset_cve UNIQUE (asset_id, vuln_id),
    CONSTRAINT ck_finding_status CHECK (status IN
        ('OPEN','IN_PROGRESS','RESOLVED','ACCEPTED_RISK','FALSE_POSITIVE')),
    CONSTRAINT ck_finding_review CHECK (
        (status = 'FALSE_POSITIVE' AND verification_status = 'REFUTED')
        OR (status <> 'FALSE_POSITIVE' AND verification_status IN ('PENDING','VERIFIED'))),
    CONSTRAINT ck_finding_review_date CHECK (
        (verification_status = 'PENDING' AND last_verified_date IS NULL)
        OR (verification_status IN ('VERIFIED','REFUTED') AND last_verified_date >= detected_date
            AND last_verified_date IS NOT NULL))
);

CREATE TABLE analyst (
    analyst_id NUMBER PRIMARY KEY,
    analyst_name VARCHAR2(150 CHAR) NOT NULL,
    email VARCHAR2(150 CHAR) NOT NULL UNIQUE,
    specialization VARCHAR2(100 CHAR),
    CONSTRAINT ck_analyst_email_case CHECK (email = LOWER(email))
);

CREATE TABLE finding_evidence (
    evidence_id NUMBER PRIMARY KEY,
    asset_vuln_id NUMBER NOT NULL REFERENCES asset_vulnerability,
    run_id NUMBER NOT NULL REFERENCES import_run,
    reviewed_by NUMBER REFERENCES analyst,
    source_locator VARCHAR2(250 BYTE) NOT NULL,
    inventory_snapshot CLOB NOT NULL,
    reviewed_at TIMESTAMP(3) DEFAULT SYS_EXTRACT_UTC(SYSTIMESTAMP) NOT NULL,
    disposition VARCHAR2(30 BYTE) NOT NULL CHECK (disposition IN ('PENDING','VERIFIED','REFUTED')),
    explanation VARCHAR2(1000 CHAR) NOT NULL
);

CREATE TABLE remediation (
    remediation_id NUMBER PRIMARY KEY,
    asset_vuln_id NUMBER NOT NULL REFERENCES asset_vulnerability,
    analyst_id NUMBER REFERENCES analyst,
    action_taken VARCHAR2(1000 CHAR),
    assigned_date DATE,
    due_date DATE,
    completion_date DATE,
    status VARCHAR2(30 BYTE) DEFAULT 'PENDING' NOT NULL,
    CONSTRAINT ck_task_status CHECK (status IN ('PENDING','IN_PROGRESS','COMPLETED','BLOCKED')),
    CONSTRAINT ck_task_completion CHECK (
        (status = 'COMPLETED' AND completion_date IS NOT NULL)
        OR (status <> 'COMPLETED' AND completion_date IS NULL)),
    CONSTRAINT ck_task_assignment CHECK (
        (analyst_id IS NULL AND assigned_date IS NULL) OR
        (analyst_id IS NOT NULL AND assigned_date IS NOT NULL))
);

CREATE TABLE remediation_history (
    history_id NUMBER PRIMARY KEY,
    remediation_id NUMBER NOT NULL REFERENCES remediation,
    old_status VARCHAR2(30 BYTE) NOT NULL,
    new_status VARCHAR2(30 BYTE) NOT NULL,
    changed_by NUMBER REFERENCES analyst,
    changed_at TIMESTAMP(3) DEFAULT SYS_EXTRACT_UTC(SYSTIMESTAMP) NOT NULL,
    remarks VARCHAR2(500 CHAR),
    CONSTRAINT ck_history_changed CHECK (old_status <> new_status)
);

CREATE INDEX ix_run_source ON import_run (source_id);
CREATE INDEX ix_vuln_source ON vulnerability (source_id);
CREATE INDEX ix_vuln_run ON vulnerability (last_applied_run_id, source_id);
CREATE INDEX ix_vs_software ON vuln_software (software_id);
CREATE INDEX ix_install_software ON asset_software (software_id);
CREATE INDEX ix_finding_vuln ON asset_vulnerability (vuln_id);
CREATE INDEX ix_evidence_finding ON finding_evidence (asset_vuln_id);
CREATE INDEX ix_evidence_run ON finding_evidence (run_id);
CREATE INDEX ix_evidence_analyst ON finding_evidence (reviewed_by);
CREATE INDEX ix_task_finding ON remediation (asset_vuln_id);
CREATE INDEX ix_task_analyst ON remediation (analyst_id);
CREATE INDEX ix_task_status_due ON remediation (status, due_date);
CREATE INDEX ix_history_task ON remediation_history (remediation_id, changed_at);
CREATE INDEX ix_history_actor ON remediation_history (changed_by);
