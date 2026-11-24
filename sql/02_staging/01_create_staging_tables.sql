-- Stage a CVE and its child records together. Use source page and row locators
-- to reconcile duplicate and invalid CVEs with the original response.
CREATE TABLE stg_vulnerability (
    run_id NUMBER REFERENCES import_run,
    row_locator VARCHAR2(250 BYTE),
    cve_id VARCHAR2(25 BYTE) NOT NULL,
    description CLOB,
    cvss_version VARCHAR2(10 BYTE),
    cvss_score NUMBER,
    cvss_source VARCHAR2(150 BYTE),
    severity VARCHAR2(20 BYTE),
    published_date TIMESTAMP(3),
    last_modified_date TIMESTAMP(3) NOT NULL,
    revision_hash CHAR(64 BYTE) NOT NULL,
    nvd_status VARCHAR2(50 CHAR),
    PRIMARY KEY (run_id, row_locator)
);

CREATE TABLE stg_app_config (
    run_id NUMBER,
    row_locator VARCHAR2(250 BYTE),
    config_ordinal NUMBER(10,0),
    original_config CLOB NOT NULL,
    PRIMARY KEY (run_id, row_locator, config_ordinal),
    FOREIGN KEY (run_id, row_locator) REFERENCES stg_vulnerability
);

CREATE TABLE stg_criterion (
    run_id NUMBER,
    row_locator VARCHAR2(250 BYTE),
    config_ordinal NUMBER(10,0),
    criterion_path VARCHAR2(250 BYTE),
    cpe_part CHAR(1 BYTE),
    cpe_vendor VARCHAR2(150 BYTE),
    cpe_product VARCHAR2(200 BYTE),
    cpe_uri VARCHAR2(1000 BYTE) NOT NULL,
    match_criteria_id VARCHAR2(36 BYTE),
    vulnerable_flag CHAR(1 BYTE) NOT NULL,
    version_start_incl VARCHAR2(100 BYTE),
    version_start_excl VARCHAR2(100 BYTE),
    version_end_incl VARCHAR2(100 BYTE),
    version_end_excl VARCHAR2(100 BYTE),
    PRIMARY KEY (run_id, row_locator, config_ordinal, criterion_path),
    FOREIGN KEY (run_id, row_locator, config_ordinal) REFERENCES stg_app_config
);

CREATE TABLE stg_reference (
    run_id NUMBER,
    row_locator VARCHAR2(250 BYTE),
    reference_url VARCHAR2(1000 BYTE),
    reference_source VARCHAR2(200 BYTE),
    PRIMARY KEY (run_id, row_locator, reference_url, reference_source),
    FOREIGN KEY (run_id, row_locator) REFERENCES stg_vulnerability
);

CREATE TABLE stg_reference_tag (
    run_id NUMBER,
    row_locator VARCHAR2(250 BYTE),
    reference_url VARCHAR2(1000 BYTE),
    reference_source VARCHAR2(200 BYTE),
    tag VARCHAR2(100 BYTE),
    PRIMARY KEY (run_id, row_locator, reference_url, reference_source, tag),
    FOREIGN KEY (run_id, row_locator, reference_url, reference_source) REFERENCES stg_reference
);
