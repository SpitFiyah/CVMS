CREATE OR REPLACE TRIGGER bi_data_source
BEFORE INSERT ON data_source
FOR EACH ROW
WHEN (NEW.source_id IS NULL)
BEGIN
    SELECT seq_data_source.NEXTVAL INTO :NEW.source_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_import_run
BEFORE INSERT ON import_run
FOR EACH ROW
WHEN (NEW.run_id IS NULL)
BEGIN
    SELECT seq_import_run.NEXTVAL INTO :NEW.run_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_vulnerability
BEFORE INSERT ON vulnerability
FOR EACH ROW
WHEN (NEW.vuln_id IS NULL)
BEGIN
    SELECT seq_vulnerability.NEXTVAL INTO :NEW.vuln_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_applicability_config
BEFORE INSERT ON applicability_config
FOR EACH ROW
WHEN (NEW.config_id IS NULL)
BEGIN
    SELECT seq_applicability_config.NEXTVAL INTO :NEW.config_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_software
BEFORE INSERT ON software
FOR EACH ROW
WHEN (NEW.software_id IS NULL)
BEGIN
    SELECT seq_software.NEXTVAL INTO :NEW.software_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_vuln_reference
BEFORE INSERT ON vuln_reference
FOR EACH ROW
WHEN (NEW.reference_id IS NULL)
BEGIN
    SELECT seq_vuln_reference.NEXTVAL INTO :NEW.reference_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_asset
BEFORE INSERT ON asset
FOR EACH ROW
WHEN (NEW.asset_id IS NULL)
BEGIN
    SELECT seq_asset.NEXTVAL INTO :NEW.asset_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_asset_software
BEFORE INSERT ON asset_software
FOR EACH ROW
WHEN (NEW.installation_id IS NULL)
BEGIN
    SELECT seq_asset_software.NEXTVAL INTO :NEW.installation_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_asset_vulnerability
BEFORE INSERT ON asset_vulnerability
FOR EACH ROW
WHEN (NEW.asset_vuln_id IS NULL)
BEGIN
    SELECT seq_asset_vulnerability.NEXTVAL INTO :NEW.asset_vuln_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_analyst
BEFORE INSERT ON analyst
FOR EACH ROW
WHEN (NEW.analyst_id IS NULL)
BEGIN
    SELECT seq_analyst.NEXTVAL INTO :NEW.analyst_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_finding_evidence
BEFORE INSERT ON finding_evidence
FOR EACH ROW
WHEN (NEW.evidence_id IS NULL)
BEGIN
    SELECT seq_finding_evidence.NEXTVAL INTO :NEW.evidence_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_remediation
BEFORE INSERT ON remediation
FOR EACH ROW
WHEN (NEW.remediation_id IS NULL)
BEGIN
    SELECT seq_remediation.NEXTVAL INTO :NEW.remediation_id FROM dual;
END;
/

CREATE OR REPLACE TRIGGER bi_remediation_history
BEFORE INSERT ON remediation_history
FOR EACH ROW
WHEN (NEW.history_id IS NULL)
BEGIN
    SELECT seq_remediation_history.NEXTVAL INTO :NEW.history_id FROM dual;
END;
/
