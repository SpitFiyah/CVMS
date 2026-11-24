WHENEVER OSERROR EXIT FAILURE
WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
SET DEFINE OFF
SET SERVEROUTPUT ON

-- Synthetic test rows are rolled back even on success. Sequence gaps are expected.
DECLARE
    source_key NUMBER;
    run_key NUMBER;
    vuln_key NUMBER;
    asset_key NUMBER;
    finding_key NUMBER;
    analyst_key NUMBER;
    task_key NUMBER;
    value_count NUMBER;
    task_status remediation.status%TYPE;
    completed_at DATE;
    current_cve vulnerability.cve_id%TYPE;
    test_token VARCHAR2(32) := RAWTOHEX(SYS_GUID());

    PROCEDURE expect_count(actual NUMBER, expected NUMBER, description VARCHAR2) IS
    BEGIN
        IF actual IS NULL OR actual <> expected THEN
            RAISE_APPLICATION_ERROR(-20900, description);
        END IF;
    END;
BEGIN
    INSERT INTO data_source (source_name, source_url)
    VALUES ('TEST-' || test_token, 'https://example.invalid')
    RETURNING source_id INTO source_key;
    INSERT INTO import_run (source_id, manifest_locator)
    VALUES (source_key, 'test') RETURNING run_id INTO run_key;

    -- Test identifier only. The test transaction never publishes it.
    SELECT 'CVE-9999-' || TO_CHAR(MOD(ABS(DBMS_UTILITY.GET_TIME), 100000000), 'FM00000000')
      INTO current_cve FROM dual;
    INSERT INTO vulnerability (cve_id, last_modified_date, revision_hash, source_id, last_applied_run_id)
    VALUES (current_cve, TIMESTAMP '2020-01-01 00:00:00', RPAD('0', 64, '0'), source_key, run_key)
    RETURNING vuln_id INTO vuln_key;

    SELECT COUNT(*) INTO value_count FROM vulnerability WHERE vuln_id = vuln_key AND cvss_score IS NULL;
    expect_count(value_count, 1, 'Generated ID or NULL score check failed');

    BEGIN
        INSERT INTO vulnerability (cve_id, last_modified_date, revision_hash, source_id, last_applied_run_id)
        VALUES (current_cve, TIMESTAMP '2020-01-01 00:00:00', RPAD('0', 64, '0'), source_key, run_key);
        RAISE_APPLICATION_ERROR(-20901, 'Duplicate CVE was accepted');
    EXCEPTION WHEN DUP_VAL_ON_INDEX THEN NULL;
    END;

    BEGIN
        UPDATE vulnerability SET cvss_score = 11, cvss_version = '3.1', cvss_source = 'test'
        WHERE vuln_id = vuln_key;
        RAISE_APPLICATION_ERROR(-20902, 'Out-of-range score was accepted');
    EXCEPTION WHEN OTHERS THEN IF SQLCODE <> -2290 THEN RAISE; END IF;
    END;

    BEGIN
        INSERT INTO asset_vulnerability (asset_id, vuln_id) VALUES (-1, vuln_key);
        RAISE_APPLICATION_ERROR(-20903, 'Orphan finding was accepted');
    EXCEPTION WHEN OTHERS THEN IF SQLCODE <> -2291 THEN RAISE; END IF;
    END;

    INSERT INTO asset (asset_name, asset_type, environment) VALUES (test_token, 'SERVER', 'PRODUCTION')
    RETURNING asset_id INTO asset_key;
    SELECT total_findings INTO value_count FROM v_asset_risk_summary WHERE asset_id = asset_key;
    expect_count(value_count, 0, 'Empty asset count is incorrect');
    INSERT INTO asset_vulnerability (asset_id, vuln_id) VALUES (asset_key, vuln_key)
    RETURNING asset_vuln_id INTO finding_key;
    INSERT INTO analyst (analyst_name, email) VALUES ('Test analyst', LOWER(test_token) || '@example.invalid')
    RETURNING analyst_id INTO analyst_key;
    INSERT INTO remediation (asset_vuln_id, due_date) VALUES (finding_key, TRUNC(SYSDATE) - 1)
    RETURNING remediation_id INTO task_key;
    INSERT INTO remediation (asset_vuln_id) VALUES (finding_key);
    assign_analyst(task_key, analyst_key);
    SELECT COUNT(*) INTO value_count
    FROM v_remediation_summary WHERE remediation_id = task_key AND analyst_id = analyst_key AND is_overdue = 1;
    expect_count(value_count, 1, 'Assignment, overdue calculation or join is incorrect');
    SELECT total_findings INTO value_count FROM v_asset_risk_summary WHERE asset_id = asset_key;
    expect_count(value_count, 1, 'Task joins multiplied the finding count');

    SAVEPOINT before_status_updates;
    update_remediation_status(task_key, 'PENDING');
    update_remediation_status(task_key, 'IN_PROGRESS', analyst_key, 'Started');
    update_remediation_status(task_key, 'COMPLETED', analyst_key);
    SELECT COUNT(*) INTO value_count FROM remediation_history
    WHERE remediation_id = task_key AND changed_by = analyst_key
      AND ((old_status = 'PENDING' AND new_status = 'IN_PROGRESS' AND remarks = 'Started')
       OR (old_status = 'IN_PROGRESS' AND new_status = 'COMPLETED'));
    expect_count(value_count, 2, 'Expected attributed status history');
    SELECT COUNT(*) INTO value_count FROM remediation_history WHERE remediation_id = task_key;
    expect_count(value_count, 2, 'No-op status produced history');
    SELECT status, completion_date INTO task_status, completed_at FROM remediation WHERE remediation_id = task_key;
    IF task_status <> 'COMPLETED' OR completed_at IS NULL THEN
        RAISE_APPLICATION_ERROR(-20904, 'Task completion was not recorded');
    END IF;
    SELECT COUNT(*) INTO value_count FROM v_unresolved_vulnerabilities WHERE asset_vuln_id = finding_key;
    expect_count(value_count, 1, 'Completing a task changed finding lifecycle');
    ROLLBACK TO before_status_updates;
    SELECT COUNT(*) INTO value_count FROM remediation_history WHERE remediation_id = task_key;
    expect_count(value_count, 0, 'Rollback retained task history');
    SELECT COUNT(*) INTO value_count FROM remediation
    WHERE remediation_id = task_key AND status = 'PENDING' AND completion_date IS NULL;
    expect_count(value_count, 1, 'Rollback retained task status or completion date');
    ROLLBACK;
    DBMS_OUTPUT.PUT_LINE('Oracle schema, view and workflow assertions passed.');
END;
/
