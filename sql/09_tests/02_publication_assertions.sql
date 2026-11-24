WHENEVER OSERROR EXIT FAILURE
WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
SET DEFINE OFF
SET SERVEROUTPUT ON

-- Test-only CVE and CPE identifiers. Always run in the dedicated test schema.
DECLARE
    token CONSTANT VARCHAR2(32) := RAWTOHEX(SYS_GUID());
    cve CONSTANT VARCHAR2(25) := 'CVE-9999-' || TO_CHAR(
        MOD(TO_NUMBER(SUBSTR(token, 1, 15), 'XXXXXXXXXXXXXXX'), 10000000000000),
        'FM00000000000000');
    locator CONSTANT VARCHAR2(40) := 'fixture.json#/vulnerabilities/0';
    source_key NUMBER;
    first_run NUMBER;
    run_key NUMBER;
    original_vuln NUMBER;
    original_product NUMBER;
    actual NUMBER;
    revision_one CONSTANT TIMESTAMP := TIMESTAMP '2024-01-01 00:00:00.100';
    revision_two CONSTANT TIMESTAMP := TIMESTAMP '2024-01-01 00:00:00.200';
    first_hash CONSTANT CHAR(64) := RPAD('a', 64, 'a');
    second_hash CONSTANT CHAR(64) := RPAD('b', 64, 'b');

    PROCEDURE require_equal(observed NUMBER, expected NUMBER, message VARCHAR2) IS
    BEGIN
        IF observed IS NULL OR observed <> expected THEN
            RAISE_APPLICATION_ERROR(-20910, message);
        END IF;
    END;

    PROCEDURE stage_revision(
        revision_at TIMESTAMP,
        hash CHAR,
        version_component VARCHAR2,
        new_run OUT NUMBER,
        vulnerable CHAR DEFAULT 'Y'
    ) IS
    BEGIN
        INSERT INTO import_run (source_id, manifest_locator, retrieved_count)
        VALUES (source_key, 'test fixture', 1)
        RETURNING run_id INTO new_run;

        INSERT INTO stg_vulnerability (run_id, row_locator, cve_id, last_modified_date, revision_hash)
        VALUES (new_run, locator, cve, revision_at, hash);

        INSERT INTO stg_app_config (run_id, row_locator, config_ordinal, original_config)
        VALUES (new_run, locator, 0, '{"nodes":[]}');

        INSERT INTO stg_criterion (run_id, row_locator, config_ordinal, criterion_path,
            cpe_part, cpe_vendor, cpe_product, cpe_uri, vulnerable_flag, version_end_excl)
        VALUES (new_run, locator, 0, '/nodes/0/cpeMatch/0', 'a', 'cvms_test', LOWER(token),
            'cpe:2.3:a:cvms_test:' || LOWER(token) || ':*:*:*:*:*:*:*:*', vulnerable, version_component);

        INSERT INTO stg_reference (run_id, row_locator, reference_url, reference_source)
        VALUES (new_run, locator, 'https://example.invalid/' || version_component, 'test');
        INSERT INTO stg_reference_tag (run_id, row_locator, reference_url, reference_source, tag)
        VALUES (new_run, locator, 'https://example.invalid/' || version_component, 'test', 'Vendor Advisory');
    END;

    PROCEDURE require_audit(batch NUMBER, accepted NUMBER, rejected NUMBER, applied NUMBER) IS
        matching NUMBER;
    BEGIN
        SELECT COUNT(*) INTO matching FROM import_run
        WHERE run_id = batch AND status = 'SUCCEEDED' AND ended_at IS NOT NULL
          AND retrieved_count = 1 AND accepted_count = accepted
          AND rejected_count = rejected AND applied_count = applied;
        require_equal(matching, 1, 'Unexpected publication counters');
    END;
BEGIN
    SAVEPOINT before_publication_test;
    INSERT INTO data_source (source_name, source_url)
    VALUES ('PUBLICATION-TEST-' || token, 'https://example.invalid')
    RETURNING source_id INTO source_key;

    stage_revision(revision_one, first_hash, '1.0', first_run);
    publish_nvd_run(first_run);
    require_audit(first_run, 1, 0, 1);

    SELECT vuln_id INTO original_vuln FROM vulnerability WHERE cve_id = cve;
    SELECT software_id INTO original_product FROM software
    WHERE cpe_part = 'a' AND cpe_vendor = 'cvms_test' AND cpe_product = LOWER(token);

    stage_revision(revision_one, first_hash, '1.0', run_key);
    publish_nvd_run(run_key);
    require_audit(run_key, 1, 0, 0);
    SELECT COUNT(*) INTO actual FROM vulnerability
    WHERE vuln_id = original_vuln AND last_applied_run_id = first_run;
    require_equal(actual, 1, 'Identical replay changed the current CVE');

    stage_revision(revision_one, second_hash, '2.0', run_key);
    publish_nvd_run(run_key);
    require_audit(run_key, 0, 1, 0);
    SELECT COUNT(*) INTO actual FROM import_reject WHERE run_id = run_key AND external_id = cve;
    require_equal(actual, 1, 'Equal-time conflict is absent from rejects');

    stage_revision(revision_two, second_hash, '2.0', run_key);
    publish_nvd_run(run_key);
    require_audit(run_key, 1, 0, 1);
    SELECT COUNT(*) INTO actual FROM vulnerability
    WHERE vuln_id = original_vuln AND last_applied_run_id = run_key AND revision_hash = second_hash;
    require_equal(actual, 1, 'New revision did not preserve the CVE ID');

    SELECT COUNT(*) INTO actual FROM applicability_config a
    JOIN vuln_software c ON c.config_id = a.config_id
    WHERE a.vuln_id = original_vuln AND c.software_id = original_product AND c.version_end_excl = '2.0';
    require_equal(actual, 1, 'New revision failed to refresh the criterion using the stable software ID');
    SELECT COUNT(*) INTO actual FROM vuln_reference r
    JOIN reference_tag t ON t.reference_id = r.reference_id
    WHERE r.vuln_id = original_vuln AND r.reference_url = 'https://example.invalid/2.0'
      AND t.tag = 'Vendor Advisory';
    require_equal(actual, 1, 'New revision failed to refresh the reference and tag');
    SELECT COUNT(*) INTO actual FROM vuln_reference
    WHERE vuln_id = original_vuln AND reference_url = 'https://example.invalid/1.0';
    require_equal(actual, 0, 'Old reference survived publication');

    stage_revision(revision_one, first_hash, '1.0', run_key);
    publish_nvd_run(run_key);
    require_audit(run_key, 1, 0, 0);

    SAVEPOINT before_invalid_revision;
    stage_revision(revision_two + INTERVAL '1' DAY, first_hash, '3.0', run_key, 'X');
    BEGIN
        publish_nvd_run(run_key);
        RAISE_APPLICATION_ERROR(-20911, 'Invalid child criterion was published');
    EXCEPTION
        WHEN OTHERS THEN
            IF SQLCODE <> -2290 THEN RAISE; END IF;
    END;
    ROLLBACK TO before_invalid_revision;
    SELECT COUNT(*) INTO actual FROM vulnerability
    WHERE vuln_id = original_vuln AND last_modified_date = revision_two AND revision_hash = second_hash;
    require_equal(actual, 1, 'Caller rollback failed to retain the last good revision');
    SELECT COUNT(*) INTO actual FROM applicability_config a
    JOIN vuln_software c ON c.config_id = a.config_id
    WHERE a.vuln_id = original_vuln AND c.version_end_excl = '2.0' AND c.vulnerable_flag = 'Y';
    require_equal(actual, 1, 'Caller rollback failed to retain the last good criterion');

    ROLLBACK TO before_publication_test;
    DBMS_OUTPUT.PUT_LINE('Oracle publication and replay assertions passed.');
END;
/
