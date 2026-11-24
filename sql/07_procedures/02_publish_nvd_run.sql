CREATE OR REPLACE PROCEDURE publish_nvd_run (p_run_id IN import_run.run_id%TYPE) AS
    run_row import_run%ROWTYPE;
    locked_source data_source.source_id%TYPE;
    target_id vulnerability.vuln_id%TYPE;
    target_source vulnerability.source_id%TYPE;
    target_revision vulnerability.last_modified_date%TYPE;
    target_hash vulnerability.revision_hash%TYPE;
    applied NUMBER := 0;
    rejected NUMBER;
    staged NUMBER;
    duplicate_ids NUMBER;
BEGIN
    SELECT * INTO run_row FROM import_run WHERE run_id = p_run_id FOR UPDATE;
    IF run_row.status <> 'RUNNING' THEN
        RAISE_APPLICATION_ERROR(-20020, 'Only a running import can be published');
    END IF;
    -- Serialize publishers for the same source across sessions.
    SELECT source_id INTO locked_source FROM data_source WHERE source_id = run_row.source_id FOR UPDATE;

    SELECT COUNT(*), COUNT(*) - COUNT(DISTINCT cve_id)
    INTO staged, duplicate_ids FROM stg_vulnerability WHERE run_id = p_run_id;
    SELECT COUNT(*) INTO rejected FROM import_reject WHERE run_id = p_run_id;
    IF duplicate_ids <> 0 OR staged + rejected <> run_row.retrieved_count THEN
        RAISE_APPLICATION_ERROR(-20021, 'Invalid staging counts or duplicate CVEs');
    END IF;

    FOR item IN (SELECT * FROM stg_vulnerability WHERE run_id = p_run_id ORDER BY cve_id) LOOP
        BEGIN
            SELECT vuln_id, source_id, last_modified_date, revision_hash
            INTO target_id, target_source, target_revision, target_hash
            FROM vulnerability WHERE cve_id = item.cve_id FOR UPDATE;
        EXCEPTION WHEN NO_DATA_FOUND THEN
            target_id := NULL;
        END;

        IF target_id IS NOT NULL THEN
            IF target_source <> run_row.source_id OR
                (target_revision = item.last_modified_date AND target_hash <> item.revision_hash)
            THEN
                INSERT INTO import_reject (run_id, row_locator, external_id, reason)
                VALUES (p_run_id, item.row_locator, item.cve_id, 'Conflicting source or same-time revision');
                rejected := rejected + 1;
                CONTINUE;
            END IF;
            IF target_revision >= item.last_modified_date THEN
                CONTINUE;
            END IF;

            UPDATE vulnerability
            SET description = item.description, cvss_version = item.cvss_version,
                cvss_score = item.cvss_score, cvss_source = item.cvss_source, severity = item.severity,
                published_date = item.published_date, last_modified_date = item.last_modified_date,
                revision_hash = item.revision_hash, nvd_status = item.nvd_status, last_applied_run_id = p_run_id
            WHERE vuln_id = target_id;
        ELSE
            INSERT INTO vulnerability (
                cve_id, description, cvss_version, cvss_score, cvss_source, severity, published_date,
                last_modified_date, revision_hash, nvd_status, source_id, last_applied_run_id)
            VALUES (
                item.cve_id, item.description, item.cvss_version, item.cvss_score, item.cvss_source,
                item.severity, item.published_date, item.last_modified_date, item.revision_hash,
                item.nvd_status, run_row.source_id, p_run_id)
            RETURNING vuln_id INTO target_id;
        END IF;

        DELETE FROM vuln_software WHERE config_id IN (
            SELECT config_id FROM applicability_config WHERE vuln_id = target_id);
        DELETE FROM applicability_config WHERE vuln_id = target_id;
        DELETE FROM reference_tag WHERE reference_id IN (
            SELECT reference_id FROM vuln_reference WHERE vuln_id = target_id);
        DELETE FROM vuln_reference WHERE vuln_id = target_id;

        INSERT INTO applicability_config (vuln_id, config_ordinal, original_config)
        SELECT target_id, config_ordinal, original_config FROM stg_app_config
        WHERE run_id = p_run_id AND row_locator = item.row_locator;

        MERGE INTO software s
        USING (
            SELECT DISTINCT cpe_part, cpe_vendor, cpe_product FROM stg_criterion
            WHERE run_id = p_run_id AND row_locator = item.row_locator
              AND cpe_part IS NOT NULL AND cpe_vendor IS NOT NULL AND cpe_product IS NOT NULL
        ) c ON (s.cpe_part = c.cpe_part AND s.cpe_vendor = c.cpe_vendor AND s.cpe_product = c.cpe_product)
        WHEN NOT MATCHED THEN INSERT (software_name, vendor, cpe_part, cpe_vendor, cpe_product)
        VALUES (c.cpe_product, c.cpe_vendor, c.cpe_part, c.cpe_vendor, c.cpe_product);

        INSERT INTO vuln_software (
            config_id, criterion_path, software_id, cpe_uri, match_criteria_id, vulnerable_flag,
            version_start_incl, version_start_excl, version_end_incl, version_end_excl)
        SELECT a.config_id, c.criterion_path, s.software_id, c.cpe_uri, c.match_criteria_id,
               c.vulnerable_flag, c.version_start_incl, c.version_start_excl,
               c.version_end_incl, c.version_end_excl
        FROM stg_criterion c
        JOIN applicability_config a ON a.vuln_id = target_id AND a.config_ordinal = c.config_ordinal
        LEFT JOIN software s ON s.cpe_part = c.cpe_part AND s.cpe_vendor = c.cpe_vendor
                           AND s.cpe_product = c.cpe_product
        WHERE c.run_id = p_run_id AND c.row_locator = item.row_locator;

        INSERT INTO vuln_reference (vuln_id, reference_url, reference_source)
        SELECT target_id, reference_url, reference_source FROM stg_reference
        WHERE run_id = p_run_id AND row_locator = item.row_locator;
        INSERT INTO reference_tag (reference_id, tag)
        SELECT r.reference_id, t.tag FROM stg_reference_tag t
        JOIN vuln_reference r ON r.vuln_id = target_id AND r.reference_url = t.reference_url
                             AND r.reference_source = t.reference_source
        WHERE t.run_id = p_run_id AND t.row_locator = item.row_locator;

        applied := applied + 1;
    END LOOP;

    UPDATE import_run
       SET status = 'SUCCEEDED', ended_at = SYS_EXTRACT_UTC(SYSTIMESTAMP),
           rejected_count = rejected, accepted_count = retrieved_count - rejected,
           applied_count = applied
     WHERE run_id = p_run_id;
EXCEPTION WHEN NO_DATA_FOUND THEN
    RAISE_APPLICATION_ERROR(-20022, 'Import run or its source does not exist');
END;
/
