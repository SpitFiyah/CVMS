WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
SET DEFINE OFF

-- Fictional Northbridge Research inventory includes documentation-only IPs.
MERGE INTO asset a
USING (
    SELECT 'demo-mail-prod' asset_name, 'SERVER' asset_type, '192.0.2.10' ip_address,
           'Operations' department, 'PRODUCTION' environment FROM dual
    UNION ALL SELECT 'demo-mail-archive', 'SERVER', '192.0.2.11', 'Operations', 'DEVELOPMENT' FROM dual
    UNION ALL SELECT 'demo-mail-lab', 'SERVER', '192.0.2.12', 'Engineering', 'DEVELOPMENT' FROM dual
    UNION ALL SELECT 'demo-web-prod', 'WEB_SERVER', '192.0.2.20', 'Engineering', 'PRODUCTION' FROM dual
    UNION ALL SELECT 'demo-db-prod', 'DATABASE_SERVER', '192.0.2.21', 'Operations', 'PRODUCTION' FROM dual
    UNION ALL SELECT 'demo-db-dev', 'DATABASE_SERVER', '192.0.2.22', 'Engineering', 'DEVELOPMENT' FROM dual
    UNION ALL SELECT 'demo-finance-01', 'WORKSTATION', '192.0.2.30', 'Finance', 'PRODUCTION' FROM dual
    UNION ALL SELECT 'demo-finance-02', 'WORKSTATION', '192.0.2.31', 'Finance', 'PRODUCTION' FROM dual
) seed ON (a.asset_name = seed.asset_name)
WHEN NOT MATCHED THEN INSERT (asset_name, asset_type, ip_address, department, environment)
VALUES (seed.asset_name, seed.asset_type, seed.ip_address, seed.department, seed.environment);

MERGE INTO analyst a
USING (
    SELECT 'Avery Cole' analyst_name, 'avery.cole@example.invalid' email,
           'Infrastructure' specialization FROM dual
    UNION ALL SELECT 'Samira Rao', 'samira.rao@example.invalid', 'Application security' FROM dual
    UNION ALL SELECT 'Morgan Iyer', 'morgan.iyer@example.invalid', 'Risk review' FROM dual
) seed ON (a.email = seed.email)
WHEN NOT MATCHED THEN INSERT (analyst_name, email, specialization)
VALUES (seed.analyst_name, seed.email, seed.specialization);

DECLARE
    cv_id NUMBER;
    run_id NUMBER;
    product_id NUMBER;
    analyst_key NUMBER;
    finding_id NUMBER;
    task_id NUMBER;
    reviewed_at TIMESTAMP(3);
    exact_cpe CONSTANT VARCHAR2(100) := 'cpe:2.3:a:eric_allman:sendmail:5.58:*:*:*:*:*:*:*';
BEGIN
    -- This evidence was reviewed against the bundled source revision. A newer
    -- revision requires review before a new verified finding can be recorded.
    SELECT v.vuln_id, v.last_applied_run_id, c.software_id
      INTO cv_id, run_id, product_id
    FROM vulnerability v
    JOIN applicability_config a ON a.vuln_id = v.vuln_id AND a.config_ordinal = 0
    JOIN vuln_software c ON c.config_id = a.config_id
    WHERE v.cve_id = 'CVE-1999-0095'
      AND v.revision_hash = 'e90946c7c5591dcd176cd6b782f4eb13fe6ec1a94c9f38bf993e697f410ab94a'
      AND c.criterion_path = '/nodes/0/cpeMatch/0'
      AND c.cpe_uri = exact_cpe
      AND c.vulnerable_flag = 'Y'
      AND c.software_id IS NOT NULL;

    INSERT INTO asset_software (asset_id, software_id, installation_slot, installed_version, observed_cpe)
    SELECT a.asset_id, product_id, 'mail-service', '5.58', exact_cpe FROM asset a
    WHERE a.asset_name IN ('demo-mail-prod', 'demo-mail-archive')
      AND NOT EXISTS (
          SELECT 1 FROM asset_software i WHERE i.asset_id = a.asset_id
          AND i.software_id = product_id AND i.installation_slot = 'mail-service'
      );

    SELECT analyst_id INTO analyst_key FROM analyst WHERE email = 'avery.cole@example.invalid';

    FOR installed IN (
        SELECT a.asset_id FROM asset a JOIN asset_software i ON i.asset_id = a.asset_id
        WHERE a.asset_name IN ('demo-mail-prod', 'demo-mail-archive')
          AND i.software_id = product_id AND i.installed_version = '5.58' AND i.observed_cpe = exact_cpe
          AND NOT EXISTS (
              SELECT 1 FROM asset_vulnerability f WHERE f.asset_id = a.asset_id AND f.vuln_id = cv_id
          )
    ) LOOP
        reviewed_at := SYS_EXTRACT_UTC(SYSTIMESTAMP);
        INSERT INTO asset_vulnerability
            (asset_id, vuln_id, detected_date, verification_status, last_verified_date)
        VALUES (installed.asset_id, cv_id, reviewed_at, 'VERIFIED', reviewed_at)
        RETURNING asset_vuln_id INTO finding_id;

        INSERT INTO finding_evidence (asset_vuln_id, run_id, reviewed_by, source_locator,
                                      inventory_snapshot, disposition, explanation)
        VALUES (finding_id, run_id, analyst_key,
                'cves-00000000.json#/vulnerabilities/0/cve/configurations/0/nodes/0/cpeMatch/0',
                'Fictional mail-service inventory CPE ' || exact_cpe, 'VERIFIED',
                'The archived configuration has one non-negated OR node with one vulnerable exact CPE criterion and no additional predicates.');

        INSERT INTO remediation (asset_vuln_id, action_taken, due_date)
        VALUES (finding_id, 'Replace the legacy mail service with a supported release and re-review the finding.',
                TRUNC(SYSDATE) + 7)
        RETURNING remediation_id INTO task_id;
        assign_analyst(task_id, analyst_key);
    END LOOP;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        RAISE_APPLICATION_ERROR(-20030, 'Load the reviewed demo snapshot before seeding fictional findings');
END;
/
COMMIT;
