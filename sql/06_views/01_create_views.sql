CREATE OR REPLACE VIEW v_critical_vulnerabilities AS
SELECT v.vuln_id, v.cve_id, v.cvss_score, v.cvss_version, v.published_date,
       s.software_id, s.software_name, s.vendor, s.cpe_vendor, s.cpe_product
FROM vulnerability v
LEFT JOIN (
    SELECT DISTINCT c.vuln_id, vs.software_id
    FROM applicability_config c
    JOIN vuln_software vs ON vs.config_id = c.config_id
    WHERE vs.vulnerable_flag = 'Y' AND vs.software_id IS NOT NULL
) product ON product.vuln_id = v.vuln_id
LEFT JOIN software s ON s.software_id = product.software_id
WHERE v.severity = 'CRITICAL';

CREATE OR REPLACE VIEW v_unresolved_vulnerabilities AS
SELECT f.asset_vuln_id, f.asset_id, a.asset_name, a.environment,
       v.cve_id, v.severity, v.cvss_score, v.cvss_version,
       f.status, f.verification_status, f.detected_date
FROM asset_vulnerability f
JOIN asset a ON a.asset_id = f.asset_id
JOIN vulnerability v ON v.vuln_id = f.vuln_id
WHERE f.status IN ('OPEN', 'IN_PROGRESS');

CREATE OR REPLACE VIEW v_remediation_summary AS
SELECT r.remediation_id, r.asset_vuln_id, f.asset_id, v.cve_id,
       r.analyst_id, a.analyst_name, r.action_taken, r.status,
       r.assigned_date, r.due_date, r.completion_date,
       CASE WHEN r.status <> 'COMPLETED' AND r.due_date < TRUNC(SYSDATE)
            THEN 1 ELSE 0 END AS is_overdue
FROM remediation r
JOIN asset_vulnerability f ON f.asset_vuln_id = r.asset_vuln_id
JOIN vulnerability v ON v.vuln_id = f.vuln_id
LEFT JOIN analyst a ON a.analyst_id = r.analyst_id;

CREATE OR REPLACE VIEW v_asset_risk_summary AS
SELECT a.asset_id, a.asset_name, a.environment,
       NVL(f.total_findings, 0) AS total_findings,
       NVL(f.critical_findings, 0) AS critical_findings,
       NVL(f.high_findings, 0) AS high_findings,
       NVL(f.unresolved_findings, 0) AS unresolved_findings,
       NVL(f.pending_review, 0) AS pending_review,
       NVL(r.open_tasks, 0) AS open_tasks, NVL(r.overdue_tasks, 0) AS overdue_tasks
FROM asset a
LEFT JOIN (
    SELECT f.asset_id, COUNT(*) AS total_findings,
           SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_findings,
           SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) AS high_findings,
           SUM(CASE WHEN f.status IN ('OPEN','IN_PROGRESS') THEN 1 ELSE 0 END) AS unresolved_findings,
           SUM(CASE WHEN f.verification_status = 'PENDING' THEN 1 ELSE 0 END) AS pending_review
    FROM asset_vulnerability f
    JOIN vulnerability v ON v.vuln_id = f.vuln_id
    GROUP BY f.asset_id
) f ON f.asset_id = a.asset_id
LEFT JOIN (
    SELECT asset_id, SUM(CASE WHEN status <> 'COMPLETED' THEN 1 ELSE 0 END) AS open_tasks,
           SUM(is_overdue) AS overdue_tasks
    FROM v_remediation_summary
    GROUP BY asset_id
) r ON r.asset_id = a.asset_id;

CREATE OR REPLACE VIEW v_analyst_workload AS
SELECT a.analyst_id, a.analyst_name, COUNT(r.remediation_id) AS assigned_tasks,
       SUM(CASE WHEN r.status <> 'COMPLETED' THEN 1 ELSE 0 END) AS open_tasks,
       NVL(SUM(r.is_overdue), 0) AS overdue_tasks
FROM analyst a
LEFT JOIN v_remediation_summary r ON r.analyst_id = a.analyst_id
GROUP BY a.analyst_id, a.analyst_name;
