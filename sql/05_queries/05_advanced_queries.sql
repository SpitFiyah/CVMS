-- 17. Rank exposure by unresolved findings and overdue work, retaining ties.
SELECT asset_name, unresolved_findings, overdue_tasks, pending_review,
       DENSE_RANK() OVER (ORDER BY unresolved_findings DESC, overdue_tasks DESC) AS exposure_rank
FROM v_asset_risk_summary
ORDER BY exposure_rank, asset_name;

-- 18. Critical open findings in production, including verification state.
SELECT asset_name, cve_id, cvss_version, cvss_score, verification_status
FROM v_unresolved_vulnerabilities
WHERE environment = 'PRODUCTION' AND severity = 'CRITICAL'
ORDER BY asset_name, cve_id;

-- 19. Incomplete tasks past their calendar due date.
SELECT remediation_id, cve_id, analyst_name, status, due_date,
       TRUNC(SYSDATE) - TRUNC(due_date) AS days_overdue
FROM v_remediation_summary WHERE is_overdue = 1
ORDER BY days_overdue DESC, remediation_id;

-- 20. Portfolio summary with independent counts at their own grains.
SELECT
    (SELECT COUNT(*) FROM vulnerability) AS cves,
    (SELECT COUNT(*) FROM vulnerability WHERE severity = 'CRITICAL') AS critical_cves,
    (SELECT COUNT(*) FROM asset) AS assets,
    (SELECT COUNT(*) FROM asset_vulnerability) AS findings,
    (SELECT COUNT(*) FROM v_unresolved_vulnerabilities) AS unresolved_findings,
    (SELECT COUNT(*) FROM v_unresolved_vulnerabilities
        WHERE verification_status = 'PENDING') AS unresolved_pending_review,
    (SELECT COUNT(*) FROM v_remediation_summary WHERE is_overdue = 1) AS overdue_tasks
FROM dual;
