-- 13. Scores above the overall arithmetic mean of stored scores.
SELECT cve_id, cvss_version, cvss_score FROM vulnerability
WHERE cvss_score > (SELECT AVG(cvss_score) FROM vulnerability)
ORDER BY cvss_score DESC, cve_id;

-- 14. Assets without findings.
SELECT a.asset_name FROM asset a
WHERE NOT EXISTS (SELECT 1 FROM asset_vulnerability f WHERE f.asset_id = a.asset_id)
ORDER BY a.asset_name;

-- 15. Analysts without assigned tasks.
SELECT a.analyst_name, a.email FROM analyst a
WHERE NOT EXISTS (SELECT 1 FROM remediation r WHERE r.analyst_id = a.analyst_id)
ORDER BY a.analyst_name, a.email;

-- 16. Unresolved findings without remediation tasks.
SELECT f.asset_name, f.cve_id, f.verification_status
FROM v_unresolved_vulnerabilities f
WHERE NOT EXISTS (SELECT 1 FROM remediation r WHERE r.asset_vuln_id = f.asset_vuln_id)
ORDER BY f.asset_name, f.cve_id;
