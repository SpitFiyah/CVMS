-- 9. Assets ordered by verified unresolved exposure.
SELECT a.asset_name, COUNT(f.asset_vuln_id) AS verified_unresolved
FROM asset a
LEFT JOIN v_unresolved_vulnerabilities f
  ON f.asset_id = a.asset_id AND f.verification_status = 'VERIFIED'
GROUP BY a.asset_id, a.asset_name
ORDER BY verified_unresolved DESC, a.asset_name;

-- 10. Count each scored CVE once per vendor and group by CVSS version.
WITH vendor_cve AS (
    SELECT DISTINCT s.cpe_vendor, c.vuln_id
    FROM software s
    JOIN vuln_software vs ON vs.software_id = s.software_id
    JOIN applicability_config c ON c.config_id = vs.config_id
    WHERE vs.vulnerable_flag = 'Y'
)
SELECT x.cpe_vendor, v.cvss_version, ROUND(AVG(v.cvss_score), 2) AS avg_cvss,
       COUNT(v.cvss_score) AS scored_cves
FROM vendor_cve x JOIN vulnerability v ON v.vuln_id = x.vuln_id
WHERE v.cvss_score IS NOT NULL
GROUP BY x.cpe_vendor, v.cvss_version
ORDER BY x.cpe_vendor, v.cvss_version;

-- 11. Assets with more than five unresolved findings, including pending review.
SELECT asset_name, COUNT(*) AS unresolved_findings FROM v_unresolved_vulnerabilities
GROUP BY asset_id, asset_name HAVING COUNT(*) > 5
ORDER BY unresolved_findings DESC, asset_name;

-- 12. Task completion rates by department.
SELECT NVL(a.department, 'UNSPECIFIED') AS department, COUNT(*) AS task_count,
       ROUND(100 * AVG(CASE WHEN r.status = 'COMPLETED' THEN 1 ELSE 0 END), 1)
           AS completion_pct
FROM v_remediation_summary r JOIN asset a ON a.asset_id = r.asset_id
GROUP BY NVL(a.department, 'UNSPECIFIED')
ORDER BY department;
