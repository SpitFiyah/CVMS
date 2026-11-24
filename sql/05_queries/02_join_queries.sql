-- 5. Asset findings for a selected CVE.
SELECT a.asset_name, f.status, f.verification_status
FROM vulnerability v
JOIN asset_vulnerability f ON f.vuln_id = v.vuln_id
JOIN asset a ON a.asset_id = f.asset_id
WHERE v.cve_id = '&cve_id'
ORDER BY a.asset_name;

-- 6. Inventory with assets that have no recorded installation.
SELECT a.asset_name, s.cpe_vendor, s.cpe_product, i.installation_slot, i.installed_version
FROM asset a
LEFT JOIN asset_software i ON i.asset_id = a.asset_id
LEFT JOIN software s ON s.software_id = i.software_id
ORDER BY a.asset_name, s.cpe_product, i.installation_slot;

-- 7. Projected vulnerable criteria for a selected software product.
SELECT v.cve_id, c.config_ordinal, vs.criterion_path, vs.cpe_uri,
       vs.version_start_incl, vs.version_start_excl, vs.version_end_incl, vs.version_end_excl
FROM software s
JOIN vuln_software vs ON vs.software_id = s.software_id
JOIN applicability_config c ON c.config_id = vs.config_id
JOIN vulnerability v ON v.vuln_id = c.vuln_id
WHERE s.cpe_part = '&cpe_part' AND s.cpe_vendor = '&cpe_vendor'
  AND s.cpe_product = '&cpe_product' AND vs.vulnerable_flag = 'Y'
ORDER BY v.cve_id, c.config_ordinal, vs.criterion_path;

-- 8. Analyst assignments and tasks, including unassigned tasks.
SELECT r.remediation_id, v.cve_id, a.analyst_name, r.assigned_date, r.due_date, r.status
FROM remediation r
LEFT JOIN analyst a ON a.analyst_id = r.analyst_id
JOIN asset_vulnerability f ON f.asset_vuln_id = r.asset_vuln_id
JOIN vulnerability v ON v.vuln_id = f.vuln_id
ORDER BY a.analyst_name NULLS LAST, r.due_date NULLS LAST, r.remediation_id;
