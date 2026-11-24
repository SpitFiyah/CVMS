-- 1. Critical vulnerability records.
SELECT cve_id, cvss_version, cvss_score, published_date
FROM vulnerability WHERE severity = 'CRITICAL'
ORDER BY cvss_score DESC NULLS LAST, cve_id;

-- 2. CVEs with a vulnerable criterion for the requested canonical vendor.
SELECT v.cve_id, v.nvd_status
FROM vulnerability v
WHERE EXISTS (
    SELECT 1 FROM applicability_config c
    JOIN vuln_software vs ON vs.config_id = c.config_id
    JOIN software s ON s.software_id = vs.software_id
    WHERE c.vuln_id = v.vuln_id AND vs.vulnerable_flag = 'Y'
      AND s.cpe_vendor = '&cpe_vendor'
)
ORDER BY v.cve_id;

-- 3. Preserve a separate bucket for absent severity.
SELECT NVL(severity, 'UNSCORED') AS severity, COUNT(*) AS cve_count
FROM vulnerability GROUP BY NVL(severity, 'UNSCORED')
ORDER BY cve_count DESC, severity;

-- 4. CVEs published during the previous 30 days.
SELECT cve_id, published_date, nvd_status FROM vulnerability
WHERE published_date >= SYS_EXTRACT_UTC(SYSTIMESTAMP) - INTERVAL '30' DAY
ORDER BY published_date DESC, cve_id;
