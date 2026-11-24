WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
MERGE INTO data_source target
USING (SELECT 'NVD' AS source_name,
              'https://services.nvd.nist.gov/rest/json/cves/2.0' AS source_url FROM dual) source
ON (target.source_name = source.source_name)
WHEN NOT MATCHED THEN INSERT (source_name, source_url)
VALUES (source.source_name, source.source_url);
COMMIT;
