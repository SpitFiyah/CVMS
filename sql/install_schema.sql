WHENEVER OSERROR EXIT FAILURE
WHENEVER SQLERROR EXIT SQL.SQLCODE ROLLBACK
SET DEFINE OFF

@@00_schema/01_create_tables.sql
@@01_sequences/01_create_sequences.sql
@@02_staging/01_create_staging_tables.sql
@@08_triggers/01_create_id_triggers.sql
@@06_views/01_create_views.sql
@@07_procedures/01_create_procedures.sql
@@07_procedures/02_publish_nvd_run.sql
@@08_triggers/02_create_history_trigger.sql

SELECT name, type, line, position, text FROM user_errors ORDER BY name, sequence;
DECLARE
    invalid_count NUMBER;
BEGIN
    SELECT COUNT(*) INTO invalid_count FROM user_objects WHERE status = 'INVALID';
    IF invalid_count > 0 THEN
        RAISE_APPLICATION_ERROR(-20001, 'Schema contains invalid objects');
    END IF;
END;
/
