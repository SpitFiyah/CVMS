CREATE OR REPLACE TRIGGER au_remediation_history
AFTER UPDATE OF status ON remediation
FOR EACH ROW
WHEN (OLD.status <> NEW.status)
BEGIN
    INSERT INTO remediation_history (remediation_id, old_status, new_status, changed_by, remarks)
    VALUES (:NEW.remediation_id, :OLD.status, :NEW.status,
            remediation_workflow.history_actor(), remediation_workflow.history_remarks());
END;
/
