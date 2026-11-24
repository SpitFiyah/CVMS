CREATE OR REPLACE PROCEDURE assign_analyst (
    p_remediation_id IN remediation.remediation_id%TYPE,
    p_analyst_id IN analyst.analyst_id%TYPE
) AS
    existing_analyst analyst.analyst_id%TYPE;
BEGIN
    SELECT analyst_id INTO existing_analyst FROM analyst WHERE analyst_id = p_analyst_id;
    UPDATE remediation
       SET assigned_date = CASE WHEN analyst_id = p_analyst_id THEN assigned_date ELSE SYSDATE END,
           analyst_id = p_analyst_id
     WHERE remediation_id = p_remediation_id;
    IF SQL%ROWCOUNT = 0 THEN
        RAISE_APPLICATION_ERROR(-20011, 'Remediation task does not exist');
    END IF;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        RAISE_APPLICATION_ERROR(-20010, 'Analyst does not exist');
END;
/

CREATE OR REPLACE PACKAGE remediation_workflow AS
    PROCEDURE update_status (
        p_remediation_id IN remediation.remediation_id%TYPE,
        p_status IN remediation.status%TYPE,
        p_changed_by IN analyst.analyst_id%TYPE DEFAULT NULL,
        p_remarks IN remediation_history.remarks%TYPE DEFAULT NULL
    );
    FUNCTION history_actor RETURN NUMBER;
    FUNCTION history_remarks RETURN VARCHAR2;
END remediation_workflow;
/

CREATE OR REPLACE PACKAGE BODY remediation_workflow AS
    actor analyst.analyst_id%TYPE;
    remarks remediation_history.remarks%TYPE;

    FUNCTION history_actor RETURN NUMBER IS
    BEGIN
        RETURN actor;
    END;

    FUNCTION history_remarks RETURN VARCHAR2 IS
    BEGIN
        RETURN remarks;
    END;

    PROCEDURE update_status (
        p_remediation_id IN remediation.remediation_id%TYPE,
        p_status IN remediation.status%TYPE,
        p_changed_by IN analyst.analyst_id%TYPE DEFAULT NULL,
        p_remarks IN remediation_history.remarks%TYPE DEFAULT NULL
    ) IS
        current_status remediation.status%TYPE;
    BEGIN
        IF p_status IS NULL OR p_status NOT IN ('PENDING','IN_PROGRESS','COMPLETED','BLOCKED') THEN
            RAISE_APPLICATION_ERROR(-20012, 'Unsupported remediation status');
        END IF;
        SELECT status INTO current_status FROM remediation
        WHERE remediation_id = p_remediation_id FOR UPDATE;
        IF p_status = current_status THEN
            RETURN;
        END IF;
        IF NOT (
            (current_status = 'PENDING' AND p_status IN ('IN_PROGRESS','BLOCKED'))
            OR (current_status = 'IN_PROGRESS' AND p_status IN ('BLOCKED','COMPLETED'))
            OR (current_status = 'BLOCKED' AND p_status = 'IN_PROGRESS')
        ) THEN
            RAISE_APPLICATION_ERROR(-20013, 'Invalid remediation status transition');
        END IF;
        IF p_changed_by IS NOT NULL THEN
            BEGIN
                SELECT analyst_id INTO actor FROM analyst WHERE analyst_id = p_changed_by;
            EXCEPTION
                WHEN NO_DATA_FOUND THEN
                    RAISE_APPLICATION_ERROR(-20010, 'Status change analyst does not exist');
            END;
        END IF;
        remarks := p_remarks;
        UPDATE remediation
           SET status = p_status,
               completion_date = CASE WHEN p_status = 'COMPLETED' THEN SYSDATE END
         WHERE remediation_id = p_remediation_id;
        actor := NULL;
        remarks := NULL;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            actor := NULL;
            remarks := NULL;
            RAISE_APPLICATION_ERROR(-20011, 'Remediation task does not exist');
        WHEN OTHERS THEN
            actor := NULL;
            remarks := NULL;
            RAISE;
    END;
END remediation_workflow;
/

CREATE OR REPLACE PROCEDURE update_remediation_status (
    p_remediation_id IN remediation.remediation_id%TYPE,
    p_status IN remediation.status%TYPE,
    p_changed_by IN analyst.analyst_id%TYPE DEFAULT NULL,
    p_remarks IN remediation_history.remarks%TYPE DEFAULT NULL
) AS
BEGIN
    remediation_workflow.update_status(p_remediation_id, p_status, p_changed_by, p_remarks);
END;
/

CREATE OR REPLACE PROCEDURE generate_asset_risk_summary (
    p_asset_id IN asset.asset_id%TYPE,
    p_summary OUT SYS_REFCURSOR
) AS
    existing_asset asset.asset_id%TYPE;
BEGIN
    SELECT asset_id INTO existing_asset FROM asset WHERE asset_id = p_asset_id;
    OPEN p_summary FOR SELECT * FROM v_asset_risk_summary WHERE asset_id = p_asset_id;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        RAISE_APPLICATION_ERROR(-20014, 'Asset does not exist');
END;
/
