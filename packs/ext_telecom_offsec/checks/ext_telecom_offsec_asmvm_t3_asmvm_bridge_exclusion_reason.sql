-- Explain why alert/service candidates do not enter the technique-context view.
-- Bound params: ?1 = run_id, ?2 = row limit.

WITH candidate_spine AS (
    SELECT
        s.run_id,
        s.engagement_id,
        s.ip,
        s.port,
        a.mitre_technique,
        CASE WHEN a.is_active_state THEN 1 ELSE 0 END AS alert_active,
        CASE WHEN ae.is_active_state THEN 1 ELSE 0 END AS endpoint_active,
        CASE WHEN s.is_active THEN 1 ELSE 0 END AS service_active,
        1 AS service_present
    FROM ext_telecom_offsec_asmvm_alert a
    JOIN ext_telecom_offsec_asmvm_alert_endpoint ae
      ON ae.run_id = a.run_id
     AND ae.engagement_id = a.engagement_id
     AND ae.alert_id = a.alert_id
    JOIN ext_telecom_offsec_asmvm_service_endpoint s
      ON s.run_id = ae.run_id
     AND s.engagement_id = ae.engagement_id
     AND s.ip = ae.ip
    WHERE a.run_id = ?1
      AND (
          (a.mitre_technique IS NOT NULL AND TRIM(a.mitre_technique) <> '')
          OR
          (a.is_active_state AND ae.is_active_state AND s.is_active)
      )

    UNION ALL

    SELECT
        a.run_id,
        a.engagement_id,
        ae.ip,
        NULL AS port,
        a.mitre_technique,
        CASE WHEN a.is_active_state THEN 1 ELSE 0 END AS alert_active,
        CASE WHEN ae.is_active_state THEN 1 ELSE 0 END AS endpoint_active,
        0 AS service_active,
        0 AS service_present
    FROM ext_telecom_offsec_asmvm_alert a
    JOIN ext_telecom_offsec_asmvm_alert_endpoint ae
      ON ae.run_id = a.run_id
     AND ae.engagement_id = a.engagement_id
     AND ae.alert_id = a.alert_id
    WHERE a.run_id = ?1
      AND a.mitre_technique IS NOT NULL
      AND TRIM(a.mitre_technique) <> ''
      AND NOT EXISTS (
          SELECT 1
          FROM ext_telecom_offsec_asmvm_service_endpoint s
          WHERE s.run_id = ae.run_id
            AND s.engagement_id = ae.engagement_id
            AND s.ip = ae.ip
      )
),
unmapped AS (
    SELECT c.*
    FROM candidate_spine c
    WHERE NOT EXISTS (
        SELECT 1
        FROM ext_telecom_offsec_asmvm_vm_technique_context m
        WHERE m.run_id = c.run_id
          AND m.engagement_id = c.engagement_id
          AND m.ip = c.ip
          AND (m.port = c.port OR (m.port IS NULL AND c.port IS NULL))
    )
),
classified AS (
    SELECT u.*, 'no_alert_coverage' AS reason_class
    FROM unmapped u
    WHERE u.service_present = 1
      AND (u.mitre_technique IS NULL OR TRIM(u.mitre_technique) = '')

    UNION ALL

    SELECT u.*, 'inactive_state_only' AS reason_class
    FROM unmapped u
    WHERE u.mitre_technique IS NOT NULL
      AND TRIM(u.mitre_technique) <> ''
      AND (u.alert_active = 0 OR u.endpoint_active = 0)

    UNION ALL

    SELECT u.*, 'endpoint_absent' AS reason_class
    FROM unmapped u
    WHERE u.mitre_technique IS NOT NULL
      AND TRIM(u.mitre_technique) <> ''
      AND u.service_active = 0
      AND u.alert_active = 1
      AND u.endpoint_active = 1

    UNION ALL

    SELECT u.*, 'unclassified' AS reason_class
    FROM unmapped u
    WHERE NOT (
        (u.service_present = 1 AND
         (u.mitre_technique IS NULL OR TRIM(u.mitre_technique) = ''))
        OR
        (u.mitre_technique IS NOT NULL AND TRIM(u.mitre_technique) <> '' AND
         (u.alert_active = 0 OR u.endpoint_active = 0))
        OR
        (u.mitre_technique IS NOT NULL AND TRIM(u.mitre_technique) <> '' AND
         u.service_active = 0 AND u.alert_active = 1 AND u.endpoint_active = 1)
    )
)
SELECT
    'asmvm:bridge-exclusion:' || c.ip || ':' ||
        COALESCE(CAST(c.port AS VARCHAR), 'unknown') || ':' ||
        c.reason_class AS finding_key,
    'Technique bridge exclusion for ' || c.ip || ':' ||
        COALESCE(CAST(c.port AS VARCHAR), 'unknown') ||
        ' (' || c.reason_class || ')' AS title,
    CAST(COUNT(*) AS BIGINT) AS affected_count,
    1 AS exposure_estimate,
    c.ip || ':' || COALESCE(CAST(c.port AS VARCHAR), 'unknown') AS record_locator,
    'reason=' || c.reason_class ||
    '; alert_active_min=' || CAST(MIN(c.alert_active) AS VARCHAR) ||
    '; alert_active_max=' || CAST(MAX(c.alert_active) AS VARCHAR) ||
    '; endpoint_active_min=' || CAST(MIN(c.endpoint_active) AS VARCHAR) ||
    '; endpoint_active_max=' || CAST(MAX(c.endpoint_active) AS VARCHAR) ||
    '; service_active_min=' || CAST(MIN(c.service_active) AS VARCHAR) ||
    '; service_active_max=' || CAST(MAX(c.service_active) AS VARCHAR) ||
    '; mitre_nullability=' ||
        CASE
            WHEN MIN(CASE WHEN c.mitre_technique IS NULL OR TRIM(c.mitre_technique) = '' THEN 1 ELSE 0 END) = 1
                THEN 'null_or_blank'
            WHEN MAX(CASE WHEN c.mitre_technique IS NULL OR TRIM(c.mitre_technique) = '' THEN 1 ELSE 0 END) = 0
                THEN 'present'
            ELSE 'mixed'
        END AS details,
    c.run_id AS run_id,
    40 AS risk_score
FROM classified c
GROUP BY c.run_id, c.ip, c.port, c.reason_class
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
