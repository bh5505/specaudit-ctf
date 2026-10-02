-- Technique context is mapped only through an alert endpoint and an active
-- service endpoint. The view intentionally emits mapped provenance only;
-- consumers derive their own unmapped population with an anti-join.
CREATE VIEW IF NOT EXISTS ext_telecom_offsec_asmvm_vm_technique_context AS
SELECT DISTINCT
    a.run_id AS run_id,
    a.engagement_id AS engagement_id,
    s.ip AS ip,
    s.port AS port,
    s.service_endpoint_id AS service_ref,
    a.mitre_tactic AS mitre_tactic,
    a.mitre_technique AS mitre_technique,
    COALESCE(a.asr_rule, ae.asr_rule) AS asr_rule,
    CASE
        WHEN INSTR(',' || REPLACE(COALESCE(a.ipv4_list, ''), ' ', '') || ',',
                   ',' || ae.ip || ',') > 0 THEN 'alert_asserted_direct'
        ELSE 'alert_endpoint_bridged'
    END AS provenance_class,
    CASE
        WHEN INSTR(',' || REPLACE(COALESCE(a.ipv4_list, ''), ' ', '') || ',',
                   ',' || ae.ip || ',') > 0
            THEN 'alert address list contains the confirmed service address'
        ELSE 'alert endpoint bridge resolves the confirmed service address'
    END AS provenance_note
FROM ext_telecom_offsec_asmvm_alert a
JOIN ext_telecom_offsec_asmvm_alert_endpoint ae
  ON ae.run_id = a.run_id
 AND ae.engagement_id = a.engagement_id
 AND ae.alert_id = a.alert_id
JOIN ext_telecom_offsec_asmvm_service_endpoint s
  ON s.run_id = ae.run_id
 AND s.engagement_id = ae.engagement_id
 AND s.ip = ae.ip
WHERE a.mitre_technique IS NOT NULL
  AND TRIM(a.mitre_technique) <> ''
  AND CAST(a.is_active_state AS BOOLEAN)
  AND CAST(ae.is_active_state AS BOOLEAN)
  AND CAST(s.is_active AS BOOLEAN);
