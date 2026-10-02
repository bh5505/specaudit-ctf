-- ext_telecom_offsec_asmvm_t1_transport_security.sql - T1 (threat-model-first),
-- insecure-transport exposure observed from outside.
--
-- Attack-surface-rule firings in the vendor's insecure-transport categories
-- (clear-text logins / text protocols, weak or insecure cryptography) that are
-- still in an ACTIVE state (New / Reopened) in the ASM feed, grouped BY RULE.
-- The rule is the unit of work because the rule is the generalization that
-- compounds into the corpus (T6): one finding per rule, carrying the
-- population behind it, is what an auditor takes to the boundary owner.
--
-- Category list is CAP-PARAM: it mirrors engagement_configs/default.yaml
-- (insecure_transport_categories). Keep the literal list and the config in sync.
--
-- Tables: ext_telecom_offsec_asmvm_alert, ext_telecom_offsec_asmvm_alert_endpoint,
-- ext_telecom_offsec_asmvm_asm_vm_surface (ownership attribution),
-- ext_telecom_offsec_asmvm_vm_asset (is the address even managed?).
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'asmvm:transport:' || a.asr_rule                 AS finding_key,
    'Active insecure-transport rule firing: ' || a.asr_rule AS title,
    COUNT(DISTINCT ai.ip)                            AS affected_count,
    COUNT(*)                                         AS exposure_estimate,
    'asm:asr:' || a.asr_rule                         AS record_locator,
    'category=' || COALESCE(MIN(a.asr_category), '') ||
    '; alerts=' || CAST(COUNT(*) AS VARCHAR) ||
    '; active_alerts=' || CAST(COUNT(CASE WHEN CAST(a.is_active_state AS BOOLEAN) THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; ips=' || CAST(COUNT(DISTINCT ai.ip) AS VARCHAR) ||
    '; ips_not_in_vm_estate=' || CAST(COUNT(DISTINCT CASE WHEN v.ip IS NULL THEN ai.ip END) AS VARCHAR) ||
    '; ips_outside_owned_range=' || CAST(COUNT(DISTINCT CASE WHEN o.ip IS NULL THEN ai.ip END) AS VARCHAR) ||
    '; critical_alerts=' || CAST(COUNT(CASE WHEN a.severity = 'Critical' THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; high_alerts=' || CAST(COUNT(CASE WHEN a.severity = 'High' THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; mitre=' || COALESCE(MIN(a.mitre_tactic), '') || '/' || COALESCE(MIN(a.mitre_technique), '') ||
    '; sample_alert=' || MIN(a.alert_id) ||
    '; validation=live_probe_required'               AS details,
    a.run_id                                         AS run_id,
    -- Severity rank is derived from counts, never from string min/max: vendor
    -- severity labels are text and order alphabetically.
    CASE WHEN COUNT(CASE WHEN a.severity = 'Critical' THEN 1 ELSE NULL END) > 0 THEN 52
         WHEN COUNT(CASE WHEN a.severity = 'High' THEN 1 ELSE NULL END) > 0 THEN 48
         ELSE 34 END                                 AS risk_score
FROM ext_telecom_offsec_asmvm_alert a
JOIN ext_telecom_offsec_asmvm_alert_endpoint ai
    ON ai.alert_id = a.alert_id
   AND ai.run_id = a.run_id
LEFT JOIN ext_telecom_offsec_asmvm_vm_asset v
    ON v.ip = ai.ip
   AND v.run_id = a.run_id
LEFT JOIN ext_telecom_offsec_asmvm_asm_vm_surface o
    ON o.ip = ai.ip
   AND o.run_id = a.run_id
   AND CAST(o.inside_owned_range AS BOOLEAN)
WHERE a.run_id = ?1
  AND CAST(a.is_active_state AS BOOLEAN)
  AND a.asr_category IN ('Unencrypted Logins and Text Protocols',
                         'Weak or Insecure Cryptography')
GROUP BY a.asr_rule, a.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
