-- ext_telecom_offsec_asmvm_t6_asmvm_rule_corpus_gap.sql - T6 (the rule corpus is
-- the compounding asset).
--
-- Every open vulnerability-management finding class (scanner plugin family) is
-- matched against the generalized rule corpus deployed for this engagement - the
-- ASM attack-surface rules plus any scanner-family rules the engagement has
-- written down. A family with no ACTIVE rule is detection that is re-derived
-- from scratch every cycle instead of compounding into prevention coverage:
-- next cycle the auditor rediscovers the same class at the same cost.
--
-- One row per finding class, sized by open findings and IP count, so the corpus
-- work can be prioritised by exposure instead of by whichever family was seen
-- first. Rules are collapsed to one row per class before joining findings,
-- so several rule versions cannot multiply affected_count. rule_state distinguishes "the corpus has no entry for this class"
-- (absent) from "someone proposed a rule and it is not deployed" (inactive).
--
-- Tables: ext_telecom_offsec_asmvm_vm_finding, ext_telecom_offsec_asmvm_rule.
-- Bound params: ?1 = run_id, ?2 = row limit.

WITH rules_by_class AS (
    SELECT run_id, rule_name,
           MAX(CASE WHEN CAST(active AS BOOLEAN) THEN 1 ELSE 0 END) AS has_active,
           MIN(CASE WHEN COALESCE(CAST(active AS BOOLEAN), false) = false
                    THEN rule_id ELSE NULL END) AS inactive_rule_id
    FROM ext_telecom_offsec_asmvm_rule
    WHERE run_id = ?1
    GROUP BY run_id, rule_name
)
SELECT
    'asmvm:rule-gap:' || COALESCE(f.plugin_family, 'unknown') AS finding_key,
    'Open finding class without active generalized rule: ' ||
        COALESCE(f.plugin_family, 'unknown')         AS title,
    COUNT(*)                                        AS affected_count,
    COUNT(DISTINCT f.ip)                            AS exposure_estimate,
    'scanner-family:' || COALESCE(f.plugin_family, 'unknown') AS record_locator,
    'open_findings=' || CAST(COUNT(*) AS VARCHAR) ||
    '; ips=' || CAST(COUNT(DISTINCT f.ip) AS VARCHAR) ||
    '; critical_findings=' || CAST(COUNT(CASE WHEN f.severity >= 9.0 THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; max_severity=' || CAST(ROUND(COALESCE(MAX(f.severity), 0), 2) AS VARCHAR) ||
    '; qids=' || CAST(COUNT(DISTINCT f.qid) AS VARCHAR) ||
    '; rule_state=' || CASE WHEN MIN(r.rule_name) IS NULL THEN 'absent' ELSE 'inactive' END ||
    '; rule_id=' || COALESCE(MIN(r.inactive_rule_id), '') ||
    '; sample_finding=' || MIN(f.finding_id)        AS details,
    f.run_id                                        AS run_id,
    CASE WHEN COUNT(CASE WHEN f.severity >= 9.0 THEN 1 ELSE NULL END) > 0 THEN 34
         ELSE 30 END                                AS risk_score
FROM ext_telecom_offsec_asmvm_vm_finding f
LEFT JOIN rules_by_class r
    ON r.rule_name = COALESCE(f.plugin_family, 'unknown')
   AND r.run_id = f.run_id
WHERE f.run_id = ?1
  AND CAST(f.is_open AS BOOLEAN)
  AND COALESCE(r.has_active, 0) = 0
GROUP BY COALESCE(f.plugin_family, 'unknown'), f.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
