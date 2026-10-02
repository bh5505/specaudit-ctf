-- ext_telecom_offsec_asmvm_t6_rule_corpus.sql - T6 (rule corpus as the compounding
-- asset). Flags finding candidates whose rule reference is empty or does not
-- resolve to an ACTIVE generalized rule, i.e. exploratory gaps that have not
-- compounded into detection/prevention coverage.
-- Bound params: ?1 = run_id, ?2 = row limit.
--
-- INHERITED CHECK: re-expressed from ext_telecom_cyber/checks/ext_telecom_t6_rule_corpus.sql unchanged
-- in logic, retargeted to this pack's own ledger tables (ext_telecom_offsec_asmvm_finding_candidate + ext_telecom_offsec_asmvm_rule). The
-- ASM/VM pack owns its evidence/candidate/rule/run ledger so it loads and runs
-- standalone; running it here keeps the process controls (adversarial
-- validation, evidence gates, dedupe, sandboxing, rule corpus, resumability)
-- enforced over the ASM/VM evidence instead of only over the AWS posture pack.
-- Booleans are CAST explicitly so the SQL stays valid under the CSV loopback
-- runner, which types an all-true/all-false column as INTEGER.

SELECT
    'asmvm:ungeneralized:' || COALESCE(NULLIF(TRIM(c.rule_id), ''), 'none') || ':' || c.candidate_id AS finding_key,
    'Finding candidate without active generalized rule: ' || c.candidate_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    c.candidate_id || ' / ' || COALESCE(c.check_id, '') || ' / ' || COALESCE(NULLIF(TRIM(c.rule_id), ''), '') AS record_locator,
    'rule_id=' || COALESCE(NULLIF(TRIM(c.rule_id), ''), '') ||
    '; llm_verdict=' || COALESCE(c.llm_verdict, '') ||
    '; finding_key=' || COALESCE(c.finding_key, '') AS details,
    c.run_id AS run_id,
    30 AS risk_score
FROM ext_telecom_offsec_asmvm_finding_candidate c
LEFT JOIN ext_telecom_offsec_asmvm_rule r
    ON r.rule_id = c.rule_id
    AND NULLIF(TRIM(c.rule_id), '') IS NOT NULL
    AND CAST(r.active AS BOOLEAN) = true
    AND r.run_id = ?1
WHERE c.run_id = ?1
  AND (
    NULLIF(TRIM(c.rule_id), '') IS NULL
    OR r.rule_id IS NULL
  )
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
