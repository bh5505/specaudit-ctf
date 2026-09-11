-- ext_telecom_t6_rule_corpus.sql - method T6 (rule corpus as the compounding
-- asset). Flags finding candidates whose rule reference is empty or does not
-- resolve to an ACTIVE generalized rule, i.e. exploratory gaps that have not
-- compounded into detection/prevention coverage.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'ungeneralized:' || COALESCE(NULLIF(TRIM(c.rule_id), ''), 'none') || ':' || c.candidate_id AS finding_key,
    'Finding candidate without active generalized rule: ' || c.candidate_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    c.candidate_id || ' / ' || COALESCE(c.check_id, '') || ' / ' || COALESCE(NULLIF(TRIM(c.rule_id), ''), '') AS record_locator,
    'rule_id=' || COALESCE(NULLIF(TRIM(c.rule_id), ''), '') ||
    '; llm_verdict=' || COALESCE(c.llm_verdict, '') ||
    '; finding_key=' || COALESCE(c.finding_key, '') AS details,
    c.run_id AS run_id,
    30 AS risk_score
FROM gw_silver_ext_telecom_finding_candidate c
LEFT JOIN gw_silver_ext_telecom_rule r
    ON r.rule_id = c.rule_id
    AND NULLIF(TRIM(c.rule_id), '') IS NOT NULL
    AND r.active = true
    AND r.run_id = ?1
WHERE c.run_id = ?1
  AND (
    NULLIF(TRIM(c.rule_id), '') IS NULL
    OR r.rule_id IS NULL
  )
ORDER BY finding_key
LIMIT ?2;
