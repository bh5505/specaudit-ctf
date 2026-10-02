-- ext_telecom_offsec_aws_t3_evidence_gate.sql - T3 (evidence gates before LLM
-- spend). Flags finding candidates that entered the LLM lane without passing
-- the deterministic evidence gate, bypassing the cost-tier control.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'candidate:' || c.candidate_id AS finding_key,
    'LLM lane entered without passing deterministic gate: ' || c.candidate_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    c.candidate_id || ' / ' || COALESCE(c.check_id, '') || ' / ' || COALESCE(c.finding_key, '') AS record_locator,
    'passed_deterministic_gate=' || COALESCE(CAST(CAST(c.passed_deterministic_gate AS BOOLEAN) AS VARCHAR), 'unknown') ||
    '; llm_lane_entered=' || CAST(COALESCE(c.llm_lane_entered, false) AS VARCHAR) ||
    '; llm_verdict=' || COALESCE(c.llm_verdict, '') AS details,
    c.run_id AS run_id,
    55 AS risk_score
FROM ext_telecom_offsec_aws_finding_candidate c
WHERE c.run_id = ?1
  AND COALESCE(CAST(c.llm_lane_entered AS BOOLEAN), false) = true
  AND COALESCE(CAST(c.passed_deterministic_gate AS BOOLEAN), false) = false
ORDER BY finding_key
LIMIT ?2;
