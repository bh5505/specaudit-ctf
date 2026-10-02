-- ext_telecom_offsec_asmvm_t3_evidence_gate.sql - T3 (evidence gates before LLM
-- spend). Flags finding candidates that entered the LLM lane without passing
-- the deterministic evidence gate, bypassing the cost-tier control.
-- Bound params: ?1 = run_id, ?2 = row limit.
--
-- Reads this pack's ASM/VM candidate queue. An unknown gate result cannot
-- authorize entry to the LLM lane and is reported as a gate failure.
-- Booleans are CAST explicitly so the SQL stays valid under the CSV loopback
-- runner, which types an all-true/all-false column as INTEGER.

SELECT
    'asmvm:candidate:' || c.candidate_id AS finding_key,
    'LLM lane entered without passing deterministic gate: ' || c.candidate_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    c.candidate_id || ' / ' || COALESCE(c.check_id, '') || ' / ' || COALESCE(c.finding_key, '') AS record_locator,
    'passed_deterministic_gate=' || CASE WHEN c.passed_deterministic_gate IS NULL THEN 'unknown'
                                         WHEN CAST(c.passed_deterministic_gate AS BOOLEAN) THEN 'true'
                                         ELSE 'false' END ||
    '; llm_lane_entered=' || CASE WHEN COALESCE(CAST(c.llm_lane_entered AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; llm_verdict=' || COALESCE(c.llm_verdict, '') AS details,
    c.run_id AS run_id,
    55 AS risk_score
FROM ext_telecom_offsec_asmvm_finding_candidate c
WHERE c.run_id = ?1
  AND CAST(c.llm_lane_entered AS BOOLEAN) = true
  AND COALESCE(CAST(c.passed_deterministic_gate AS BOOLEAN), false) = false
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
