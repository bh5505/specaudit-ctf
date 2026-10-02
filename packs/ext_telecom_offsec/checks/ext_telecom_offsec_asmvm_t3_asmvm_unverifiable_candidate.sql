-- ext_telecom_offsec_asmvm_t3_asmvm_unverifiable_candidate.sql - T3
-- (deterministic evidence gate before LLM spend), ASM/VM shape.
--
-- A High/Critical ASM alert candidate can only pass a *deterministic* gate when
-- a second, independent source can speak about the same address. The
-- vulnerability-management estate is that second source in this engagement: when
-- it holds no asset for the candidate's IP, there is no deterministic
-- corroboration path at all, so sending the candidate to the LLM lane means the
-- lane narrates a single vendor export back to itself while spending the review
-- budget. The candidate must be held out of the lane until an authenticated scan
-- or a live probe covers the address.
--
-- The candidate -> subject-IP binding lives in the pack-local
-- ext_telecom_offsec_asmvm_candidate_subject table: the finding_candidate contract has
-- no subject column (see docs/findings/README.md, "Contract gaps this pack works
-- around"). A candidate with no subject row cannot be gated on coverage and is
-- therefore NOT flagged here - it is flagged by ext_telecom_offsec_asmvm_t3_evidence_gate
-- when it entered the lane without passing the gate.
--
-- Tables: ext_telecom_offsec_asmvm_candidate_subject, ext_telecom_offsec_asmvm_finding_candidate,
-- ext_telecom_offsec_asmvm_vm_asset.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'asmvm:no-gate:' || cs.candidate_id             AS finding_key,
    'High-severity ASM candidate with no second-source coverage' AS title,
    1                                               AS affected_count,
    1                                               AS exposure_estimate,
    cs.candidate_id || ' / ip:' || COALESCE(cs.subject_ip, 'unknown') AS record_locator,
    'check_id=' || COALESCE(cs.check_id, '') ||
    '; ip=' || COALESCE(cs.subject_ip, '') ||
    '; subject_kind=' || COALESCE(cs.subject_kind, '') ||
    '; severity=' || COALESCE(cs.severity, '') ||
    '; rule=' || COALESCE(cs.rule_name, '') ||
    '; source_system=' || COALESCE(cs.candidate_source_system, '') ||
    '; detail_ref=' || COALESCE(cs.detail_ref, '') ||
    '; in_vm_estate=false' ||
    '; passed_deterministic_gate=' || CASE WHEN COALESCE(CAST(c.passed_deterministic_gate AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; llm_lane_entered=' || CASE WHEN COALESCE(CAST(c.llm_lane_entered AS BOOLEAN), false) THEN 'true' ELSE 'false' END ||
    '; llm_verdict=' || COALESCE(c.llm_verdict, 'pending') ||
    '; gate_action=hold_out_of_llm_lane'            AS details,
    cs.run_id                                       AS run_id,
    CASE WHEN cs.severity = 'Critical' THEN 48 ELSE 44 END AS risk_score
FROM ext_telecom_offsec_asmvm_candidate_subject cs
JOIN ext_telecom_offsec_asmvm_finding_candidate c
    ON c.candidate_id = cs.candidate_id
   AND c.run_id = cs.run_id
WHERE cs.run_id = ?1
  AND cs.candidate_source_system = 'cortex_xpanse'
  AND cs.severity IN ('High', 'Critical')
  AND NOT EXISTS (
        SELECT 1
        FROM ext_telecom_offsec_asmvm_vm_asset v
        WHERE v.run_id = cs.run_id
          AND v.ip = cs.subject_ip)
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
