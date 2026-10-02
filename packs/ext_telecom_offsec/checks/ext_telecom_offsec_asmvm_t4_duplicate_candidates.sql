-- ext_telecom_offsec_asmvm_t4_duplicate_candidates.sql - T4 (deduplicate, then
-- chain). Flags duplicate-verdict candidates inside dedupe-hash clusters with
-- more than one row, so overlaps collapse before multi-step chaining.
-- The 'duplicate' verdict value is defined in mapping_spec.yaml value_map for
-- llm_verdict (ext_telecom_offsec_asmvm_finding_candidate) and planted via
-- gen_evidence.py LLM_VERDICTS (which notes 'duplicate' separately for T4).
-- Bound params: ?1 = run_id, ?2 = row limit.
--
-- INHERITED CHECK: re-expressed from ext_telecom_cyber/checks/ext_telecom_t4_duplicate_candidates.sql unchanged
-- in logic, retargeted to this pack's own ledger tables (ext_telecom_offsec_asmvm_finding_candidate). The
-- ASM/VM pack owns its evidence/candidate/rule/run ledger so it loads and runs
-- standalone; running it here keeps the process controls (adversarial
-- validation, evidence gates, dedupe, sandboxing, rule corpus, resumability)
-- enforced over the ASM/VM evidence instead of only over the AWS posture pack.
-- Booleans are CAST explicitly so the SQL stays valid under the CSV loopback
-- runner, which types an all-true/all-false column as INTEGER.
SELECT
    'asmvm:cluster:' || c.dedupe_hash || ':' || c.candidate_id AS finding_key,
    'Duplicate candidate cluster with duplicate verdict: ' || COALESCE(c.dedupe_hash, 'null') AS title,
    cluster_sizes.cluster_count AS affected_count,
    cluster_sizes.cluster_count AS exposure_estimate,
    c.candidate_id || ' / ' || COALESCE(c.check_id, '') AS record_locator,
    'dedupe_hash=' || COALESCE(c.dedupe_hash, '') ||
    '; llm_verdict=' || COALESCE(c.llm_verdict, '') ||
    '; finding_key=' || COALESCE(c.finding_key, '') AS details,
    c.run_id AS run_id,
    40 AS risk_score
FROM ext_telecom_offsec_asmvm_finding_candidate c
JOIN (
    SELECT c2.dedupe_hash, COUNT(*) AS cluster_count
    FROM ext_telecom_offsec_asmvm_finding_candidate c2
    WHERE c2.dedupe_hash IS NOT NULL
      AND c2.run_id = ?1
    GROUP BY c2.dedupe_hash
    HAVING COUNT(*) > 1
) cluster_sizes
    ON cluster_sizes.dedupe_hash = c.dedupe_hash
WHERE c.run_id = ?1
  AND c.llm_verdict = 'duplicate'
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
