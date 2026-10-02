-- ext_telecom_offsec_aws_t4_duplicate_candidates.sql - T4 (deduplicate, then
-- chain). Flags duplicate-verdict candidates inside dedupe-hash clusters with
-- more than one row, so overlaps collapse before multi-step chaining.
-- The 'duplicate' verdict value is defined in mapping_spec.yaml value_map for
-- llm_verdict (ext_telecom_offsec_aws_finding_candidate) and planted via
-- gen_evidence.py LLM_VERDICTS (which notes 'duplicate' separately for T4).
-- Bound params: ?1 = run_id, ?2 = row limit.
-- Accept event IDs are UUIDs, not timestamps. Aggregate the duplicate state
-- per candidate and hash across accepted partitions.
WITH candidate_state AS (
    SELECT c.run_id, c.dedupe_hash, c.candidate_id,
           MIN(c.check_id) AS check_id,
           MIN(c.finding_key) AS source_finding_key,
           MAX(CASE WHEN c.llm_verdict = 'duplicate' THEN 1 ELSE 0 END) AS duplicate_seen,
           COUNT(DISTINCT COALESCE(c.llm_verdict, 'unknown')) AS verdict_variants
    FROM ext_telecom_offsec_aws_finding_candidate c
    WHERE c.run_id = ?1
      AND c.dedupe_hash IS NOT NULL
    GROUP BY c.run_id, c.dedupe_hash, c.candidate_id
),
cluster_sizes AS (
    SELECT dedupe_hash, COUNT(*) AS cluster_count
    FROM candidate_state
    GROUP BY dedupe_hash
    HAVING COUNT(*) > 1
)
SELECT
    'cluster:' || c.dedupe_hash || ':' || c.candidate_id AS finding_key,
    'Duplicate candidate cluster with duplicate verdict: ' || COALESCE(c.dedupe_hash, 'null') AS title,
    cluster_sizes.cluster_count AS affected_count,
    cluster_sizes.cluster_count AS exposure_estimate,
    c.candidate_id || ' / ' || COALESCE(c.check_id, '') AS record_locator,
    'dedupe_hash=' || COALESCE(c.dedupe_hash, '') ||
    '; llm_verdict=duplicate' ||
    '; verdict_variants=' || CAST(c.verdict_variants AS VARCHAR) ||
    '; finding_key=' || COALESCE(c.source_finding_key, '') AS details,
    c.run_id AS run_id,
    40 AS risk_score
FROM candidate_state c
JOIN cluster_sizes
    ON cluster_sizes.dedupe_hash = c.dedupe_hash
WHERE c.run_id = ?1
  AND c.duplicate_seen = 1
ORDER BY finding_key
LIMIT ?2;
