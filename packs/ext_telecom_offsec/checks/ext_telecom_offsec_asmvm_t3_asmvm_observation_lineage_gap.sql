-- ext_telecom_offsec_asmvm_t3_asmvm_observation_lineage_gap.sql - T3
--
-- Evidence-integrity guard for the Finding R lineage rollups.
-- `ext_telecom_offsec_asmvm_vm_cve_observation` carries TWO counts of the same fact:
-- deprecated compatibility alias `finding_count` and authoritative
-- `n_findings`, added with the scan-context rollups. Consumers read n_findings;
-- this guard keeps the two projected counts from silently drifting. A
-- future generator that forgets either field would otherwise leave a stale
-- count in a seemingly valid observation. Migration 002 declares these columns CHECK-less and the loopback
-- runner re-issues `CREATE TABLE t (col TYPE, ...)` from name/type pairs, so
-- nothing above this check enforces them (Finding Q); enforcement is a pack
-- check, the second instance of that pattern after
-- checks/ext_telecom_offsec_asmvm_t3_asmvm_scan_confidence_vocabulary_gap.sql.
--
-- Reasons, one aggregate row each, so a broken projection cannot flood the
-- report:
--   rollup_columns_missing                projection predates Finding R
--   zero_contributing_findings            an observation with no source finding
--   finding_count_disagrees_with_n_findings  the two counts disagree
--   negative_contributor_counts           a count below zero
--   external_contributors_exceed_total    n_external_findings > n_findings
--   unknown_context_contributors_exceed_total  n_unknown_context_findings > n_findings
--   context_contributors_exceed_total     external + unknown > n_findings
--   scan_networks_holds_unknown_network_sentinel  `scan_networks` is defined as
--         sorted distinct NON-NULL network names, so unknown-context contributors
--         contribute nothing to it. The sentinel-shaped token is reserved for
--         detecting a future coercion bug; a literal vendor name "Unknown" is a
--         legitimate name and must not trip this guard.
--
-- One aggregate row per reason. Bound params: ?1 run_id, ?2 row limit.

SELECT
    'asmvm:observation-lineage-gap:' || obs.reason AS finding_key,
    'VM CVE observation lineage counts are inconsistent or missing' AS title,
    COUNT(*) AS affected_count,
    COUNT(DISTINCT obs.ip) AS exposure_estimate,
    'ext_telecom_offsec_asmvm_vm_cve_observation[reason=' || obs.reason || ']' AS record_locator,
    'affected_ips=' || CAST(COUNT(DISTINCT obs.ip) AS VARCHAR) ||
    '; reason=' || obs.reason ||
    '; contract=deprecated finding_count must equal authoritative n_findings' ||
    '; contract=n_external_findings + n_unknown_context_findings <= n_findings' ||
    '; contract=scan_networks holds sorted non-null network names only' ||
    '; contract_reference=schema/migrations/002_ext_telecom_offsec_asmvm_vm_silver.sql' AS details,
    obs.run_id AS run_id,
    40 AS risk_score
FROM (
    SELECT
        run_id,
        ip,
        CASE
            WHEN n_findings IS NULL AND finding_count IS NOT NULL
                THEN 'rollup_columns_missing'
            WHEN n_findings = 0
                THEN 'zero_contributing_findings'
            WHEN finding_count IS NOT NULL AND finding_count <> n_findings
                THEN 'finding_count_disagrees_with_n_findings'
            WHEN n_findings < 0 OR n_external_findings < 0 OR n_unknown_context_findings < 0
                THEN 'negative_contributor_counts'
            WHEN n_external_findings > n_findings
                THEN 'external_contributors_exceed_total'
            WHEN n_unknown_context_findings > n_findings
                THEN 'unknown_context_contributors_exceed_total'
            WHEN n_external_findings + n_unknown_context_findings > n_findings
                THEN 'context_contributors_exceed_total'
            WHEN (',' || lower(scan_networks) || ',')
                     LIKE '%,<unknown-network>,%'
                THEN 'scan_networks_holds_unknown_network_sentinel'
            ELSE NULL
        END AS reason
    FROM ext_telecom_offsec_asmvm_vm_cve_observation
    WHERE run_id = ?1
) AS obs
WHERE obs.reason IS NOT NULL
GROUP BY obs.reason, obs.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
