-- ext_telecom_offsec_asmvm_t4_asmvm_cross_source_duplicate_cve.sql - T4
-- (deduplicate, then chain), cross-source edition.
--
-- The same (ip, cve) pair is reported by the ASM feed's banner inference AND by
-- the vulnerability-management scan. Left uncollapsed, the pair counts twice in
-- exposure estimates and twice in any chain built on it, so the same host/CVE is
-- presented as two problems. The VM scan is the canonical row: it is the only
-- source with a finding id, a scanner plugin id and a scan timestamp; the ASM
-- observation is corroborating evidence for it.
--
-- One row per (ip, cve) pair, with the canonical survivor named in details
-- (canonical=vm:<finding_id>) so the chain builder has a deterministic winner.
--
-- Tables: ext_telecom_offsec_asmvm_cve_observation, ext_telecom_offsec_asmvm_vm_cve_observation.
-- Bound params: ?1 = run_id, ?2 = row limit.

WITH asm_pair AS (
    SELECT run_id, ip, cve,
           MIN(evidence_ref) AS evidence_ref,
           MIN(sources) AS sources,
           MIN(inferred_score) AS inferred_score
    FROM ext_telecom_offsec_asmvm_cve_observation
    WHERE run_id = ?1 AND CAST(is_active AS BOOLEAN)
    GROUP BY run_id, ip, cve
),
vm_pair AS (
    SELECT run_id, ip, cve,
           MIN(evidence_ref) AS evidence_ref,
           MAX(COALESCE(n_findings, 0)) AS n_findings,
           MAX(COALESCE(severity, 0)) AS severity,
           MIN(scan_mode) AS scan_mode,
           MAX(last_found_ts) AS last_found_ts
    FROM ext_telecom_offsec_asmvm_vm_cve_observation
    WHERE run_id = ?1 AND CAST(is_open AS BOOLEAN)
    GROUP BY run_id, ip, cve
)
SELECT
    'asmvm:dup-cve:' || a.ip || ':' || a.cve        AS finding_key,
    'Cross-source duplicate finding (ASM + VM): ' || a.cve || ' on ' || a.ip AS title,
    -- The aggregate CTEs collapse reaccepted rows before the cross-source join.
    CAST(1 + v.n_findings AS BIGINT) AS affected_count,
    1                                               AS exposure_estimate,
    a.ip || ' / ' || a.cve || ' / ' || a.evidence_ref AS record_locator,
    'asm_sources=' || COALESCE(a.sources, '') ||
    '; vm_evidence=' || COALESCE(v.evidence_ref, '') ||
    '; vm_rows_for_pair=1' ||
    '; vm_findings_for_pair=' || CAST(v.n_findings AS VARCHAR) ||
    '; vm_severity=' || CAST(ROUND(v.severity, 2) AS VARCHAR) ||
    '; asm_inferred_score=' || CAST(ROUND(COALESCE(a.inferred_score, 0), 2) AS VARCHAR) ||
    '; vm_scan_mode=' || COALESCE(v.scan_mode, 'unknown') ||
    '; vm_last_found=' || COALESCE(SUBSTR(CAST(v.last_found_ts AS VARCHAR), 1, 19), '') ||
    '; canonical=vm_scan'                           AS details,
    a.run_id                                        AS run_id,
    34                                              AS risk_score
FROM asm_pair a
JOIN vm_pair v
    ON v.run_id = a.run_id
   AND v.ip = a.ip
   AND v.cve = a.cve
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
