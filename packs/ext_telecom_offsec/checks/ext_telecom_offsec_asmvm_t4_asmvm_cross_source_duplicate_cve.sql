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

SELECT
    'asmvm:dup-cve:' || a.ip || ':' || a.cve        AS finding_key,
    'Cross-source duplicate finding (ASM + VM): ' || a.cve || ' on ' || a.ip AS title,
    -- one finding per (ip, cve) pair: several VM rows may corroborate the same
    -- ASM inference (one per source system), and the finding contract requires
    -- a unique finding_key per run, so every VM-side value is aggregated
    CAST(1 + SUM(COALESCE(v.n_findings, 0)) AS BIGINT) AS affected_count,
    1                                               AS exposure_estimate,
    a.ip || ' / ' || a.cve || ' / ' || MIN(a.evidence_ref) AS record_locator,
    'asm_sources=' || COALESCE(MIN(a.sources), '') ||
    '; vm_evidence=' || COALESCE(MIN(v.evidence_ref), '') ||
    '; vm_rows_for_pair=' || CAST(COUNT(*) AS VARCHAR) ||
    '; vm_findings_for_pair=' || CAST(SUM(COALESCE(v.n_findings, 0)) AS VARCHAR) ||
    '; vm_severity=' || CAST(ROUND(MAX(COALESCE(v.severity, 0)), 2) AS VARCHAR) ||
    '; asm_inferred_score=' || CAST(ROUND(MIN(COALESCE(a.inferred_score, 0)), 2) AS VARCHAR) ||
    '; vm_scan_mode=' || COALESCE(MIN(v.scan_mode), 'unknown') ||
    '; vm_last_found=' || COALESCE(SUBSTR(CAST(MAX(v.last_found_ts) AS VARCHAR), 1, 19), '') ||
    '; canonical=vm_scan'                           AS details,
    a.run_id                                        AS run_id,
    34                                              AS risk_score
FROM ext_telecom_offsec_asmvm_cve_observation a
JOIN ext_telecom_offsec_asmvm_vm_cve_observation v
    ON v.run_id = a.run_id
   AND v.ip = a.ip
   AND v.cve = a.cve
WHERE a.run_id = ?1
  AND CAST(a.is_active AS BOOLEAN)
  AND CAST(v.is_open AS BOOLEAN)
GROUP BY a.run_id, a.ip, a.cve
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
