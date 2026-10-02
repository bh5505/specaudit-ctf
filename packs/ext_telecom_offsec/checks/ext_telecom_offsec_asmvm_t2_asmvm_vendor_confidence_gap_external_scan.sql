-- ext_telecom_offsec_asmvm_t2_asmvm_vendor_confidence_gap_external_scan.sql - T2
--
-- This is lineage-true because scan context is rolled up from every VM finding
-- contributing to each (IP,CVE), rather than inferred from the observation's
-- single evidence_ref. Requiring all contributing findings to have an
-- external scanner context prevents mixed-network observations from being
-- presented as externally scanned.
--
-- This strict check and the broad vendor-confidence-gap check are mutually
-- exclusive by construction. One row per IP; affected_count is the number of
-- distinct qualifying CVEs on that IP (the observation table is unique at
-- (IP,CVE)). Bound params: ?1 = run_id, ?2 = row limit.
-- Finding U: every token list is a pre-deduped subselect aggregated with an
-- explicit ORDER BY on both engines; GROUP_CONCAT(DISTINCT ...) left input order
-- to engine parallelism and made report details irreproducible between runs.
WITH network_sets_by_pair AS (
    SELECT x.run_id, x.ip, x.cve,
           string_agg(x.v, ',' ORDER BY x.v) AS scan_networks
    FROM (
        -- one distinct projection token per pair; NULL column values are skipped
        -- by the aggregate exactly as GROUP_CONCAT skipped them
        SELECT DISTINCT run_id, ip, cve, CAST(scan_networks AS VARCHAR) AS v
        FROM ext_telecom_offsec_asmvm_vm_cve_observation
        WHERE run_id = ?1
          AND CAST(is_open AS BOOLEAN)
    ) x
    GROUP BY x.run_id, x.ip, x.cve
),
confidence_by_pair AS (
    SELECT
        p.run_id,
        p.ip,
        p.cve,
        COUNT(*) AS observation_count,
        MAX(p.severity) AS max_severity,
        MAX(CASE WHEN p.scan_confidence = 'vendor_vuln_confirmed' THEN 1 ELSE 0 END) AS has_confirmed,
        MAX(CASE WHEN p.scan_confidence = 'vendor_mixed_category' THEN 1 ELSE 0 END) AS has_mixed,
        MAX(CASE WHEN p.scan_confidence = 'vendor_potential_vulnerability' THEN 1 ELSE 0 END) AS has_potential,
        MAX(p.n_findings) AS n_findings,
        MAX(p.n_external_findings) AS n_external_findings,
        MIN(ns.scan_networks) AS scan_networks
    FROM ext_telecom_offsec_asmvm_vm_cve_observation p
    LEFT JOIN network_sets_by_pair ns
           ON ns.run_id = p.run_id
          AND ns.ip = p.ip
          AND ns.cve = p.cve
    WHERE p.run_id = ?1
      AND CAST(p.is_open AS BOOLEAN)
    GROUP BY p.run_id, p.ip, p.cve
), qualifying AS (
    SELECT p.*
    FROM confidence_by_pair p
    WHERE p.max_severity >= 9.0
      AND p.has_potential = 1
      AND p.has_confirmed = 0
      AND p.has_mixed = 0
      AND p.n_external_findings = p.n_findings
      AND p.n_findings > 0
      AND EXISTS (
          SELECT 1
          FROM ext_telecom_offsec_asmvm_asm_vm_surface s
          WHERE s.run_id = p.run_id
            AND s.ip = p.ip
            AND CAST(s.has_active_service AS BOOLEAN)
      )
)
SELECT
    'asmvm:vendor-confidence-gap-external-scan:' || q.ip AS finding_key,
    'Internet-active IP with external-scan potential-only critical VM observations: ' || q.ip AS title,
    COUNT(DISTINCT q.cve) AS affected_count,
    CAST(COALESCE((
        SELECT MAX(es.asm_exposed_services)
        FROM ext_telecom_offsec_asmvm_asm_vm_surface es
        WHERE es.run_id = q.run_id AND es.ip = q.ip
    ), 0) AS BIGINT) AS exposure_estimate,
    'vm:cve-observation:' || q.ip || ' + asm:ip:' || q.ip AS record_locator,
    'observation_count=' || CAST(SUM(q.observation_count) AS VARCHAR) ||
    '; distinct_cve_count=' || CAST(COUNT(DISTINCT q.cve) AS VARCHAR) ||
    '; max_severity=' || CAST(ROUND(MAX(q.max_severity), 2) AS VARCHAR) ||
    '; n_findings=' || CAST(SUM(q.n_findings) AS VARCHAR) ||
    '; n_external_findings=' || CAST(SUM(q.n_external_findings) AS VARCHAR) ||
    '; scan_networks=' || COALESCE(MAX(sp.mode_set), 'unknown') ||
    '; confidence=vendor_potential_vulnerability_only' ||
    '; lineage=all_contributing_findings_external' AS details,
    q.run_id AS run_id,
    CASE WHEN MAX(q.max_severity) >= 9.8 THEN 60 ELSE 56 END AS risk_score
FROM qualifying q
LEFT JOIN (
    -- Finding U: the outer list aggregates each pair's already-deterministic
    -- token set; dedup and ORDER BY it once more so the IP-level string is a
    -- rendering choice, not an engine artifact.
    SELECT r.run_id, r.ip,
           string_agg(r.m, ',' ORDER BY r.m) AS mode_set
    FROM (
        SELECT DISTINCT q2.run_id, q2.ip, q2.scan_networks AS m
        FROM qualifying q2
        WHERE q2.scan_networks IS NOT NULL
    ) r
    GROUP BY r.run_id, r.ip
) sp
       ON sp.run_id = q.run_id
      AND sp.ip = q.ip
GROUP BY q.ip, q.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
