-- ext_telecom_offsec_asmvm_t2_asmvm_vendor_confidence_gap.sql - T2
--
-- Scoping decision: report only OPEN severity >= 9.0 per-(IP,CVE) pairs whose
-- best vendor confidence is potential-only, on an IP where ASM independently
-- records has_active_service. The active-service intersection uses the
-- flagship check's reachability definition rather than the narrower
-- exposed-service counter.
--
-- The predicate is based on the criticality and confidence contract, not
-- on whether a particular test case fires.
--
-- The strict sibling partitions by lineage at the (IP,CVE) grain, not at
-- the emitted IP grain. An IP may appear in both checks if different CVE
-- pairs have different lineage; deduplicate by pair before summing exposure.
-- Suppressing an entire IP would discard qualifying broad-lineage evidence.
--
-- One row per IP. affected_count is the number of distinct qualifying CVEs on
-- that IP (the observation table is unique at (IP,CVE), but the semantic unit
-- is pinned explicitly). Bound params: ?1 = run_id, ?2 = row limit.
-- Finding U: every token list is a pre-deduped subselect aggregated with an
-- explicit ORDER BY on both engines; GROUP_CONCAT(DISTINCT ...) left input order
-- to engine parallelism and made report details irreproducible between runs.
WITH modes_by_pair AS (
    SELECT x.run_id, x.ip, x.cve,
           string_agg(x.v, ',' ORDER BY x.v) AS scan_modes
    FROM (
        -- one distinct projection token per pair
        SELECT DISTINCT run_id, ip, cve, CAST(scan_mode AS VARCHAR) AS v
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
        MIN(m.scan_modes) AS scan_modes,
        MAX(p.n_findings) AS n_findings,
        MAX(p.n_external_findings) AS n_external_findings
    FROM ext_telecom_offsec_asmvm_vm_cve_observation p
    LEFT JOIN modes_by_pair m
           ON m.run_id = p.run_id
          AND m.ip = p.ip
          AND m.cve = p.cve
    WHERE p.run_id = ?1
      AND CAST(p.is_open AS BOOLEAN)
    GROUP BY p.run_id, p.ip, p.cve
), fully_external_ips AS (
    -- IPs that the strict sibling check also reports: used only to mark the
    -- overlap, never to exclude rows from this check.
    SELECT DISTINCT p.run_id, p.ip
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
), qualifying AS (
    SELECT p.*,
           CASE WHEN x.ip IS NULL THEN 0 ELSE 1 END AS also_in_strict
    FROM confidence_by_pair p
    LEFT JOIN fully_external_ips x
           ON x.run_id = p.run_id AND x.ip = p.ip
    WHERE p.max_severity >= 9.0
      AND p.has_potential = 1
      AND p.has_confirmed = 0
      AND p.has_mixed = 0
      AND (COALESCE(p.n_external_findings, 0) < COALESCE(p.n_findings, 0)
           OR COALESCE(p.n_findings, 0) = 0)
      AND EXISTS (
          SELECT 1
          FROM ext_telecom_offsec_asmvm_asm_vm_surface s
          WHERE s.run_id = p.run_id
            AND s.ip = p.ip
            AND CAST(s.has_active_service AS BOOLEAN)
      )
)
SELECT
    'asmvm:vendor-confidence-gap:' || q.ip AS finding_key,
    'Internet-active IP with potential-only critical VM observations: ' || q.ip AS title,
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
    '; confidence=vendor_potential_vulnerability_only' ||
    '; excluded_confidence_mix=vendor_vuln_confirmed,vendor_mixed_category' ||
    '; exclusion_reason=stronger_or_mixed_vendor_evidence_is_not_a_potential_only_gap' ||
    '; scan_mode=' || COALESCE(MAX(mp.mode_set), 'unknown') ||
    '; scan_context=lineage_rollup_not_fully_external' ||
    '; lineage_excluded_pairs=fully_external_contributors_are_in_the_strict_sibling' ||
    '; also_in_external_scan_check=' ||
        CASE WHEN MAX(q.also_in_strict) = 1 THEN 'true' ELSE 'false' END ||
    '; scope_note=TC-01_sev7_nonconfirmed_2_to_0,TC-02_sev7_nonconfirmed_8_to_0' AS details,
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
        SELECT DISTINCT q2.run_id, q2.ip, q2.scan_modes AS m
        FROM qualifying q2
        WHERE q2.scan_modes IS NOT NULL
    ) r
    GROUP BY r.run_id, r.ip
) mp
       ON mp.run_id = q.run_id
      AND mp.ip = q.ip
GROUP BY q.ip, q.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
