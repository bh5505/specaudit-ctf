-- ext_telecom_offsec_asmvm_t1_asmvm_critical_internal_record_only.sql - T1
-- (threat-model first: distinguish scan context from observed reachability).
--
-- Flags internet-active IPs whose contributing OPEN critical VM records came
-- from a named non-external scanner network, and that have no open critical from
-- an external scanner network at all. Rows with unknown scan context are
-- excluded rather than counted. This is an additive qualification
-- of the flagship IP-level intersection, not a replacement for it.
--
-- One row per IP (aggregated): the address is the unit of remediation.
--
-- Tables: ext_telecom_offsec_asmvm_asm_vm_surface, ext_telecom_offsec_asmvm_vm_finding.
-- Boolean columns are CAST explicitly: the loopback CSV runner types an
-- all-true/all-false column as INTEGER, and the cast keeps this SQL valid on
-- DuckDB and SQLite alike.
-- Bound params: ?1 = run_id, ?2 = row limit.
-- Finding U: token lists come from a pre-deduped subselect aggregated with an
-- explicit ORDER BY (plain string_agg honors it on DuckDB and SQLite alike);
-- GROUP_CONCAT(DISTINCT ...) left input order to engine parallelism and made
-- report details irreproducible between identical-evidence runs.
WITH network_lists AS (
    SELECT x.run_id, x.ip,
           string_agg(x.v, ',' ORDER BY x.v) AS networks
    FROM (
        -- same contributing rows as the main WHERE below: open critical records
        -- from a named non-external scanner network; unknown context excluded by
        -- policy, not folded into the list
        SELECT DISTINCT f.run_id, f.ip,
               CAST(f.scan_network_name AS VARCHAR) AS v
        FROM ext_telecom_offsec_asmvm_vm_finding f
        WHERE CAST(f.is_open AS BOOLEAN)
          AND f.severity >= 9.0
          AND f.scan_network_name IS NOT NULL
          AND LOWER(CAST(f.scan_network_name AS VARCHAR)) NOT LIKE '%external%'
    ) x
    GROUP BY x.run_id, x.ip
)
SELECT
    'asmvm:critical-internal-record-only:' || f.ip    AS finding_key,
    'Internet-active IP with internal-network critical record: ' || f.ip AS title,
    COUNT(*)                                         AS affected_count,
    CAST(COALESCE(MAX(s.asm_exposed_services), 0) AS BIGINT) AS exposure_estimate,
    'vm:asset:' || f.ip || ' + asm:ip:' || f.ip      AS record_locator,
    'open_critical_internal_records=' || CAST(COUNT(*) AS VARCHAR) ||
    '; max_severity=' || CAST(ROUND(MAX(f.severity), 2) AS VARCHAR) ||
    '; finding_networks=' || COALESCE(MAX(n.networks), 'unknown') ||
    '; portless_contributing_findings=' ||
        CAST(SUM(CASE WHEN f.port IS NULL THEN 1 ELSE 0 END) AS VARCHAR) ||
    '; exposed_services=' || CAST(COALESCE(MAX(s.asm_exposed_services), 0) AS VARCHAR) ||
    '; validation=external_scan_or_service_corroboration_required' AS details,
    f.run_id                                         AS run_id,
    CASE WHEN MAX(f.severity) >= 9.8 THEN 60
         WHEN MAX(f.severity) >= 9.5 THEN 58
         ELSE 56 END                                 AS risk_score
FROM ext_telecom_offsec_asmvm_vm_finding f
LEFT JOIN network_lists n
       ON n.ip = f.ip
      AND n.run_id = f.run_id
JOIN ext_telecom_offsec_asmvm_asm_vm_surface s
    ON s.ip = f.ip
   AND s.run_id = f.run_id
WHERE f.run_id = ?1
  AND CAST(f.is_open AS BOOLEAN)
  AND f.severity >= 9.0
  AND CAST(s.has_active_service AS BOOLEAN)
  -- Unknown scan context is deliberately NOT counted as internal: a finding
  -- whose producing network is unknown proves nothing either way, and reading
  -- NULL as "internal" would let missing provenance masquerade as a qualified
  -- result. This matters whenever scan-context evidence is missing.
  AND f.scan_network_name IS NOT NULL
  AND LOWER(f.scan_network_name) NOT LIKE '%external%'
  AND NOT EXISTS (
      SELECT 1
      FROM ext_telecom_offsec_asmvm_vm_finding ef
      WHERE ef.run_id = f.run_id
        AND ef.ip = f.ip
        AND CAST(ef.is_open AS BOOLEAN)
        AND ef.severity >= 9.0
        AND LOWER(COALESCE(ef.scan_network_name, '')) LIKE '%external%'
  )
GROUP BY f.ip, f.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
