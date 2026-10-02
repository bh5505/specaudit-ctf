-- ext_telecom_offsec_asmvm_t1_asmvm_critical_service_corroborated.sql - T1
-- (threat-model first: corroborate the vulnerable service itself).
--
-- Flags an OPEN critical VM finding where ASM independently recorded a service
-- on the same IP and port. The service endpoint table is the canonical
-- service-to-IP expansion; the comma-joined service ipv4_list is not parsed.
--
-- One row per IP (aggregated): the address is the unit of remediation.
--
-- Tables: ext_telecom_offsec_asmvm_vm_finding,
-- ext_telecom_offsec_asmvm_service_endpoint.
-- Boolean columns are CAST explicitly: the loopback CSV runner types an
-- all-true/all-false column as INTEGER, and the cast keeps this SQL valid on
-- DuckDB and SQLite alike.
-- Bound params: ?1 = run_id, ?2 = row limit.
-- Finding U: token lists come from pre-deduped subselects aggregated with an
-- explicit ORDER BY on both engines; GROUP_CONCAT(DISTINCT ...) left input order
-- to engine parallelism and made report details irreproducible between runs.
WITH port_lists AS (
    SELECT y.run_id, y.ip,
           string_agg(y.v, ',' ORDER BY y.v) AS ports
    FROM (
        -- distinct (ip, port) pairs of open critical findings that the ASM
        -- service endpoint table independently records - same rows as the
        -- join in the main query below, deduplicated once up front
        SELECT DISTINCT f2.run_id, f2.ip, CAST(ep.port AS VARCHAR) AS v
        FROM ext_telecom_offsec_asmvm_vm_finding f2
        JOIN (SELECT DISTINCT run_id, ip, port
              FROM ext_telecom_offsec_asmvm_service_endpoint) ep
          ON ep.ip = f2.ip AND ep.run_id = f2.run_id AND ep.port = f2.port
        WHERE CAST(f2.is_open AS BOOLEAN)
          AND f2.severity >= 9.0
    ) y
    GROUP BY y.run_id, y.ip
),
network_lists AS (
    SELECT z.run_id, z.ip,
           string_agg(z.v, ',' ORDER BY z.v) AS networks
    FROM (
        -- networks of open critical findings whose port ASM corroborates;
        -- NULL scan context is skipped by aggregation exactly as before
        SELECT DISTINCT f3.run_id, f3.ip,
               CAST(f3.scan_network_name AS VARCHAR) AS v
        FROM ext_telecom_offsec_asmvm_vm_finding f3
        WHERE CAST(f3.is_open AS BOOLEAN)
          AND f3.severity >= 9.0
          AND EXISTS (
              SELECT 1
              FROM (SELECT DISTINCT run_id, ip, port
                    FROM ext_telecom_offsec_asmvm_service_endpoint) epx
              WHERE epx.ip = f3.ip
                AND epx.run_id = f3.run_id
                AND epx.port = f3.port
          )
    ) z
    GROUP BY z.run_id, z.ip
)
SELECT
    'asmvm:critical-service-corroborated:' || f.ip    AS finding_key,
    'Open critical finding on ASM-confirmed service port: ' || f.ip AS title,
    COUNT(DISTINCT f.finding_id)                     AS affected_count,
    CAST(COUNT(DISTINCT ep.port) AS BIGINT)          AS exposure_estimate,
    'vm:asset:' || f.ip || ' + asm:service:' || f.ip AS record_locator,
    'port_matched_critical_findings=' || CAST(COUNT(DISTINCT f.finding_id) AS VARCHAR) ||
    '; max_severity=' || CAST(ROUND(MAX(f.severity), 2) AS VARCHAR) ||
    '; finding_networks=' || COALESCE(MAX(nl.networks), 'unknown') ||
    '; matched_ports=' || COALESCE(MAX(pl.ports), 'unknown') ||
    '; validation=asm_service_port_corroborated'     AS details,
    f.run_id                                         AS run_id,
    CASE WHEN MAX(f.severity) >= 9.8 THEN 60
         WHEN MAX(f.severity) >= 9.5 THEN 58
         ELSE 56 END                                 AS risk_score
FROM ext_telecom_offsec_asmvm_vm_finding f
LEFT JOIN port_lists pl
       ON pl.ip = f.ip
      AND pl.run_id = f.run_id
LEFT JOIN network_lists nl
       ON nl.ip = f.ip
      AND nl.run_id = f.run_id
JOIN (
    SELECT DISTINCT run_id, ip, port
    FROM ext_telecom_offsec_asmvm_service_endpoint
) ep
    ON ep.ip = f.ip
   AND ep.run_id = f.run_id
   AND ep.port = f.port
WHERE f.run_id = ?1
  AND CAST(f.is_open AS BOOLEAN)
  AND f.severity >= 9.0
GROUP BY f.ip, f.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
