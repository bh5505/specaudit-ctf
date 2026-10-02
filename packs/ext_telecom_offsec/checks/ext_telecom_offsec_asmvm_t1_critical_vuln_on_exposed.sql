-- ext_telecom_offsec_asmvm_t1_critical_vuln_on_exposed.sql - T1 (threat-model
-- first: what is actually reachable?).
--
-- The intersection this engagement exists for: an OPEN vulnerability-management
-- finding with severity >= 9.0 on an IPv4 the ASM feed simultaneously confirms
-- is answering on the internet. Neither source supports the claim end to end on
-- its own - the scanner knows the vulnerability but not the reachability, the
-- ASM feed knows the reachability but only infers the vulnerability - so the
-- record_locator names BOTH evidence paths and the finding is the agreement.
--
-- One row per IP (aggregated): the address is the unit of remediation and the
-- unit an engagement test can be scoped to.
--
-- Tables: ext_telecom_offsec_asmvm_asm_vm_surface, ext_telecom_offsec_asmvm_vm_finding.
-- Boolean columns are CAST explicitly: the loopback CSV runner types an
-- all-true/all-false column as INTEGER, and the cast keeps this SQL valid on
-- DuckDB and SQLite alike.
-- Bound params: ?1 = run_id, ?2 = row limit.
-- Finding U: the network token list comes from a pre-deduped subselect aggregated
-- with an explicit ORDER BY on both engines; GROUP_CONCAT(DISTINCT ...) left input
-- order to engine parallelism and made report details irreproducible between runs.
WITH network_lists AS (
    SELECT x.run_id, x.ip,
           string_agg(x.v, ',' ORDER BY x.v) AS networks
    FROM (
        -- exactly the contributing rows of the main query below minus the
        -- surface join: open critical records on that IP (NULL scan context is
        -- skipped by the aggregate, exactly as GROUP_CONCAT skipped it)
        SELECT DISTINCT f.run_id, f.ip,
               CAST(f.scan_network_name AS VARCHAR) AS v
        FROM ext_telecom_offsec_asmvm_vm_finding f
        WHERE CAST(f.is_open AS BOOLEAN)
          AND f.severity >= 9.0
    ) x
    GROUP BY x.run_id, x.ip
)
SELECT
    'asmvm:critical-exposed:' || f.ip                AS finding_key,
    'Open critical finding on internet-active IP: ' || f.ip AS title,
    COUNT(DISTINCT f.finding_id)                     AS affected_count,
    CAST(COALESCE(MAX(s.asm_exposed_services), 0) AS BIGINT) AS exposure_estimate,
    'vm:asset:' || f.ip || ' + asm:ip:' || f.ip      AS record_locator,
    'open_critical=' || CAST(COUNT(DISTINCT f.finding_id) AS VARCHAR) ||
    '; max_severity=' || CAST(ROUND(MAX(f.severity), 2) AS VARCHAR) ||
    '; exposed_services=' || CAST(COALESCE(MAX(s.asm_exposed_services), 0) AS VARCHAR) ||
    '; exposed_websites=' || CAST(COALESCE(MAX(s.asm_exposed_websites), 0) AS VARCHAR) ||
    '; asm_active_alerts=' || CAST(COALESCE(MAX(s.asm_active_alerts), 0) AS VARCHAR) ||
    '; inside_owned_range=' || CASE WHEN MAX(CAST(s.inside_owned_range AS BOOLEAN)) THEN 'true' ELSE 'false' END ||
    '; credentialed_scan=' || CASE WHEN MAX(CAST(s.vm_has_credentialed_scan AS BOOLEAN)) THEN 'true' ELSE 'false' END ||
    '; last_vm_scan=' || COALESCE(SUBSTR(CAST(MAX(s.vm_last_scan_ts) AS VARCHAR), 1, 19), 'never') ||
    '; lowest_qid=' || CAST(MIN(f.qid) AS VARCHAR) ||
    '; finding_networks=' || COALESCE(MAX(n.networks), 'unknown') ||
    '; port_corroborated=' || CASE WHEN EXISTS (
        SELECT 1
        FROM ext_telecom_offsec_asmvm_vm_finding cf
        JOIN ext_telecom_offsec_asmvm_service_endpoint ep
          ON ep.ip = cf.ip
         AND ep.run_id = cf.run_id
         AND ep.port = cf.port
        WHERE cf.run_id = f.run_id
          AND cf.ip = f.ip
          AND CAST(cf.is_open AS BOOLEAN)
          AND cf.severity >= 9.0
    ) THEN 'true' ELSE 'false' END ||
    '; validation=authenticated_scan_required'       AS details,
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
GROUP BY f.ip, f.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
