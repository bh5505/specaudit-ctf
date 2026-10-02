-- ext_telecom_offsec_asmvm_t1_exposed_mgmt_ports.sql - T1 (threat-model-first
-- trust boundary), ASM analogue of ext_telecom_t1_trust_boundary's
-- security-group ingress test.
--
-- AWS posture tells you what a firewall ALLOWS; an ASM feed tells you what is
-- actually ANSWERING. This check flags every ASM-observed active service that
-- answers on the public internet on a management, legacy-clear-text or
-- data-plane port - the ports that should never be internet-reachable in a
-- telecom estate. Grouping is per protocol+port (the policy exception), because
-- the audit action is a boundary rule change, not a per-host ticket.
--
-- Port set is CAP-PARAM: it mirrors engagement_configs/default.yaml
-- (mgmt_legacy_data_ports). Keep the literal list and the config in sync.
--
-- Tables: ext_telecom_offsec_asmvm_service_endpoint, ext_telecom_offsec_asmvm_vm_asset,
-- ext_telecom_offsec_asmvm_service_observation (P7, pre-aggregated).
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'asmvm:mgmt-port:' || s.protocol || ':' || CAST(s.port AS VARCHAR) AS finding_key,
    'Internet-reachable management/legacy service surface: ' ||
        CAST(s.port AS VARCHAR) || '/' || s.protocol   AS title,
    COUNT(DISTINCT s.ip)                             AS affected_count,
    COUNT(*)                                         AS exposure_estimate,
    s.protocol || ':' || CAST(s.port AS VARCHAR)     AS record_locator,
    'exposed_endpoints=' || CAST(COUNT(*) AS VARCHAR) ||
    '; ips=' || CAST(COUNT(DISTINCT s.ip) AS VARCHAR) ||
    '; ips_not_in_vm_estate=' || CAST(COUNT(DISTINCT CASE WHEN v.ip IS NULL THEN s.ip END) AS VARCHAR) ||
    '; observed_ips=' || CAST(COUNT(DISTINCT CASE WHEN CAST(o.observed AS BOOLEAN) THEN s.ip END) AS VARCHAR) ||
    '; predicted_ips=' || CAST(COUNT(DISTINCT CASE WHEN o.observed IS NULL OR NOT CAST(o.observed AS BOOLEAN) THEN s.ip END) AS VARCHAR) ||
    '; max_inferred_cvss=' || CAST(ROUND(COALESCE(MAX(s.inferred_vuln_score), 0), 1) AS VARCHAR) ||
    '; services=' || CAST(COUNT(DISTINCT COALESCE(s.service_name, s.service_type)) AS VARCHAR) ||
    '; sample_service=' || COALESCE(MAX(s.service_name), '') ||
    '; validation=live_probe_required'               AS details,
    s.run_id                                         AS run_id,
    -- P7 predicted-vs-observed: a live observation (passive intel or stand-in
    -- probe) corroborates the exposure (higher score); a source-declared prediction
    -- with no observation stays unconfirmed (lower score).
    CASE WHEN COUNT(DISTINCT CASE WHEN CAST(o.observed AS BOOLEAN) THEN s.ip END) > 0
         THEN 60 ELSE 50 END                         AS risk_score
FROM ext_telecom_offsec_asmvm_service_endpoint s
-- Pre-aggregated joins: multiple observation sources (or accept events) per
-- endpoint, and multiple vm_asset rows per ip, must not multiply endpoint
-- counts (exposure_estimate counts endpoints). Any-true wins for observed:
-- one live confirmation outweighs another source's negative.
LEFT JOIN (
    SELECT run_id, ip
    FROM ext_telecom_offsec_asmvm_vm_asset
    GROUP BY run_id, ip
) v
    ON v.ip = s.ip
   AND v.run_id = s.run_id
LEFT JOIN (
    SELECT run_id, ip, port, protocol,
           MAX(CAST(observed AS BOOLEAN)) AS observed
    FROM ext_telecom_offsec_asmvm_service_observation
    WHERE CAST(is_active AS BOOLEAN)
    GROUP BY run_id, ip, port, protocol
) o
    ON o.ip = s.ip
   AND o.port = s.port
   AND o.protocol = s.protocol
   AND o.run_id = s.run_id
WHERE s.run_id = ?1
  AND CAST(s.is_active AS BOOLEAN)
  AND s.port IN (21, 22, 23, 25, 69, 110, 111, 135, 137, 139, 143, 161, 162, 389,
                 445, 512, 513, 514, 636, 873, 993, 995, 1433, 1521, 1723, 2049,
                 2181, 2375, 2376, 3306, 3389, 4444, 5432, 5601, 5672, 5900, 5901,
                 5902, 5984, 5985, 5986, 6379, 8080, 9000, 9092, 9200, 11211,
                 15672, 27017, 50000, 50070,
                 -- WinRM-HTTP 7680 is in the same class as 5985/5986
                 -- Telecom control-plane ports are handled by a separate check; see
                 -- ext_telecom_offsec_asmvm_t1_telecom_control_plane_exposed.sql.
                 7680)
GROUP BY s.protocol, s.port, s.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
