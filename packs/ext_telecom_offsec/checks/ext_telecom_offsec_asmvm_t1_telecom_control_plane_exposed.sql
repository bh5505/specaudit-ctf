-- ext_telecom_offsec_asmvm_t1_telecom_control_plane_exposed.sql - T1 (threat-
-- model-first trust boundary), telecom control-plane analogue of
-- ext_telecom_offsec_asmvm_t1_exposed_mgmt_ports.
--
-- The restricted-service list includes administration, data, and peer ports.
-- A telecom estate has a second reachable plane that the list does not name:
-- subscriber-edge CPE management (CWMP/TR-069), call
-- signalling (SIP/SIPS), the core (GTP-C, GTP-U, GTP'/NCP, Diameter), the timing
-- plane (NTP), name resolution (DNS), and the IPsec anchors (IKE / NAT-T).
-- The control-plane and unattributed-exposure findings can compound: an
-- exposed service with no attributable owner may lack a remediation path.
--
-- Grouping is class + protocol + port, because the remediation and the risk are
-- per class, not per port: exposing Diameter is not like exposing NTP. The
-- classes are CAP-PARAM (engagement_configs/default.yaml
-- `telecom_control_plane_ports`); the literal rows below must stay in sync.
-- IKE/NAT-T are reported at the bottom of the risk order on purpose: a VPN
-- anchor is *expected* to answer from the internet, and the finding there is
-- attribution and allow-listing, not existence.
--
-- Observed reachability, not configured reachability: an ASM feed shows what
-- answers, which is stronger evidence than a security-group rule review. Every
-- row still says `validation=live_probe_required`, because "answers on the
-- internet" is the ASM claim, not a banner we took ourselves.
--
-- Tables: ext_telecom_offsec_asmvm_service_endpoint, ext_telecom_offsec_asmvm_vm_asset,
-- ext_telecom_offsec_asmvm_service_observation (P7, pre-aggregated).
-- Bound params: ?1 = run_id, ?2 = row limit.

WITH telecom_ports(class_key, class_label, class_risk, port) AS (
    -- core signalling: should never answer on the public internet
    SELECT 'gtp_core', 'GTP/GTP-prime/Diameter core signalling', 58, 2123 UNION ALL
    SELECT 'gtp_core', 'GTP/GTP-prime/Diameter core signalling', 58, 2152 UNION ALL
    SELECT 'gtp_core', 'GTP/GTP-prime/Diameter core signalling', 58, 20001 UNION ALL
    SELECT 'gtp_core', 'GTP/GTP-prime/Diameter core signalling', 58, 3868 UNION ALL
    -- subscriber-edge CPE management plane (CWMP/TR-069 and its HTTP variants)
    SELECT 'cpe_management', 'CWMP/TR-069 CPE management plane', 56, 7547 UNION ALL
    SELECT 'cpe_management', 'CWMP/TR-069 CPE management plane', 56, 8200 UNION ALL
    SELECT 'cpe_management', 'CWMP/TR-069 CPE management plane', 56, 8201 UNION ALL
    -- call signalling
    SELECT 'signalling', 'SIP call signalling', 55, 5060 UNION ALL
    SELECT 'signalling', 'SIP call signalling', 55, 5061 UNION ALL
    -- timing plane (amplification and drift)
    SELECT 'timing', 'NTP timing plane', 45, 123 UNION ALL
    -- name resolution (amplification, disclosure)
    SELECT 'resolver', 'DNS resolution service', 42, 53 UNION ALL
    -- expected to answer; the finding is attribution and allow-listing
    SELECT 'vpn_anchor', 'IKE / IPsec NAT-T anchor', 35, 500 UNION ALL
    SELECT 'vpn_anchor', 'IKE / IPsec NAT-T anchor', 35, 4500
)
SELECT
    'asmvm:telecom-control:' || p.class_key || ':' || s.protocol || ':' ||
        CAST(s.port AS VARCHAR)                     AS finding_key,
    'Telecom ' || p.class_label ||
        ' reachable from the internet: ' ||
        CAST(s.port AS VARCHAR) || '/' || s.protocol AS title,
    COUNT(DISTINCT s.ip)                            AS affected_count,
    COUNT(*)                                        AS exposure_estimate,
    'telecom-control:' || p.class_key || ':' || s.protocol || ':' ||
        CAST(s.port AS VARCHAR)                     AS record_locator,
    'class=' || p.class_key ||
    '; exposed_endpoints=' || CAST(COUNT(*) AS VARCHAR) ||
    '; ips=' || CAST(COUNT(DISTINCT s.ip) AS VARCHAR) ||
    '; ips_not_in_vm_estate=' ||
        CAST(COUNT(DISTINCT CASE WHEN v.ip IS NULL THEN s.ip END) AS VARCHAR) ||
    '; observed_ips=' ||
        CAST(COUNT(DISTINCT CASE WHEN CAST(o.observed AS BOOLEAN) THEN s.ip END) AS VARCHAR) ||
    '; predicted_ips=' ||
        CAST(COUNT(DISTINCT CASE WHEN o.observed IS NULL OR NOT CAST(o.observed AS BOOLEAN) THEN s.ip END) AS VARCHAR) ||
    '; max_inferred_cvss=' ||
        CAST(ROUND(COALESCE(MAX(s.inferred_vuln_score), 0), 1) AS VARCHAR) ||
    '; services=' ||
        CAST(COUNT(DISTINCT COALESCE(s.service_name, s.service_type)) AS VARCHAR) ||
    '; sample_service=' || COALESCE(MAX(s.service_name), '') ||
    '; validation=live_probe_required'              AS details,
    s.run_id                                        AS run_id,
    -- P7 predicted-vs-observed: a live observation corroborates the exposure
    -- (higher score, capped at the 60 band ceiling); a source-declared prediction
    -- with no observation stays unconfirmed (lower score).
    CASE WHEN COUNT(DISTINCT CASE WHEN CAST(o.observed AS BOOLEAN) THEN s.ip END) > 0
         THEN CASE WHEN p.class_risk + 5 < 60 THEN p.class_risk + 5 ELSE 60 END
         ELSE p.class_risk - 5 END AS risk_score
FROM ext_telecom_offsec_asmvm_service_endpoint s
JOIN telecom_ports p
    ON p.port = s.port
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
GROUP BY p.class_key, p.class_label, p.class_risk, s.protocol, s.port, s.run_id
ORDER BY risk_score DESC, exposure_estimate DESC, finding_key
LIMIT ?2;
