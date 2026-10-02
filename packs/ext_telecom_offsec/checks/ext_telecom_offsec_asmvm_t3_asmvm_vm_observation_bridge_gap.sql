-- ext_telecom_offsec_asmvm_t3_asmvm_vm_observation_bridge_gap.sql - T3
--
-- Evidence-integrity guard for Finding T: the vm_cve_observation rollup columns
-- (finding_count, n_findings, n_external_findings, n_unknown_context_findings,
-- scan_networks) must agree with the pair's own contributing rows. The silver
-- builder derives them from the CVE explosion, but the pack's bridge table
-- `ext_telecom_offsec_asmvm_vm_cve_finding` is keyed on (run_id, accept_event_id, ip,
-- cve, finding_id), so it holds DISTINCT contributing findings; a projection
-- that counts repeated bronze payload entries instead of distinct findings will
-- disagree with its own evidence. Recompute with
-- count(DISTINCT finding_id), never count(*).
--
-- Reasons, one aggregate row each:
--   observation_without_bridge_coverage            obs pair has no contributing findings at all
--   bridge_pair_without_observation                contribution with no projected observation
--   bridge_finding_without_vm_source               exploded finding has no VM source row
--   legacy_finding_count_disagrees_with_recompute  deprecated alias drift
--   n_findings_disagrees_with_recompute
--   n_external_findings_disagrees_with_recompute
--   n_unknown_context_findings_disagrees_with_recompute
--   scan_networks_missing_contributor_token        a named contributor network absent from the list
--   scan_networks_cardinality_mismatch             token count != distinct contributor names
--         (together with forward membership this makes spurious or duplicate tokens visible;
--          ordering itself is not asserted - it is a rendering choice, not a fact)
--   scan_networks_unverifiable_comma_name           a contributor name contains the
--         unescaped list delimiter, so token membership/cardinality cannot be proved
--
-- Portable by construction: no string_agg/group_concat/split; null-safe compares via
-- `(x <> y OR (x IS NULL) <> (y IS NULL))`. Bound params: ?1 run_id, ?2 row limit.

WITH contrib AS (
    SELECT b.run_id, b.ip, b.cve,
           count(DISTINCT b.finding_id) AS n_findings,
           count(DISTINCT CASE WHEN lower(coalesce(f.scan_network_name, '')) LIKE '%external%'
                               THEN b.finding_id END) AS n_external,
           count(DISTINCT CASE WHEN f.scan_network_name IS NULL
                                    OR trim(f.scan_network_name) = ''
                               THEN b.finding_id END) AS n_unknown,
           count(DISTINCT CASE WHEN f.finding_id IS NULL
                               THEN b.finding_id END) AS n_orphan,
           count(DISTINCT nullif(trim(f.scan_network_name), '')) AS n_networks,
           max(CASE WHEN instr(coalesce(f.scan_network_name, ''), ',') > 0
                    THEN 1 ELSE 0 END) AS has_comma_name
    FROM ext_telecom_offsec_asmvm_vm_cve_finding b
    LEFT JOIN ext_telecom_offsec_asmvm_vm_finding f
           ON f.finding_id = b.finding_id AND f.run_id = b.run_id
          AND f.ip = b.ip
    GROUP BY b.run_id, b.ip, b.cve
),
names AS (
    SELECT DISTINCT b.run_id, b.ip, b.cve,
           nullif(trim(f.scan_network_name), '') AS net_name
    FROM ext_telecom_offsec_asmvm_vm_cve_finding b
    LEFT JOIN ext_telecom_offsec_asmvm_vm_finding f
           ON f.finding_id = b.finding_id AND f.run_id = b.run_id
          AND f.ip = b.ip
    WHERE nullif(trim(f.scan_network_name), '') IS NOT NULL
),
gaps AS (
    SELECT o.run_id, o.ip, o.cve,
           'observation_without_bridge_coverage' AS reason
    FROM ext_telecom_offsec_asmvm_vm_cve_observation o
    LEFT JOIN contrib r ON r.ip = o.ip AND r.cve = o.cve AND r.run_id = o.run_id
    WHERE o.run_id = ?1 AND r.ip IS NULL

    UNION ALL
    SELECT r.run_id, r.ip, r.cve,
           'bridge_pair_without_observation'
    FROM contrib r
    LEFT JOIN ext_telecom_offsec_asmvm_vm_cve_observation o
           ON o.ip = r.ip AND o.cve = r.cve AND o.run_id = r.run_id
    WHERE r.run_id = ?1 AND o.ip IS NULL

    UNION ALL
    SELECT r.run_id, r.ip, r.cve,
           'bridge_finding_without_vm_source'
    FROM contrib r
    WHERE r.run_id = ?1 AND r.n_orphan > 0

    UNION ALL
    SELECT o.run_id, o.ip, o.cve,
           CASE WHEN (o.n_findings <> r.n_findings)
                     OR ((o.n_findings IS NULL) <> (r.n_findings IS NULL))
                THEN 'n_findings_disagrees_with_recompute'
                WHEN (o.finding_count <> r.n_findings)
                     OR ((o.finding_count IS NULL) <> (r.n_findings IS NULL))
                THEN 'legacy_finding_count_disagrees_with_recompute'
                ELSE NULL END AS reason
    FROM ext_telecom_offsec_asmvm_vm_cve_observation o
    JOIN contrib r ON r.ip = o.ip AND r.cve = o.cve AND r.run_id = o.run_id
    WHERE o.run_id = ?1

    UNION ALL
    SELECT o.run_id, o.ip, o.cve, 'n_external_findings_disagrees_with_recompute'
    FROM ext_telecom_offsec_asmvm_vm_cve_observation o
    JOIN contrib r ON r.ip = o.ip AND r.cve = o.cve AND r.run_id = o.run_id
    WHERE o.run_id = ?1
      AND ((o.n_external_findings <> r.n_external)
           OR ((o.n_external_findings IS NULL) <> (r.n_external IS NULL)))

    UNION ALL
    SELECT o.run_id, o.ip, o.cve, 'n_unknown_context_findings_disagrees_with_recompute'
    FROM ext_telecom_offsec_asmvm_vm_cve_observation o
    JOIN contrib r ON r.ip = o.ip AND r.cve = o.cve AND r.run_id = o.run_id
    WHERE o.run_id = ?1
      AND ((o.n_unknown_context_findings <> r.n_unknown)
           OR ((o.n_unknown_context_findings IS NULL) <> (r.n_unknown IS NULL)))

    UNION ALL
    SELECT r.run_id, r.ip, r.cve, 'scan_networks_unverifiable_comma_name'
    FROM contrib r
    JOIN ext_telecom_offsec_asmvm_vm_cve_observation o
         ON o.ip = r.ip AND o.cve = r.cve AND o.run_id = r.run_id
    WHERE o.run_id = ?1 AND r.has_comma_name = 1

    UNION ALL
    SELECT nm.run_id, nm.ip, nm.cve, 'scan_networks_missing_contributor_token'
    FROM names nm
    JOIN ext_telecom_offsec_asmvm_vm_cve_observation o
         ON o.ip = nm.ip AND o.cve = nm.cve AND o.run_id = nm.run_id
    JOIN contrib r ON r.ip = nm.ip AND r.cve = nm.cve AND r.run_id = nm.run_id
    WHERE o.run_id = ?1
      AND r.has_comma_name = 0
      AND instr(',' || coalesce(o.scan_networks, '') || ',',
                ',' || nm.net_name || ',') = 0

    UNION ALL
    SELECT o.run_id, o.ip, o.cve, 'scan_networks_cardinality_mismatch'
    FROM ext_telecom_offsec_asmvm_vm_cve_observation o
    JOIN contrib r ON r.ip = o.ip AND r.cve = o.cve AND r.run_id = o.run_id
    WHERE o.run_id = ?1
      AND r.has_comma_name = 0
      AND CASE WHEN coalesce(o.scan_networks, '') = '' THEN 0
               ELSE length(o.scan_networks)
                    - length(replace(o.scan_networks, ',', '')) + 1 END
          <> r.n_networks
),
hits AS (
    SELECT * FROM gaps WHERE reason IS NOT NULL
)
SELECT
    'asmvm:observation-bridge-gap:' || d.reason AS finding_key,
    'VM CVE observation lineage disagrees with its contributing findings' AS title,
    COUNT(*) AS affected_count,
    COUNT(DISTINCT d.ip) AS exposure_estimate,
    'ext_telecom_offsec_asmvm_vm_cve_observation[reason=' || d.reason || ']' AS record_locator,
    'affected_ips=' || CAST(COUNT(DISTINCT d.ip) AS VARCHAR) ||
    '; contributor_pairs=' || CAST(COUNT(*) AS VARCHAR) ||
    '; reason=' || d.reason ||
    '; contract=rollups must equal count(DISTINCT finding_id) over ext_telecom_offsec_asmvm_vm_cve_finding' ||
    '; contract_reference=schema/migrations/002_ext_telecom_offsec_asmvm_vm_silver.sql' AS details,
    d.run_id AS run_id,
    40 AS risk_score
FROM hits d
GROUP BY d.reason, d.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
