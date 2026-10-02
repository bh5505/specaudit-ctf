-- ext_telecom_offsec_asmvm_t2_asmvm_initial_access_convergence.sql - cross-corroborated
-- initial access on the same address.
--
-- A host is most actionable when its alert-asserted technique context includes an
-- initial-access technique (T1190 exploit public-facing app / T1110 brute force /
-- T1203 client RCE) AND it carries a CVE observation with corroborating provenance
-- (scan_corroborated, probe_corroborated or banner_asserted_inference) on the same address. This flags
-- the cross-corroborated initial-access population. The specaudit-ctf
-- target-analysis layer (tools/demo_target_analysis.py) then confirms each flagged
-- (ip, technique) with the Finding E curated CVE->technique map, so this pack check
-- is the durable signal layer and the tool is the durable confirmation layer.
--
-- Tables: ext_telecom_offsec_asmvm_vm_technique_context (migration 005) +
-- ext_telecom_offsec_asmvm_cve_observation_provenance (migration 006). The technique
-- context is alert-derived provenance; the CVE side is scan/probe/banner-corroborated
-- so banner context is the second source here, never the first.
-- Bound params: ?1 = run_id, ?2 = row limit.
-- Engine-portable SQL (equality / LIKE / CASE; no string_agg/group_concat).

WITH ia AS (
    SELECT DISTINCT
        run_id, ip, port, mitre_technique, mitre_tactic, provenance_class
    FROM ext_telecom_offsec_asmvm_vm_technique_context
    WHERE run_id = ?1
      AND (mitre_technique LIKE 'T1190%'
           OR mitre_technique LIKE 'T1110%'
           OR mitre_technique LIKE 'T1203%'
           OR mitre_tactic LIKE 'TA0001%')
),
cve AS (
    SELECT DISTINCT
        run_id, ip, cve, provenance_class
    FROM ext_telecom_offsec_asmvm_cve_observation_provenance
    WHERE run_id = ?1
      AND CAST(is_active AS BOOLEAN)
      AND provenance_class IN ('scan_corroborated', 'probe_corroborated', 'banner_asserted_inference')
)
SELECT
    'asmvm:initial-access-convergence:' || ia.ip  AS finding_key,
    'Alert-asserted initial access on a CVE-corroborated address: ' || ia.ip AS title,
    CAST(1 AS BIGINT)                             AS affected_count,
    CAST(1 AS BIGINT)                             AS exposure_estimate,
    'ip:' || ia.ip || ' / technique:' || MAX(ia.mitre_technique) AS record_locator,
    'technique=' || MAX(ia.mitre_technique) ||
    '; tactic=' || MAX(ia.mitre_tactic) ||
    '; technique_provenance=' || MAX(ia.provenance_class) ||
    '; corroborated_cves=' || CAST(COUNT(DISTINCT cve.cve) AS VARCHAR) ||
    '; validation=target_analysis_curated_map_confirm_required' AS details,
    ia.run_id                                     AS run_id,
    CAST(55 AS BIGINT)                            AS risk_score
FROM ia
JOIN cve
  ON cve.run_id = ia.run_id
 AND cve.ip = ia.ip
GROUP BY ia.ip, ia.run_id
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
