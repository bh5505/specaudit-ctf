-- Technique-bearing alert context now reaches confirmed service candidates,
-- but the flagship and T1 predicates do not consume this context yet.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'asmvm:technique-context-gap:' || c.ip || ':' ||
        COALESCE(CAST(c.port AS VARCHAR), 'unknown') AS finding_key,
    'Technique context is not consumed for service ' || c.ip || ':' ||
        COALESCE(CAST(c.port AS VARCHAR), 'unknown') AS title,
    CAST(COUNT(*) AS BIGINT) AS affected_count,
    1 AS exposure_estimate,
    c.ip || ':' || COALESCE(CAST(c.port AS VARCHAR), 'unknown') ||
        ' / service:' || COALESCE(MIN(c.service_ref), 'unknown') AS record_locator,
    'technique=' || COALESCE(MIN(c.mitre_technique), 'unknown') ||
    '; tactic=' || COALESCE(MIN(c.mitre_tactic), 'unknown') ||
    '; provenance_class=' || MIN(c.provenance_class) ||
    '; gap_count=' || CAST(COUNT(*) AS VARCHAR) ||
    '; consumer_predicate=absent' AS details,
    c.run_id AS run_id,
    40 AS risk_score
FROM ext_telecom_offsec_asmvm_vm_technique_context c
WHERE c.run_id = ?1
GROUP BY c.run_id, c.ip, c.port
ORDER BY risk_score DESC, finding_key
LIMIT ?2;
