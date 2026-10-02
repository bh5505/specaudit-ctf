-- Missing, inconclusive, contradicted, or ambiguous independent validation.
-- A missing result is a coverage gap, never a clean finding disposition.
-- ?1 = current pack run, ?2 = row limit.
WITH validation_by_finding AS (
    SELECT
        v.run_id, v.engagement_id, v.validator_project_id,
        v.validator_engagement_id, v.finding_id, v.source_run_id,
        v.inventory_snapshot_id, v.rule_id, v.provider, v.resource_uid,
        MIN(v.account_id) AS account_id,
        COUNT(*) AS result_count,
        MIN(v.configuration_status) AS configuration_status,
        MIN(v.reachability_status) AS reachability_status,
        MIN(v.verdict) AS verdict
    FROM ext_telecom_offsec_technology_validation v
    WHERE v.run_id = ?1
    GROUP BY v.run_id, v.engagement_id, v.validator_project_id,
        v.validator_engagement_id, v.finding_id,
        v.source_run_id, v.inventory_snapshot_id, v.rule_id,
        v.provider, v.resource_uid
)
SELECT
    'technology:validation-gap:' || c.rule_id || ':' || c.finding_id AS finding_key,
    'Technology finding requires validator disposition: ' || c.rule_id AS title,
    1 AS affected_count,
    NULL AS exposure_estimate,
    c.finding_id || ' / ' || c.rule_id || ' / ' || COALESCE(c.resource_uid, '') AS record_locator,
    'validation=' || CASE
        WHEN c.validator_project_id = '' OR c.validator_engagement_id = ''
            THEN 'invalid_validator_scope'
        WHEN c.validator_engagement_id <> c.engagement_id
            THEN 'engagement_scope_mismatch'
        WHEN COALESCE(c.source_run_id, '') = '' THEN 'missing_source_run_id'
        WHEN COALESCE(c.resource_uid, '') = '' THEN 'missing_resource_uid'
        WHEN v.result_count IS NULL THEN 'missing'
        WHEN v.result_count <> 1 THEN 'ambiguous_multiple_results'
        WHEN v.configuration_status = 'refuted' THEN 'source_claim_contradicted'
        WHEN v.configuration_status = 'unknown' THEN 'inconclusive'
        WHEN v.configuration_status NOT IN ('confirmed', 'refuted', 'unknown') THEN 'invalid_status'
        WHEN v.reachability_status NOT IN ('observed', 'blocked', 'unknown') THEN 'invalid_reachability'
        WHEN COALESCE(c.account_id, '') = '' THEN 'missing_account_scope'
        WHEN c.rule_id = 'AWS-NET-001' AND UPPER(COALESCE(c.severity, '')) = 'CRITICAL'
             AND v.reachability_status <> 'observed' THEN 's3_critical_exposure_unverified'
        ELSE 'unclassified'
    END ||
    '; configuration=' || COALESCE(v.configuration_status, 'none') ||
    '; reachability=' || COALESCE(v.reachability_status, 'none') ||
    '; account=' || COALESCE(c.account_id, 'unknown') ||
    '; validator_project=' || c.validator_project_id ||
    '; validator_engagement=' || c.validator_engagement_id ||
    '; source_run=' || COALESCE(c.source_run_id, '') ||
    '; snapshot=' || c.inventory_snapshot_id AS details,
    c.run_id AS run_id,
    42 AS risk_score
FROM ext_telecom_offsec_technology_candidate c
LEFT JOIN validation_by_finding v
  ON v.run_id = c.run_id
 AND v.engagement_id = c.engagement_id
 AND v.validator_project_id = c.validator_project_id
 AND v.validator_engagement_id = c.validator_engagement_id
 AND v.finding_id = c.finding_id
 AND v.source_run_id = c.source_run_id
 AND v.inventory_snapshot_id = c.inventory_snapshot_id
 AND v.rule_id = c.rule_id
 AND v.provider = c.provider
 AND v.resource_uid = c.resource_uid
 AND (v.account_id = c.account_id OR (v.account_id IS NULL AND c.account_id IS NULL))
WHERE c.run_id = ?1
  AND c.rule_id IN ('AWS-NET-001', 'AWS-NET-010', 'AWS-NET-011', 'GCP-IAM-001', 'AZURE-NET-002')
  AND (
       c.validator_project_id = ''
       OR c.validator_engagement_id = ''
       OR c.validator_engagement_id <> c.engagement_id
       OR COALESCE(c.source_run_id, '') = ''
       OR COALESCE(c.resource_uid, '') = ''
       OR COALESCE(c.account_id, '') = ''
       OR v.result_count IS NULL
       OR v.result_count <> 1
       OR v.configuration_status <> 'confirmed'
       OR v.configuration_status IS NULL
       OR v.reachability_status NOT IN ('observed', 'blocked', 'unknown')
       OR v.reachability_status IS NULL
       OR (c.rule_id = 'AWS-NET-001' AND UPPER(COALESCE(c.severity, '')) = 'CRITICAL'
           AND v.reachability_status <> 'observed')
  )
ORDER BY finding_key
LIMIT ?2;
