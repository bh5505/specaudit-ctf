-- Independent validator results for a bounded Technology rule set.
-- A confirmed configuration is not proof of practical reachability.
-- ?1 = current pack run, ?2 = row limit.
WITH candidate_scope AS (
    SELECT c.run_id, c.engagement_id, c.validator_project_id,
           c.validator_engagement_id, c.finding_id, c.source_run_id,
           c.inventory_snapshot_id, c.rule_id, c.provider, c.resource_uid,
           c.account_id,
           MIN(COALESCE(c.region, '')) AS region,
           COUNT(DISTINCT COALESCE(c.region, '')) AS region_variants,
           MAX(CASE WHEN UPPER(COALESCE(c.severity, '')) = 'CRITICAL'
                    THEN 1 ELSE 0 END) AS critical_seen,
           CAST(LENGTH(c.engagement_id) AS VARCHAR) || ':' || c.engagement_id ||
           CAST(LENGTH(c.validator_project_id) AS VARCHAR) || ':' || c.validator_project_id ||
           CAST(LENGTH(c.validator_engagement_id) AS VARCHAR) || ':' || c.validator_engagement_id ||
           CAST(LENGTH(c.finding_id) AS VARCHAR) || ':' || c.finding_id ||
           CASE WHEN c.source_run_id IS NULL THEN '-1:'
                ELSE CAST(LENGTH(c.source_run_id) AS VARCHAR) || ':' || c.source_run_id END ||
           CAST(LENGTH(c.inventory_snapshot_id) AS VARCHAR) || ':' || c.inventory_snapshot_id ||
           CAST(LENGTH(c.rule_id) AS VARCHAR) || ':' || c.rule_id ||
           CAST(LENGTH(c.provider) AS VARCHAR) || ':' || c.provider ||
           CASE WHEN c.resource_uid IS NULL THEN '-1:'
                ELSE CAST(LENGTH(c.resource_uid) AS VARCHAR) || ':' || c.resource_uid END ||
           CASE WHEN c.account_id IS NULL THEN '-1:'
                ELSE CAST(LENGTH(c.account_id) AS VARCHAR) || ':' || c.account_id END AS identity_key
    FROM ext_telecom_offsec_technology_candidate c
    WHERE c.run_id = ?1
    GROUP BY c.run_id, c.engagement_id, c.validator_project_id,
             c.validator_engagement_id, c.finding_id, c.source_run_id,
             c.inventory_snapshot_id, c.rule_id, c.provider, c.resource_uid,
             c.account_id
),
validation_by_finding AS (
    SELECT
        v.run_id, v.engagement_id, v.validator_project_id,
        v.validator_engagement_id, v.finding_id, v.source_run_id,
        v.inventory_snapshot_id, v.rule_id, v.provider, v.resource_uid,
        v.account_id,
        MIN(COALESCE(v.region, '')) AS region,
        COUNT(DISTINCT COALESCE(v.region, '')) AS region_variants,
        COUNT(DISTINCT v.attempt_id) AS result_count,
        COUNT(DISTINCT v.configuration_status) AS configuration_variants,
        COUNT(DISTINCT v.reachability_status) AS reachability_variants,
        COUNT(DISTINCT v.verdict) AS verdict_variants,
        COUNT(DISTINCT v.receipt_sha256) AS receipt_variants,
        MIN(v.configuration_status) AS configuration_status,
        MIN(v.reachability_status) AS reachability_status,
        MIN(v.verdict) AS verdict,
        MIN(v.attempt_id) AS attempt_id,
        MIN(v.receipt_sha256) AS receipt_sha256
    FROM ext_telecom_offsec_technology_validation v
    WHERE v.run_id = ?1
    GROUP BY v.run_id, v.engagement_id, v.validator_project_id,
        v.validator_engagement_id, v.finding_id,
        v.source_run_id, v.inventory_snapshot_id, v.rule_id,
        v.provider, v.resource_uid, v.account_id
)
SELECT
    'technology:validated:' || c.identity_key AS finding_key,
    CASE c.rule_id
        WHEN 'AWS-NET-001' THEN 'S3 public-access condition independently checked: ' || c.resource_uid
        WHEN 'AWS-NET-010' THEN 'AWS public SSH ingress independently checked: ' || c.resource_uid
        WHEN 'AWS-NET-011' THEN 'AWS public RDP ingress independently checked: ' || c.resource_uid
        WHEN 'GCP-IAM-001' THEN 'GCP public-principal binding independently checked: ' || c.resource_uid
        ELSE 'Azure management NSG rule independently checked: ' || c.resource_uid
    END AS title,
    1 AS affected_count,
    CASE v.reachability_status WHEN 'observed' THEN 1 WHEN 'blocked' THEN 0 END AS exposure_estimate,
    c.finding_id || ' / ' || c.rule_id || ' / ' || c.resource_uid AS record_locator,
    'configuration=' || v.configuration_status ||
        '; reachability=' || v.reachability_status ||
        '; verdict=' || v.verdict ||
        '; account=' || c.account_id ||
        '; validator_project=' || c.validator_project_id ||
        '; validator_engagement=' || c.validator_engagement_id ||
        '; source_run=' || c.source_run_id ||
        '; snapshot=' || c.inventory_snapshot_id ||
        '; attempt=' || v.attempt_id ||
        '; receipt_sha256=' || v.receipt_sha256 AS details,
    c.run_id AS run_id,
    CASE WHEN v.reachability_status = 'observed' THEN 60 ELSE 44 END AS risk_score
FROM candidate_scope c
JOIN validation_by_finding v
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
  AND c.validator_project_id <> ''
  AND c.validator_engagement_id = c.engagement_id
  AND COALESCE(c.source_run_id, '') <> ''
  AND COALESCE(c.resource_uid, '') <> ''
  AND COALESCE(c.account_id, '') <> ''
  AND (c.rule_id <> 'AZURE-NET-002' OR
       (c.region_variants = 1 AND c.region <> ''
        AND v.region_variants = 1 AND v.region = c.region))
  AND c.rule_id IN ('AWS-NET-001', 'AWS-NET-010', 'AWS-NET-011', 'GCP-IAM-001', 'AZURE-NET-002')
  AND v.result_count = 1
  AND v.configuration_variants = 1
  AND v.reachability_variants = 1
  AND v.verdict_variants = 1
  AND v.receipt_variants = 1
  AND v.configuration_status = 'confirmed'
  AND v.verdict IN ('CONFIRMED_CONFIGURATION',
                    'CONFIRMED_REAL_EXPLOITABLE', 'CONFIRMED_GAP_NOT_EXPLOITABLE')
  AND v.reachability_status IN ('observed', 'blocked', 'unknown')
  AND (v.verdict <> 'CONFIRMED_REAL_EXPLOITABLE'
       OR v.reachability_status = 'observed')
  AND (v.verdict <> 'CONFIRMED_GAP_NOT_EXPLOITABLE'
       OR v.reachability_status = 'blocked')
ORDER BY finding_key
LIMIT ?2;
