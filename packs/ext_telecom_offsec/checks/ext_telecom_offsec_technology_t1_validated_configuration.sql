-- Independent validator results for a bounded Technology rule set.
-- A confirmed configuration is not proof of practical reachability.
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
        MIN(v.verdict) AS verdict,
        MIN(v.attempt_id) AS attempt_id,
        MIN(v.receipt_sha256) AS receipt_sha256
    FROM ext_telecom_offsec_technology_validation v
    WHERE v.run_id = ?1
    GROUP BY v.run_id, v.engagement_id, v.validator_project_id,
        v.validator_engagement_id, v.finding_id,
        v.source_run_id, v.inventory_snapshot_id, v.rule_id,
        v.provider, v.resource_uid
)
SELECT
    'technology:validated:' || c.rule_id || ':' || c.finding_id AS finding_key,
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
FROM ext_telecom_offsec_technology_candidate c
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
  AND c.rule_id IN ('AWS-NET-001', 'AWS-NET-010', 'AWS-NET-011', 'GCP-IAM-001', 'AZURE-NET-002')
  AND v.result_count = 1
  AND v.configuration_status = 'confirmed'
  AND v.reachability_status IN ('observed', 'blocked', 'unknown')
ORDER BY finding_key
LIMIT ?2;
