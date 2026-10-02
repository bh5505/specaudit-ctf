-- Missing, inconclusive, contradicted, or ambiguous independent validation,
-- plus incomplete import of the bridge's scoped candidate inventory.
-- ?1 = current pack run, ?2 = row limit.
WITH candidate_scope AS (
    SELECT c.run_id, c.engagement_id, c.validator_project_id,
           c.validator_engagement_id, c.finding_id, c.source_run_id,
           c.inventory_snapshot_id, c.rule_id, c.provider, c.resource_uid,
           c.account_id,
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
        COUNT(DISTINCT v.attempt_id) AS result_count,
        COUNT(DISTINCT v.configuration_status) AS configuration_variants,
        COUNT(DISTINCT v.reachability_status) AS reachability_variants,
        COUNT(DISTINCT v.verdict) AS verdict_variants,
        COUNT(DISTINCT v.receipt_sha256) AS receipt_variants,
        MIN(v.configuration_status) AS configuration_status,
        MIN(v.reachability_status) AS reachability_status,
        MIN(v.verdict) AS verdict
    FROM ext_telecom_offsec_technology_validation v
    WHERE v.run_id = ?1
    GROUP BY v.run_id, v.engagement_id, v.validator_project_id,
        v.validator_engagement_id, v.finding_id,
        v.source_run_id, v.inventory_snapshot_id, v.rule_id,
        v.provider, v.resource_uid, v.account_id
),
candidate_members AS (
    SELECT DISTINCT run_id, engagement_id, validator_project_id,
           validator_engagement_id, inventory_snapshot_id, finding_id,
           COALESCE(source_run_id, '') AS source_run_id, rule_id, provider,
           COALESCE(resource_uid, '') AS resource_uid,
           COALESCE(account_id, '') AS account_id,
           COALESCE(region, '') AS region,
           COALESCE(severity, '') AS severity,
           COALESCE(title, '') AS title
    FROM ext_telecom_offsec_technology_candidate
    WHERE run_id = ?1
),
expected_members AS (
    SELECT DISTINCT run_id, engagement_id, validator_project_id,
           validator_engagement_id, inventory_snapshot_id, finding_id,
           COALESCE(source_run_id, '') AS source_run_id, rule_id, provider,
           COALESCE(resource_uid, '') AS resource_uid,
           COALESCE(account_id, '') AS account_id,
           COALESCE(region, '') AS region,
           COALESCE(severity, '') AS severity,
           COALESCE(title, '') AS title
    FROM ext_telecom_offsec_technology_inventory_member
    WHERE run_id = ?1
),
candidate_counts AS (
    SELECT run_id, engagement_id, validator_project_id,
           validator_engagement_id, inventory_snapshot_id, COUNT(*) AS actual_count
    FROM candidate_members
    GROUP BY run_id, engagement_id, validator_project_id,
             validator_engagement_id, inventory_snapshot_id
),
member_counts AS (
    SELECT run_id, engagement_id, validator_project_id,
           validator_engagement_id, inventory_snapshot_id, COUNT(*) AS member_count
    FROM expected_members
    GROUP BY run_id, engagement_id, validator_project_id,
             validator_engagement_id, inventory_snapshot_id
),
unmatched_actual AS (
    SELECT c.run_id, c.engagement_id, c.validator_project_id,
           c.validator_engagement_id, c.inventory_snapshot_id,
           COUNT(*) AS unmatched_count
    FROM candidate_members c
    WHERE NOT EXISTS (
        SELECT 1 FROM expected_members m
        WHERE m.run_id = c.run_id AND m.engagement_id = c.engagement_id
          AND m.validator_project_id = c.validator_project_id
          AND m.validator_engagement_id = c.validator_engagement_id
          AND m.inventory_snapshot_id = c.inventory_snapshot_id
          AND m.finding_id = c.finding_id AND m.source_run_id = c.source_run_id
          AND m.rule_id = c.rule_id AND m.provider = c.provider
          AND m.resource_uid = c.resource_uid AND m.account_id = c.account_id
          AND m.region = c.region AND m.severity = c.severity AND m.title = c.title
    )
    GROUP BY c.run_id, c.engagement_id, c.validator_project_id,
             c.validator_engagement_id, c.inventory_snapshot_id
),
unmatched_expected AS (
    SELECT m.run_id, m.engagement_id, m.validator_project_id,
           m.validator_engagement_id, m.inventory_snapshot_id,
           COUNT(*) AS unmatched_count
    FROM expected_members m
    WHERE NOT EXISTS (
        SELECT 1 FROM candidate_members c
        WHERE c.run_id = m.run_id AND c.engagement_id = m.engagement_id
          AND c.validator_project_id = m.validator_project_id
          AND c.validator_engagement_id = m.validator_engagement_id
          AND c.inventory_snapshot_id = m.inventory_snapshot_id
          AND c.finding_id = m.finding_id AND c.source_run_id = m.source_run_id
          AND c.rule_id = m.rule_id AND c.provider = m.provider
          AND c.resource_uid = m.resource_uid AND c.account_id = m.account_id
          AND c.region = m.region AND c.severity = m.severity AND c.title = m.title
    )
    GROUP BY m.run_id, m.engagement_id, m.validator_project_id,
             m.validator_engagement_id, m.inventory_snapshot_id
),
receipt_scope AS (
    SELECT run_id, engagement_id, validator_project_id,
           validator_engagement_id, inventory_snapshot_id,
           COUNT(*) AS receipt_rows,
           COUNT(DISTINCT inventory_membership_id) AS membership_variants,
           COUNT(DISTINCT source_inventory_total) AS total_variants,
           COUNT(DISTINCT expected_eligible_candidates) AS expected_variants,
           COUNT(DISTINCT candidate_identity_sha256) AS digest_variants,
           MIN(inventory_membership_id) AS inventory_membership_id,
           MIN(source_inventory_total) AS source_inventory_total,
           MIN(expected_eligible_candidates) AS expected_eligible_candidates,
           MIN(candidate_identity_sha256) AS candidate_identity_sha256
    FROM ext_telecom_offsec_technology_inventory_receipt
    WHERE run_id = ?1
    GROUP BY run_id, engagement_id, validator_project_id,
             validator_engagement_id, inventory_snapshot_id
),
receipt_digest AS (
    SELECT receipt_scope.*,
           REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(candidate_identity_sha256, '0', ''), '1', ''), '2', ''), '3', ''), '4', ''), '5', ''), '6', ''), '7', ''), '8', ''), '9', ''), 'a', ''), 'b', ''), 'c', ''), 'd', ''), 'e', ''), 'f', '') AS candidate_digest_nonhex
    FROM receipt_scope
),
inventory_scopes AS (
    SELECT run_id, engagement_id, validator_project_id,
           validator_engagement_id, inventory_snapshot_id FROM candidate_counts
    UNION
    SELECT run_id, engagement_id, validator_project_id,
           validator_engagement_id, inventory_snapshot_id FROM member_counts
    UNION
    SELECT run_id, engagement_id, validator_project_id,
           validator_engagement_id, inventory_snapshot_id FROM receipt_digest
),
inventory_coverage AS (
    SELECT s.run_id, s.engagement_id, s.validator_project_id,
           s.validator_engagement_id, s.inventory_snapshot_id,
           r.source_inventory_total, r.expected_eligible_candidates,
           r.candidate_identity_sha256,
           COALESCE(c.actual_count, 0) AS actual_count,
           COALESCE(m.member_count, 0) AS member_count,
           COALESCE(a.unmatched_count, 0) AS unmatched_actual_count,
           COALESCE(e.unmatched_count, 0) AS unmatched_expected_count,
           CASE
             WHEN r.receipt_rows IS NULL THEN 'missing_inventory_receipt'
             WHEN TRIM(r.engagement_id) = '' OR TRIM(r.validator_project_id) = ''
                  OR TRIM(r.validator_engagement_id) = ''
                  OR TRIM(r.inventory_snapshot_id) = ''
                  OR r.validator_engagement_id <> r.engagement_id
                  OR r.engagement_id <> TRIM(r.engagement_id)
                  OR r.validator_project_id <> TRIM(r.validator_project_id)
                  OR r.validator_engagement_id <> TRIM(r.validator_engagement_id)
                  OR r.inventory_snapshot_id <> TRIM(r.inventory_snapshot_id)
                  THEN 'invalid_inventory_receipt_scope'
             WHEN r.membership_variants <> 1 OR r.total_variants <> 1
                  OR r.expected_variants <> 1 OR r.digest_variants <> 1
                  THEN 'ambiguous_inventory_receipt'
             WHEN TRIM(r.inventory_membership_id) = ''
                  OR r.inventory_membership_id <> TRIM(r.inventory_membership_id)
                  OR r.candidate_identity_sha256 = ''
                  OR LENGTH(r.candidate_identity_sha256) <> 64
                  OR LENGTH(r.candidate_digest_nonhex) <> 0
                  OR r.expected_eligible_candidates < 0
                  OR r.source_inventory_total < r.expected_eligible_candidates
                  THEN 'invalid_inventory_receipt'
             WHEN COALESCE(c.actual_count, 0) < r.expected_eligible_candidates
                  THEN 'candidate_count_shortfall'
             WHEN COALESCE(c.actual_count, 0) > r.expected_eligible_candidates
                  THEN 'candidate_count_overage'
             WHEN COALESCE(m.member_count, 0) <> r.expected_eligible_candidates
                  THEN 'receipt_member_count_mismatch'
             WHEN COALESCE(a.unmatched_count, 0) > 0
                  OR COALESCE(e.unmatched_count, 0) > 0
                  THEN 'candidate_identity_mismatch'
             ELSE NULL
           END AS gap_reason
    FROM inventory_scopes s
    LEFT JOIN receipt_digest r
      ON r.run_id = s.run_id AND r.engagement_id = s.engagement_id
     AND r.validator_project_id = s.validator_project_id
     AND r.validator_engagement_id = s.validator_engagement_id
     AND r.inventory_snapshot_id = s.inventory_snapshot_id
    LEFT JOIN candidate_counts c
      ON c.run_id = s.run_id AND c.engagement_id = s.engagement_id
     AND c.validator_project_id = s.validator_project_id
     AND c.validator_engagement_id = s.validator_engagement_id
     AND c.inventory_snapshot_id = s.inventory_snapshot_id
    LEFT JOIN member_counts m
      ON m.run_id = s.run_id AND m.engagement_id = s.engagement_id
     AND m.validator_project_id = s.validator_project_id
     AND m.validator_engagement_id = s.validator_engagement_id
     AND m.inventory_snapshot_id = s.inventory_snapshot_id
    LEFT JOIN unmatched_actual a
      ON a.run_id = s.run_id AND a.engagement_id = s.engagement_id
     AND a.validator_project_id = s.validator_project_id
     AND a.validator_engagement_id = s.validator_engagement_id
     AND a.inventory_snapshot_id = s.inventory_snapshot_id
    LEFT JOIN unmatched_expected e
      ON e.run_id = s.run_id AND e.engagement_id = s.engagement_id
     AND e.validator_project_id = s.validator_project_id
     AND e.validator_engagement_id = s.validator_engagement_id
     AND e.inventory_snapshot_id = s.inventory_snapshot_id
)
SELECT
    'technology:validation-gap:' || c.identity_key AS finding_key,
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
        WHEN v.configuration_variants <> 1 OR v.reachability_variants <> 1
             OR v.verdict_variants > 1 OR v.receipt_variants <> 1
            THEN 'ambiguous_inconsistent_result'
        WHEN v.configuration_status = 'refuted' THEN 'source_claim_contradicted'
        WHEN v.configuration_status = 'unknown' THEN 'inconclusive'
        WHEN v.configuration_status NOT IN ('confirmed', 'refuted', 'unknown') THEN 'invalid_status'
        WHEN v.reachability_status NOT IN ('observed', 'blocked', 'unknown') THEN 'invalid_reachability'
        WHEN COALESCE(c.account_id, '') = '' THEN 'missing_account_scope'
        WHEN v.verdict IS NULL THEN 'missing_validator_verdict'
        WHEN v.verdict NOT IN ('CONFIRMED_CONFIGURATION',
                               'CONFIRMED_REAL_EXPLOITABLE', 'CONFIRMED_GAP_NOT_EXPLOITABLE')
            THEN 'disputed_validator_verdict'
        WHEN (v.verdict = 'CONFIRMED_REAL_EXPLOITABLE'
              AND v.reachability_status <> 'observed')
          OR (v.verdict = 'CONFIRMED_GAP_NOT_EXPLOITABLE'
              AND v.reachability_status <> 'blocked')
            THEN 'inconsistent_verdict_reachability'
        WHEN c.rule_id = 'AWS-NET-001' AND c.critical_seen = 1
             AND v.reachability_status <> 'observed' THEN 's3_critical_exposure_unverified'
        ELSE 'unclassified'
    END ||
    '; configuration=' || COALESCE(v.configuration_status, 'none') ||
    '; reachability=' || COALESCE(v.reachability_status, 'none') ||
    '; verdict=' || COALESCE(v.verdict, 'none') ||
    '; account=' || COALESCE(c.account_id, 'unknown') ||
    '; validator_project=' || c.validator_project_id ||
    '; validator_engagement=' || c.validator_engagement_id ||
    '; source_run=' || COALESCE(c.source_run_id, '') ||
    '; snapshot=' || c.inventory_snapshot_id AS details,
    c.run_id AS run_id,
    42 AS risk_score
FROM candidate_scope c
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
       OR v.configuration_variants <> 1
       OR v.reachability_variants <> 1
       OR v.verdict_variants <> 1
       OR v.receipt_variants <> 1
       OR v.configuration_status <> 'confirmed'
       OR v.configuration_status IS NULL
       OR v.reachability_status NOT IN ('observed', 'blocked', 'unknown')
       OR v.reachability_status IS NULL
       OR COALESCE(v.verdict, '') NOT IN ('CONFIRMED_CONFIGURATION',
                                         'CONFIRMED_REAL_EXPLOITABLE', 'CONFIRMED_GAP_NOT_EXPLOITABLE')
       OR (v.verdict = 'CONFIRMED_REAL_EXPLOITABLE'
           AND v.reachability_status <> 'observed')
       OR (v.verdict = 'CONFIRMED_GAP_NOT_EXPLOITABLE'
           AND v.reachability_status <> 'blocked')
       OR (c.rule_id = 'AWS-NET-001' AND c.critical_seen = 1
           AND v.reachability_status <> 'observed')
  )
UNION ALL
SELECT
    'technology:inventory-gap:' ||
      CAST(LENGTH(i.engagement_id) AS VARCHAR) || ':' || i.engagement_id ||
      CAST(LENGTH(i.validator_project_id) AS VARCHAR) || ':' || i.validator_project_id ||
      CAST(LENGTH(i.validator_engagement_id) AS VARCHAR) || ':' || i.validator_engagement_id ||
      CAST(LENGTH(i.inventory_snapshot_id) AS VARCHAR) || ':' || i.inventory_snapshot_id
      AS finding_key,
    'Technology candidate inventory import requires reconciliation' AS title,
    1 AS affected_count,
    NULL AS exposure_estimate,
    i.validator_project_id || ' / ' || i.validator_engagement_id || ' / ' ||
      i.inventory_snapshot_id AS record_locator,
    'inventory=' || i.gap_reason ||
      '; expected_candidates=' || COALESCE(CAST(i.expected_eligible_candidates AS VARCHAR), 'none') ||
      '; actual_candidates=' || CAST(i.actual_count AS VARCHAR) ||
      '; expected_members=' || CAST(i.member_count AS VARCHAR) ||
      '; unmatched_actual=' || CAST(i.unmatched_actual_count AS VARCHAR) ||
      '; unmatched_expected=' || CAST(i.unmatched_expected_count AS VARCHAR) ||
      '; source_inventory_total=' || COALESCE(CAST(i.source_inventory_total AS VARCHAR), 'none') ||
      '; candidate_identity_sha256=' || COALESCE(i.candidate_identity_sha256, 'none') ||
      '; validator_project=' || i.validator_project_id ||
      '; validator_engagement=' || i.validator_engagement_id ||
      '; snapshot=' || i.inventory_snapshot_id AS details,
    i.run_id AS run_id,
    55 AS risk_score
FROM inventory_coverage i
WHERE i.gap_reason IS NOT NULL
UNION ALL
SELECT
    'technology:inventory-gap:empty-run:' || ?1 AS finding_key,
    'Technology inventory receipt is absent for this run' AS title,
    1 AS affected_count,
    NULL AS exposure_estimate,
    ?1 AS record_locator,
    'inventory=missing_inventory_transfer; no candidate, expected-member, or receipt rows for run' AS details,
    ?1 AS run_id,
    55 AS risk_score
WHERE NOT EXISTS (SELECT 1 FROM inventory_scopes)
ORDER BY finding_key
LIMIT ?2;
