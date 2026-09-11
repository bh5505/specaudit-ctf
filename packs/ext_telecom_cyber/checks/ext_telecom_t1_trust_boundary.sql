-- ext_telecom_t1_trust_boundary.sql - method T1 (threat-model-first).
-- Trust-boundary completeness over the AWS posture surface (S3, IAM,
-- security-group). Flags buckets whose public-access block is disabled or
-- whose bucket policy allows anonymous principals; IAM principals that allow
-- an external principal; and ingress SG rules that are public or use
-- 0.0.0.0/0.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'bucket:' || b.bucket_name AS finding_key,
    'S3 bucket outside trust boundary: ' || b.bucket_name AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    b.bucket_name || ' / ' || COALESCE(b.account_id, '') || ' / ' || COALESCE(b.region, '') AS record_locator,
    'public_access_block_enabled=' || CAST(COALESCE(b.public_access_block_enabled, false) AS VARCHAR) ||
    '; policy_allows_anonymous=' || CAST(COALESCE(b.policy_allows_anonymous, false) AS VARCHAR) ||
    '; public_read_acl=' || CAST(COALESCE(b.public_read_acl, false) AS VARCHAR) ||
    '; public_write_acl=' || CAST(COALESCE(b.public_write_acl, false) AS VARCHAR) ||
    '; encryption_enabled=' || CAST(COALESCE(b.encryption_enabled, false) AS VARCHAR) ||
    '; tls_required=' || CAST(COALESCE(b.tls_required, false) AS VARCHAR) AS details,
    b.run_id AS run_id,
    45 AS risk_score
FROM gw_silver_ext_telecom_s3_bucket b
WHERE b.run_id = ?1
  AND (
    b.public_access_block_enabled = false
    OR b.policy_allows_anonymous = true
  )
UNION ALL
SELECT
    'principal:' || p.principal_arn AS finding_key,
    'IAM principal outside trust boundary: ' || p.principal_arn AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    p.principal_arn || ' / ' || COALESCE(p.principal_type, '') AS record_locator,
    'allows_external_principal=' || CAST(COALESCE(p.allows_external_principal, false) AS VARCHAR) ||
    '; mfa_required=' || CAST(COALESCE(p.mfa_required, false) AS VARCHAR) AS details,
    p.run_id AS run_id,
    45 AS risk_score
FROM gw_silver_ext_telecom_iam_principal p
WHERE p.run_id = ?1
  AND p.allows_external_principal = true
UNION ALL
SELECT
    'sg:' || sg.sg_id || ':' || sg.direction || ':' || sg.ip_protocol || ':' ||
        CAST(sg.from_port AS VARCHAR) || ':' || CAST(sg.to_port AS VARCHAR) || ':' || sg.cidr AS finding_key,
    'Security-group rule outside trust boundary: ' || sg.sg_id AS title,
    1 AS affected_count,
    1 AS exposure_estimate,
    sg.sg_id || ' / ' || COALESCE(sg.vpc_id, '') || ' / ' || sg.direction AS record_locator,
    'direction=' || sg.direction ||
    '; ip_protocol=' || sg.ip_protocol ||
    '; from_port=' || CAST(sg.from_port AS VARCHAR) ||
    '; to_port=' || CAST(sg.to_port AS VARCHAR) ||
    '; cidr=' || sg.cidr ||
    '; is_public=' || CAST(COALESCE(sg.is_public, false) AS VARCHAR) AS details,
    sg.run_id AS run_id,
    45 AS risk_score
FROM gw_silver_ext_telecom_security_group sg
WHERE sg.run_id = ?1
  AND sg.direction = 'ingress'
  AND (
    sg.is_public = true
    OR sg.cidr = '0.0.0.0/0'
  )
ORDER BY finding_key
LIMIT ?2;
