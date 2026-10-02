-- ext_telecom_offsec_asmvm_t3_asmvm_scan_confidence_vocabulary_gap.sql - T3
--
-- Evidence-integrity guard for the VM CVE observation vocabulary. Migration
-- schema/migrations/002_ext_telecom_offsec_asmvm_vm_silver.sql:125-126 declares
-- CHECK-less VARCHAR columns; the loopback runner therefore does not enforce
-- either vocabulary. Enforcement has to be a pack check rather than decorative
-- DDL on that execution path.
--
-- One aggregate row per offending (scan_mode, scan_confidence) combination, so
-- malformed evidence cannot flood the report. Bound params: ?1 run_id, ?2 limit.

SELECT
    'asmvm:scan-confidence-vocabulary-gap:' ||
        COALESCE(scan_mode, '<NULL>') || ':' || COALESCE(scan_confidence, '<NULL>') AS finding_key,
    'VM CVE observation uses undocumented scan vocabulary' AS title,
    COUNT(*) AS affected_count,
    COUNT(DISTINCT ip) AS exposure_estimate,
    'ext_telecom_offsec_asmvm_vm_cve_observation[scan_mode=' ||
        COALESCE(scan_mode, '<NULL>') || ',scan_confidence=' ||
        COALESCE(scan_confidence, '<NULL>') || ']' AS record_locator,
    'affected_ips=' || CAST(COUNT(DISTINCT ip) AS VARCHAR) ||
    '; scan_mode_vocabulary=credentialed|external' ||
    '; scan_confidence_vocabulary=vendor_vuln_confirmed|vendor_mixed_category|vendor_potential_vulnerability|banner_inference|unknown' ||
    '; contract_reference=schema/migrations/002_ext_telecom_offsec_asmvm_vm_silver.sql:125-126' AS details,
    run_id AS run_id,
    40 AS risk_score
FROM ext_telecom_offsec_asmvm_vm_cve_observation
WHERE run_id = ?1
  AND (
      scan_mode IS NULL
      OR scan_mode NOT IN ('credentialed', 'external')
      OR scan_confidence IS NULL
      OR scan_confidence NOT IN (
          'vendor_vuln_confirmed',
          'vendor_mixed_category',
          'vendor_potential_vulnerability',
          'banner_inference',
          'unknown'
      )
  )
GROUP BY scan_mode, scan_confidence, run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
