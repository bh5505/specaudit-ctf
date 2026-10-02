-- ext_telecom_offsec_asmvm_t2_asmvm_no_authenticated_visibility.sql - T2
-- (adversarial validation) applied to the scanner fleet itself.
--
-- If no asset in a scanner network scope has EVER had a credentialed scan, then
-- every vulnerability statement this source makes about that scope is an
-- unauthenticated guess: patch levels, OS and installed-version facts are not
-- observable without credentials. In that state no finding derived from the
-- source has been validated by an independent lane, and the ASM banner
-- inference has nothing to be checked against.
--
-- Grouped by scanner network scope, because credentialed coverage is granted
-- per scope, and that is the unit the operations team can act on.
--
-- Tables: ext_telecom_offsec_asmvm_vm_asset.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'asmvm:no-credentialed-scan:' || COALESCE(a.network_name, 'unknown-network') ||
        ':' || COALESCE(a.scanner, 'unknown-scanner')  AS finding_key,
    'Scanner scope has no authenticated-scan coverage: ' ||
        COALESCE(a.network_name, 'unknown network')    AS title,
    COUNT(*)                                          AS affected_count,
    CAST(COALESCE(SUM(a.open_cve_count), 0) AS BIGINT) AS exposure_estimate,
    'vm:network:' || COALESCE(a.network_name, 'unknown') || ' / scanner:' ||
        COALESCE(a.scanner, 'unknown')                AS record_locator,
    'assets=' || CAST(COUNT(*) AS VARCHAR) ||
    '; credentialed_assets=' || CAST(COUNT(CASE WHEN CAST(a.has_credentialed_scan AS BOOLEAN) THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; external_assets=' || CAST(COUNT(CASE WHEN CAST(a.is_external AS BOOLEAN) THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; open_cve_count=' || CAST(COALESCE(SUM(a.open_cve_count), 0) AS VARCHAR) ||
    '; open_threat_count=' || CAST(COALESCE(SUM(a.open_threat_count), 0) AS VARCHAR) ||
    '; max_critical_severity=' || CAST(ROUND(COALESCE(MAX(a.vrr_critical_max), 0), 2) AS VARCHAR) ||
    '; last_scan=' || COALESCE(SUBSTR(CAST(MAX(a.last_scan_ts) AS VARCHAR), 1, 19), 'never') ||
    '; validation=credentialed_scan_required'         AS details,
    a.run_id                                          AS run_id,
    52                                                AS risk_score
FROM ext_telecom_offsec_asmvm_vm_asset a
WHERE a.run_id = ?1
GROUP BY a.network_name, a.scanner, a.run_id
HAVING COUNT(CASE WHEN CAST(a.has_credentialed_scan AS BOOLEAN) THEN 1 ELSE NULL END) = 0
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
