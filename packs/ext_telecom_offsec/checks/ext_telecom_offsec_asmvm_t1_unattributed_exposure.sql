-- ext_telecom_offsec_asmvm_t1_unattributed_exposure.sql - T1 (threat-model
-- first: is the boundary you drew the boundary you own?).
--
-- The ASM feed observes an active internet-facing service on an IPv4 address
-- that falls OUTSIDE every declared owned range. Either the owned-address-space
-- declaration is stale/incomplete, or the asset is genuinely third-party
-- (SaaS-adjacent, hosting, partner) exposure the engagement never scoped. Both
-- answers change scope, so the exception is surfaced rather than filtered away.
--
-- Grouped by /16 (prefix_16, computed at ingest): a per-IP finding would return
-- tens of thousands of rows of the same story, and the remediation unit for an
-- address-attribution dispute is the block, not the host. prefix_16 is an
-- INGEST-time column because regexp string extraction is not portable between
-- the DuckDB engine and the SQLite loopback runner.
--
-- Tables: ext_telecom_offsec_asmvm_asm_vm_surface.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'asmvm:unattributed:' || s.prefix_16            AS finding_key,
    'Exposed service outside declared owned ranges: ' || s.prefix_16 AS title,
    COUNT(*)                                        AS affected_count,
    CAST(COALESCE(SUM(s.asm_exposed_services), 0)
         + COALESCE(SUM(s.asm_exposed_websites), 0) AS BIGINT) AS exposure_estimate,
    s.prefix_16                                     AS record_locator,
    'ips=' || CAST(COUNT(*) AS VARCHAR) ||
    '; exposed_services=' || CAST(COALESCE(SUM(s.asm_exposed_services), 0) AS VARCHAR) ||
    '; exposed_websites=' || CAST(COALESCE(SUM(s.asm_exposed_websites), 0) AS VARCHAR) ||
    '; ips_in_vm_estate=' || CAST(COUNT(CASE WHEN CAST(s.in_vm_estate AS BOOLEAN) THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; active_alerts=' || CAST(COALESCE(SUM(s.asm_active_alerts), 0) AS VARCHAR) ||
    '; inferred_cves=' || CAST(COALESCE(SUM(s.asm_inferred_cves), 0) AS VARCHAR) ||
    '; sample_ip=' || MIN(s.ip) ||
    '; resolution=confirm_ownership_or_scope_in'     AS details,
    s.run_id                                        AS run_id,
    50                                              AS risk_score
FROM ext_telecom_offsec_asmvm_asm_vm_surface s
WHERE s.run_id = ?1
  AND CAST(s.has_active_service AS BOOLEAN)
  AND NOT CAST(s.inside_owned_range AS BOOLEAN)
GROUP BY s.prefix_16, s.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
