-- ext_telecom_offsec_asmvm_t1_unmanaged_surface.sql - T1 (threat-model-first):
-- the ASM/VM analogue of an unmanaged trust-boundary asset.
--
-- IPv4 addresses that the ASM feed sees answering on the internet, that sit
-- INSIDE declared owned address space, and that the vulnerability-management
-- estate does not scan. Owned + externally reachable + unmanaged is the single
-- highest-value reconciliation result of pairing an ASM feed with a VM feed:
-- one source alone cannot produce it (ASM cannot know what is scanned; the VM
-- console cannot see what it does not scan).
--
-- Grouped by /24 (prefix_24, ingest-computed): an unmanaged block is an
-- ownership/deployment-ownership conversation, and a /24 is the unit a network
-- owner can act on. `sample_ip` carries one address for immediate verification.
--
-- Tables: ext_telecom_offsec_asmvm_asm_vm_surface.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'asmvm:owned-unmanaged:' || s.prefix_24         AS finding_key,
    'Exposed owned IP with no VM coverage: ' || s.prefix_24 AS title,
    COUNT(*)                                        AS affected_count,
    CAST(COALESCE(SUM(s.asm_exposed_services), 0)
         + COALESCE(SUM(s.asm_exposed_websites), 0) AS BIGINT) AS exposure_estimate,
    s.prefix_24                                     AS record_locator,
    'ips=' || CAST(COUNT(*) AS VARCHAR) ||
    '; exposed_services=' || CAST(COALESCE(SUM(s.asm_exposed_services), 0) AS VARCHAR) ||
    '; exposed_websites=' || CAST(COALESCE(SUM(s.asm_exposed_websites), 0) AS VARCHAR) ||
    '; inside_owned_range=true; in_vm_estate=false' ||
    '; active_alerts=' || CAST(COALESCE(SUM(s.asm_active_alerts), 0) AS VARCHAR) ||
    '; high_alerts=' || CAST(COALESCE(SUM(s.asm_high_alerts), 0) AS VARCHAR) ||
    '; inferred_cves=' || CAST(COALESCE(SUM(s.asm_inferred_cves), 0) AS VARCHAR) ||
    '; sample_ip=' || MIN(s.ip) ||
    '; sample_exposed_service_ip=' || MIN(CASE WHEN COALESCE(s.asm_exposed_services, 0) > 0 THEN s.ip ELSE NULL END) AS details,
    s.run_id                                        AS run_id,
    54                                              AS risk_score
FROM ext_telecom_offsec_asmvm_asm_vm_surface s
WHERE s.run_id = ?1
  AND CAST(s.has_active_service AS BOOLEAN)
  AND NOT CAST(s.in_vm_estate AS BOOLEAN)
  AND CAST(s.inside_owned_range AS BOOLEAN)
GROUP BY s.prefix_24, s.run_id
ORDER BY risk_score DESC, affected_count DESC, finding_key
LIMIT ?2;
