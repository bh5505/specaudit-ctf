-- ext_telecom_offsec_asmvm_t1_vm_asset_unobserved.sql - T1, the other direction
-- of the same boundary reconciliation.
--
-- The vulnerability-management estate scans an IPv4 address that the ASM feed
-- never observed as internet-facing. Two possible answers, and both change the
-- audit scope: the scanner scope includes internal space (expected, benign, and
-- worth stating in the workpaper so the population gap is explained rather than
-- hand-waved), or ASM discovery is blind for that range (a discovery gap in the
-- attacker-view threat model). The check reports the population and how much
-- unpatched severity sits on it, and leaves the interpretation to the auditor.
--
-- Grouped by /24. Risk is elevated when unmanaged-but-scanned addresses carry
-- open criticals, because then the address space is both unproven from outside
-- and vulnerable from inside.
--
-- Tables: ext_telecom_offsec_asmvm_asm_vm_surface.
-- Bound params: ?1 = run_id, ?2 = row limit.

SELECT
    'asmvm:vm-not-observed:' || s.prefix_24         AS finding_key,
    'VM-scanned IP never observed as internet-facing: ' || s.prefix_24 AS title,
    COUNT(*)                                        AS affected_count,
    CAST(COALESCE(SUM(s.vm_open_findings), 0) AS BIGINT) AS exposure_estimate,
    s.prefix_24                                     AS record_locator,
    'ips=' || CAST(COUNT(*) AS VARCHAR) ||
    '; open_findings=' || CAST(COALESCE(SUM(s.vm_open_findings), 0) AS VARCHAR) ||
    '; open_critical=' || CAST(COALESCE(SUM(s.vm_open_critical), 0) AS VARCHAR) ||
    '; inside_owned_range=' || CAST(COUNT(CASE WHEN CAST(s.inside_owned_range AS BOOLEAN) THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; credentialed_scans=' || CAST(COUNT(CASE WHEN CAST(s.vm_has_credentialed_scan AS BOOLEAN) THEN 1 ELSE NULL END) AS VARCHAR) ||
    '; asm_active_service=false' ||
    '; sample_ip=' || MIN(s.ip) ||
    '; resolution=confirm_internal_scope_or_asm_discovery_gap' AS details,
    s.run_id                                        AS run_id,
    CASE WHEN COALESCE(SUM(s.vm_open_critical), 0) > 0 THEN 44 ELSE 26 END AS risk_score
FROM ext_telecom_offsec_asmvm_asm_vm_surface s
WHERE s.run_id = ?1
  AND CAST(s.in_vm_estate AS BOOLEAN)
  AND NOT CAST(s.has_active_service AS BOOLEAN)
GROUP BY s.prefix_24, s.run_id
ORDER BY risk_score DESC, COALESCE(SUM(s.vm_open_critical), 0) DESC, affected_count DESC, finding_key
LIMIT ?2;
