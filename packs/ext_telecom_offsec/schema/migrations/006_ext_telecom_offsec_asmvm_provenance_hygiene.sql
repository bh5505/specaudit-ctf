-- Additive provenance landing zone for ASM-inferred CVEs.
--
-- product_version is a banner assertion carried by service/service_endpoint.
-- It is not evidence independent of an ASM CVE inferred from that same banner.
-- Consumers must select an explicit provenance_class before joining this surface
-- into a T1/T2 scan predicate. In particular, banner_asserted_inference must
-- never masquerade as independent scan corroboration.
--
-- VM count hygiene decision (Finding R): vm_cve_observation.n_findings is the
-- authoritative count of distinct contributing VM findings. finding_count is a
-- deprecated compatibility alias and must equal n_findings while it remains in
-- accepted evidence. No DDL change is made here because migrations are applied
-- verbatim and existing accepted tables must remain additive-compatible.
CREATE VIEW IF NOT EXISTS ext_telecom_offsec_asmvm_cve_observation_provenance AS
SELECT
    a.run_id AS run_id,
    a.engagement_id AS engagement_id,
    a.accept_event_id AS accept_event_id,
    a.cve_observation_id AS cve_observation_id,
    a.ip AS ip,
    a.cve AS cve,
    a.sources AS sources,
    a.evidence_ref AS evidence_ref,
    a.inferred_score AS inferred_score,
    a.is_active AS is_active,
    CASE
        WHEN EXISTS (
            SELECT 1
            FROM ext_telecom_offsec_asmvm_vm_cve_observation v
            WHERE v.run_id = a.run_id
              AND v.ip = a.ip
              AND v.cve = a.cve
        ) THEN 'scan_corroborated'
        WHEN EXISTS (
            SELECT 1
            FROM ext_telecom_offsec_asmvm_service_endpoint s
            WHERE s.run_id = a.run_id
              AND s.ip = a.ip
              AND s.service_id = a.evidence_ref
              AND s.product_version IS NOT NULL
              AND TRIM(s.product_version) <> ''
        ) THEN 'banner_asserted_inference'
        ELSE 'asm_asserted_inference'
    END AS provenance_class,
    CASE
        WHEN EXISTS (
            SELECT 1
            FROM ext_telecom_offsec_asmvm_vm_cve_observation v
            WHERE v.run_id = a.run_id
              AND v.ip = a.ip
              AND v.cve = a.cve
        ) THEN 'matching VM CVE observation supplies scan corroboration'
        WHEN EXISTS (
            SELECT 1
            FROM ext_telecom_offsec_asmvm_service_endpoint s
            WHERE s.run_id = a.run_id
              AND s.ip = a.ip
              AND s.service_id = a.evidence_ref
              AND s.product_version IS NOT NULL
              AND TRIM(s.product_version) <> ''
        ) THEN 'ASM CVE inference and product version share one banner-derived service assertion'
        ELSE 'ASM inference has no matching VM CVE observation or attributable service banner'
    END AS provenance_note
FROM ext_telecom_offsec_asmvm_cve_observation a;
