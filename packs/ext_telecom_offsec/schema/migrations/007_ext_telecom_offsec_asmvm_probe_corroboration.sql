-- Additive live-probe corroboration landing zone for ASM-inferred CVEs (P6).
--
-- A live probe (governed http_probe / snmp_readtier / ike_readtier arm, or a
-- passive third-party intel read such as shodan.host) observes the service
-- version on the target IP. This table records that observation and whether the
-- observed version falls inside the CVE's affected range. It is the evidence
-- that lets the cve_observation_provenance landing zone distinguish a
-- probe_corroborated CVE (version observed in the affected range) from a
-- banner/ASM-only inference.
--
-- Provenance priority (highest first): scan_corroborated (VM scan) >
-- probe_corroborated (live probe, version in range) > banner_asserted_inference
-- (service banner) > asm_asserted_inference (ASM only). A NEGATIVE probe
-- (in_affected_range = false, e.g. the edge runs BigIP/AkamaiGHost not the
-- predicted Apache httpd) does NOT upgrade the class; it is recorded here so the
-- edge-vs-origin limitation is visible, and the CVE stays banner/ASM-inferred.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_probe_corroboration (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    probe_corroboration_id             VARCHAR,             -- stable id (probe-<key>)
    ip                                 VARCHAR NOT NULL,    -- target IP that was probed
    cve                                VARCHAR NOT NULL,    -- CVE the probe bears on
    observed_version                   VARCHAR,             -- observed service version / Server header
    in_affected_range                  BOOLEAN,             -- TRUE if observed version is in the CVE affected range
    probe_source                       VARCHAR,             -- e.g. 'httpprobe stand-in', 'shodan.host', 'snmp_readtier'
    is_active                          BOOLEAN,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, probe_corroboration_id)
);

-- Re-create the provenance landing-zone view (created in 006 without the probe
-- class) so it can rank a live-probe observation. Priority: scan_corroborated
-- (VM scan) > probe_corroborated (live probe, version in range) >
-- banner_asserted_inference (service banner) > asm_asserted_inference (ASM only).
-- Negative or incomplete probes remain recorded but do not upgrade the class.
-- A positive source-declared result needs an observed version and named source;
-- these fields provide attribution, not independent source authentication.
-- (SQLite has no CREATE OR REPLACE VIEW, so drop-then-create.)
DROP VIEW IF EXISTS ext_telecom_offsec_asmvm_cve_observation_provenance;
CREATE VIEW ext_telecom_offsec_asmvm_cve_observation_provenance AS
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
            FROM ext_telecom_offsec_asmvm_probe_corroboration p
            WHERE p.run_id = a.run_id
              AND p.ip = a.ip
              AND p.cve = a.cve
              AND CAST(p.is_active AS BOOLEAN)
              AND CAST(p.in_affected_range AS BOOLEAN)
              AND NULLIF(TRIM(p.observed_version), '') IS NOT NULL
              AND NULLIF(TRIM(p.probe_source), '') IS NOT NULL
        ) THEN 'probe_corroborated'
        WHEN EXISTS (
            SELECT 1
            FROM ext_telecom_offsec_asmvm_service_endpoint s
            WHERE s.run_id = a.run_id
              AND s.ip = a.ip
              AND s.service_id = a.evidence_ref
              AND CAST(s.is_active AS BOOLEAN)
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
            FROM ext_telecom_offsec_asmvm_probe_corroboration p
            WHERE p.run_id = a.run_id
              AND p.ip = a.ip
              AND p.cve = a.cve
              AND CAST(p.is_active AS BOOLEAN)
              AND CAST(p.in_affected_range AS BOOLEAN)
              AND NULLIF(TRIM(p.observed_version), '') IS NOT NULL
              AND NULLIF(TRIM(p.probe_source), '') IS NOT NULL
        ) THEN 'live probe observed the service version inside the CVE affected range'
        WHEN EXISTS (
            SELECT 1
            FROM ext_telecom_offsec_asmvm_service_endpoint s
            WHERE s.run_id = a.run_id
              AND s.ip = a.ip
              AND s.service_id = a.evidence_ref
              AND CAST(s.is_active AS BOOLEAN)
              AND s.product_version IS NOT NULL
              AND TRIM(s.product_version) <> ''
        ) THEN 'ASM CVE inference and product version share one banner-derived service assertion'
        ELSE 'ASM inference has no matching VM CVE observation or attributable service banner'
    END AS provenance_note
FROM ext_telecom_offsec_asmvm_cve_observation a;
