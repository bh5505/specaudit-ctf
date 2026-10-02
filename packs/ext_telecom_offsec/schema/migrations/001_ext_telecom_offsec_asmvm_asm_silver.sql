-- 001_ext_telecom_offsec_asmvm_asm_silver.sql - pack-owned ASM (attack-surface
-- management) silver for the ext_telecom_offsec_asmvm namespace.
--
-- Pure declarative W1 DDL: default schema, natural keys, VARCHAR / INTEGER /
-- BIGINT / BOOLEAN / DOUBLE / TIMESTAMP types only (DuckDB- and
-- SQLite-compatible), the accept spine (run_id / engagement_id /
-- accept_event_id + source_* provenance + record_hash / lineage_batch_id /
-- mapping_version / model_version), and PRIMARY KEY (run_id, accept_event_id,
-- <entity key>) so re-accept is a delete+insert.
--
-- ip columns stay VARCHAR (locators, never arithmetic); the integer form used
-- for owned-range containment lives in ip_bigint / ip_from / ip_to.
--
-- The derived join tables (ip, service_endpoint, website_endpoint,
-- alert_endpoint, cve_observation) are produced by the ingest mapping from the
-- vendor `*_list` columns. They are silver, not views: a view cannot carry the
-- accept spine, and the checks need the spine on both sides of every join.
-- Every column here is a column at least one check or the workpaper reads.

-- ext_telecom_offsec_asmvm_asset - ASM asset inventory (Cortex Xpanse Assets export, one row per asset).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_asset (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    asset_id                           VARCHAR NOT NULL,
    asset_name                         VARCHAR,
    asset_type                         VARCHAR,             -- normalized asset class
    ipv4_list                          VARCHAR,             -- comma-joined IPv4 list as exported
    ipv6_list                          VARCHAR,
    has_active_services                BOOLEAN,             -- asset answers on at least one external service
    has_related_alerts                 BOOLEAN,
    has_related_incidents              BOOLEAN,
    inferred_vuln_score                DOUBLE,              -- vendor banner-inferred CVSS (never a scan result)
    inferred_cves                      VARCHAR,             -- comma-joined banner-inferred CVE ids
    business_units                     VARCHAR,
    sources                            VARCHAR,             -- ASM connector(s) that observed the asset
    active_service_types               VARCHAR,
    asn_handles                        VARCHAR,             -- ownership attribution evidence
    date_added                         TIMESTAMP,           -- first seen by ASM
    last_observed                      TIMESTAMP,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, asset_id)
);

-- ext_telecom_offsec_asmvm_service - ASM externally-reachable service observation (Xpanse External Services).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_service (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    service_id                         VARCHAR NOT NULL,
    service_name                       VARCHAR,
    service_type                       VARCHAR,
    ipv4_list                          VARCHAR,
    ipv6_list                          VARCHAR,
    port                               INTEGER,
    protocol                           VARCHAR,             -- tcp|udp
    is_active                          BOOLEAN,             -- ASM active state (inactive = withdrawn observation)
    domain                             VARCHAR,
    providers                          VARCHAR,             -- hosting / ASN provider attribution
    active_classifications             VARCHAR,
    product_version                    VARCHAR,             -- banner product/version
    inferred_vuln_score                DOUBLE,
    inferred_cves                      VARCHAR,
    has_inferred_cve_signal            BOOLEAN,
    first_observed                     TIMESTAMP,
    last_observed                      TIMESTAMP,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, service_id)
);

-- ext_telecom_offsec_asmvm_website - ASM web-property observation (Xpanse Websites).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_website (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    website_id                         VARCHAR NOT NULL,
    host                               VARCHAR,
    port                               INTEGER,
    is_active                          BOOLEAN,
    http_type                          VARCHAR,             -- http|https
    site_category                      VARCHAR,
    technologies                       VARCHAR,             -- banner-detected stack
    failed_security_assessments        VARCHAR,             -- raw ASM assessment-name list (see pack README: names can be positive assertions)
    has_failed_assessment              BOOLEAN,             -- raw column non-empty (NOT proof of failure)
    authentication                     VARCHAR,
    root_http_status                   INTEGER,
    is_non_configured_host             BOOLEAN,
    ipv4_list                          VARCHAR,
    third_party_script_domains         VARCHAR,             -- supply-chain script domains
    inferred_vuln_score                DOUBLE,
    inferred_cves                      VARCHAR,
    country                            VARCHAR,
    first_observed                     TIMESTAMP,
    last_observed                      TIMESTAMP,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, website_id)
);

-- ext_telecom_offsec_asmvm_alert - ASM attack-surface-rule alert (Xpanse Alerts).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_alert (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    alert_id                           VARCHAR NOT NULL,
    vendor_alert_id                    VARCHAR,             -- vendor numeric id kept as text
    alert_version                      INTEGER,
    alert_name                         VARCHAR,
    asr_rule                           VARCHAR,             -- attack-surface-rule name (the generalization unit)
    asr_category                       VARCHAR,             -- vendor rule category
    severity                           VARCHAR,             -- Critical|High|Medium|Low (vendor wording)
    resolution_status                  VARCHAR,
    is_excluded                        BOOLEAN,
    is_active_state                    BOOLEAN,             -- true = New/Reopened (still actionable)
    ipv4_list                          VARCHAR,
    domain_names                       VARCHAR,
    incident_ref                       VARCHAR,             -- vendor incident id (joins ext_telecom_offsec_asmvm_incident)
    incident_status                    VARCHAR,
    mitre_tactic                       VARCHAR,
    mitre_technique                    VARCHAR,
    observed_at                        TIMESTAMP,
    last_observed                      TIMESTAMP,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, alert_id)
);

-- ext_telecom_offsec_asmvm_incident - ASM incident roll-up (Xpanse Incidents).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_incident (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    incident_id                        VARCHAR NOT NULL,
    vendor_incident_id                 VARCHAR,
    asr_rule                           VARCHAR,
    status                             VARCHAR,
    score                              DOUBLE,              -- vendor incident score
    total_alerts                       INTEGER,
    critical_alerts                    INTEGER,
    high_alerts                        INTEGER,
    medium_alerts                      INTEGER,
    low_alerts                         INTEGER,
    ipv4_list                          VARCHAR,
    domain_names                       VARCHAR,
    port                               INTEGER,
    mitre_tactic                       VARCHAR,
    mitre_technique                    VARCHAR,
    created_at                         TIMESTAMP,
    last_observed                      TIMESTAMP,
    resolved_at                        TIMESTAMP,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, incident_id)
);

-- ext_telecom_offsec_asmvm_owned_ip_range - Declared owned address space: the ownership boundary the ASM scope is tested against.
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_owned_ip_range (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    range_id                           VARCHAR NOT NULL,
    ip_version                         INTEGER,             -- 4|6
    first_ip                           VARCHAR,
    last_ip                            VARCHAR,
    ip_from                            BIGINT,              -- first_ip as an integer
    ip_to                              BIGINT,              -- last_ip as an integer
    ips_count                          BIGINT,
    active_responsive_ips              BIGINT,              -- ASM-observed responsive IPs inside the range
    business_units                     VARCHAR,
    asn_handles                        VARCHAR,
    is_subrange                        BOOLEAN,
    date_added                         VARCHAR,             -- declaration date as exported
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, range_id)
);

-- ext_telecom_offsec_asmvm_ip - Derived ASM IPv4 observation spine (one row per observed IPv4, exploded from the vendor *_list columns).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_ip (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    ip                                 VARCHAR NOT NULL,
    ip_bigint                          BIGINT,              -- ip as an integer (owned-range containment)
    seen_via                           VARCHAR,             -- asset|service|website|alert (pipe-joined)
    has_active_service                 BOOLEAN,             -- at least one active service or website observation
    asm_observations                   BIGINT,              -- observation count across ASM sources
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, ip)
);

-- ext_telecom_offsec_asmvm_service_endpoint - Derived service x IPv4 endpoint join: the exposed attack surface, one row per service+IP.
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_service_endpoint (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    service_endpoint_id                VARCHAR,             -- service_id || '|' || ip (stable composite key)
    service_id                         VARCHAR NOT NULL,
    ip                                 VARCHAR NOT NULL,
    service_name                       VARCHAR,
    service_type                       VARCHAR,
    port                               INTEGER,
    protocol                           VARCHAR,
    is_active                          BOOLEAN,
    inferred_vuln_score                DOUBLE,
    inferred_cves                      VARCHAR,
    product_version                    VARCHAR,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, service_endpoint_id)
);

-- ext_telecom_offsec_asmvm_website_endpoint - Derived website x IPv4 endpoint join.
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_website_endpoint (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    website_endpoint_id                VARCHAR,             -- website_id || '|' || ip (stable composite key)
    website_id                         VARCHAR NOT NULL,
    ip                                 VARCHAR NOT NULL,
    host                               VARCHAR,
    port                               INTEGER,
    is_active                          BOOLEAN,
    http_type                          VARCHAR,
    has_failed_assessment              BOOLEAN,
    failed_security_assessments        VARCHAR,
    inferred_cves                      VARCHAR,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, website_endpoint_id)
);

-- ext_telecom_offsec_asmvm_alert_endpoint - Derived alert x IPv4 join (alert attribution to addresses).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_alert_endpoint (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    alert_endpoint_id                  VARCHAR,             -- alert_id || '|' || ip (stable composite key)
    alert_id                           VARCHAR NOT NULL,
    ip                                 VARCHAR NOT NULL,
    severity                           VARCHAR,
    resolution_status                  VARCHAR,
    is_active_state                    BOOLEAN,
    asr_rule                           VARCHAR,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, alert_endpoint_id)
);

-- ext_telecom_offsec_asmvm_cve_observation - ASM-inferred CVE observation, one row per (ip, cve). Inference, not a scan result.
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_cve_observation (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    cve_observation_id                 VARCHAR,             -- ip || '|' || cve (stable composite key)
    ip                                 VARCHAR NOT NULL,
    cve                                VARCHAR NOT NULL,
    sources                            VARCHAR,             -- ASM sources that inferred the CVE
    evidence_ref                       VARCHAR,             -- asset/service id the inference came from
    inferred_score                     DOUBLE,              -- vendor inferred CVSS
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
    PRIMARY KEY (run_id, accept_event_id, cve_observation_id)
);
