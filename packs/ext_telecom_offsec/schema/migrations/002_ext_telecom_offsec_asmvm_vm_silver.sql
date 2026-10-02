-- 002_ext_telecom_offsec_asmvm_vm_silver.sql - vulnerability-management silver plus the
-- ASM/VM reconciliation surface.
--
-- ext_telecom_offsec_asmvm_asm_vm_surface is the pack's central artefact: one row per
-- IPv4 that the ASM feed observed OR the VM estate scans, carrying both views
-- side by side, so a one-sided coverage gap is a WHERE clause instead of a
-- cross-source join at query time.
--
-- Rollups that need date or string arithmetic (prefix_16, prefix_24) are
-- computed at INGEST time, because check SQL has to stay portable across the
-- DuckDB engine and the SQLite loopback runner: date_diff() does not exist in
-- SQLite and regexp_extract() does not exist in DuckDB.

-- ext_telecom_offsec_asmvm_vm_asset - Vulnerability-management asset (Ivanti Neurons / Qualys inventory).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_vm_asset (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    asset_id                           VARCHAR NOT NULL,
    ip                                 VARCHAR,             -- primary address; the ASM/VM join key
    hostname                           VARCHAR,
    network_name                       VARCHAR,             -- scanner network scope
    scanner                            VARCHAR,             -- scanner / connector identity
    is_external                        BOOLEAN,             -- vendor's own addressability flag; not scan context
    last_scan_ts                       TIMESTAMP,
    last_credentialed_scan_ts          TIMESTAMP,           -- NULL = never authenticated
    has_credentialed_scan              BOOLEAN,
    open_cve_count                     INTEGER,
    open_threat_count                  INTEGER,
    total_finding_count                INTEGER,
    vrr_critical_max                   DOUBLE,              -- max critical severity reported for the asset
    vrr_high_max                       DOUBLE,
    os_detected                        VARCHAR,
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

-- ext_telecom_offsec_asmvm_vm_finding - Vulnerability-management finding (one row per scanner finding).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_vm_finding (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    finding_id                         VARCHAR NOT NULL,
    ip                                 VARCHAR,
    title                              VARCHAR,
    qid                                INTEGER,             -- scanner plugin / qid id
    plugin_family                      VARCHAR,             -- the generalization class for T6
    port                               INTEGER,
    protocol                           VARCHAR,
    severity                           DOUBLE,              -- normalized severity 0-10 (CVSS/VRR)
    risk_rating                        DOUBLE,
    status                             VARCHAR,             -- scanner status wording
    is_open                            BOOLEAN,
    last_found_ts                      TIMESTAMP,
    resolved_ts                        TIMESTAMP,
    scanner                            VARCHAR,
    -- Scanner-side scan context of the asset row that produced this finding.
    -- vm_asset.is_external is the vendor's own addressability flag, not a scan-context flag.
    vm_asset_id                        VARCHAR,             -- producing scanner asset row
    scan_network_name                  VARCHAR,             -- producing asset's scanner network
    scan_network_id                    INTEGER,             -- vendor scanner-network id
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, finding_id)
);

-- ext_telecom_offsec_asmvm_vm_cve_finding - CVE rows extracted from VM findings (one row per finding x CVE): the canonical CVE evidence.
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_vm_cve_finding (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    ip                                 VARCHAR NOT NULL,
    cve                                VARCHAR NOT NULL,
    finding_id                         VARCHAR NOT NULL,
    severity                           DOUBLE,
    is_open                            BOOLEAN,
    last_found_ts                      TIMESTAMP,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, ip, cve, finding_id)
);

-- ext_telecom_offsec_asmvm_vm_cve_observation - VM CVE observations collapsed to (ip, cve) with scan-mode provenance.
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_vm_cve_observation (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    ip                                 VARCHAR NOT NULL,
    cve                                VARCHAR NOT NULL,
    evidence_ref                       VARCHAR,             -- finding / qid reference
    severity                           DOUBLE,
    is_open                            BOOLEAN,
    finding_count                      BIGINT,              -- deprecated compatibility alias; must equal n_findings
    last_found_ts                      TIMESTAMP,
    scan_mode                          VARCHAR,             -- credentialed|external (how the CVE was seen)
    scan_confidence                    VARCHAR,
    -- Lineage-true context for observations with multiple contributing findings.
    n_findings                         BIGINT,              -- authoritative distinct contributing VM findings
    n_external_findings                BIGINT,              -- contributors from a network named external
    n_unknown_context_findings         BIGINT,              -- contributors with NULL/empty network
    scan_networks                      VARCHAR,             -- sorted distinct contributing network names
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, ip, cve)
);

-- ext_telecom_offsec_asmvm_asm_vm_surface - The ASM/VM reconciliation surface: one row per IPv4 the ASM feed observed or the VM estate scans.
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_asm_vm_surface (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    ip                                 VARCHAR NOT NULL,
    ip_bigint                          BIGINT,
    prefix_16                          VARCHAR,             -- ingest-computed /16 rollup key
    prefix_24                          VARCHAR,             -- ingest-computed /24 rollup key
    seen_via                           VARCHAR,
    has_active_service                 BOOLEAN,             -- ASM: answering on the internet
    inside_owned_range                 BOOLEAN,             -- inside a declared owned range
    in_vm_estate                       BOOLEAN,             -- the VM estate scans this address
    vm_asset_id                        VARCHAR,
    vm_last_scan_ts                    TIMESTAMP,
    vm_has_credentialed_scan           BOOLEAN,
    vm_open_findings                   BIGINT,
    vm_open_critical                   BIGINT,              -- severity >= 9.0
    vm_max_severity                    DOUBLE,
    asm_inferred_cves                  BIGINT,
    asm_active_alerts                  BIGINT,
    asm_high_alerts                    BIGINT,
    asm_exposed_services               BIGINT,
    asm_exposed_websites               BIGINT,
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
