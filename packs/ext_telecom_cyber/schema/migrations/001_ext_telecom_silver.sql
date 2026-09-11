-- 001_ext_telecom_silver.sql - pack-owned ext_telecom silver spine.
-- Pure declarative W1 DDL: default schema, natural keys, VARCHAR/INTEGER/
-- BOOLEAN/DATE/TIMESTAMP types only (DuckDB- and SQLite-compatible), and
-- accept lineage columns mirroring the external-pack spine convention.
-- Check SQL binds the ambient run with `<alias>.run_id = ?1` (every silver
-- table carries run_id VARCHAR NOT NULL).

CREATE TABLE IF NOT EXISTS gw_silver_ext_telecom_s3_bucket (
    run_id                           VARCHAR NOT NULL,
    engagement_id                    VARCHAR NOT NULL,
    accept_event_id                  VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    bucket_name                      VARCHAR NOT NULL,
    account_id                       VARCHAR,
    region                           VARCHAR,
    public_access_block_enabled      BOOLEAN,
    public_read_acl                  BOOLEAN,
    public_write_acl                 BOOLEAN,
    has_bucket_policy                BOOLEAN,
    policy_allows_anonymous          BOOLEAN,
    encryption_enabled               BOOLEAN,
    tls_required                     BOOLEAN,
    audit_year                       INTEGER,
    source_system                    VARCHAR,
    source_file                      VARCHAR,
    source_row_id                    VARCHAR,
    record_hash                      VARCHAR,
    lineage_batch_id                 VARCHAR,
    mapping_version                  VARCHAR,
    model_version                    VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, bucket_name)
);

CREATE TABLE IF NOT EXISTS gw_silver_ext_telecom_iam_principal (
    run_id                           VARCHAR NOT NULL,
    engagement_id                    VARCHAR NOT NULL,
    accept_event_id                  VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    principal_arn                    VARCHAR NOT NULL,
    principal_type                   VARCHAR,
    allows_external_principal        BOOLEAN,
    mfa_required                     BOOLEAN,
    last_used_dt                     DATE,
    audit_year                       INTEGER,
    source_system                    VARCHAR,
    source_file                      VARCHAR,
    source_row_id                    VARCHAR,
    record_hash                      VARCHAR,
    lineage_batch_id                 VARCHAR,
    mapping_version                  VARCHAR,
    model_version                    VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, principal_arn)
);

CREATE TABLE IF NOT EXISTS gw_silver_ext_telecom_security_group (
    run_id                           VARCHAR NOT NULL,
    engagement_id                    VARCHAR NOT NULL,
    accept_event_id                  VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    sg_id                            VARCHAR NOT NULL,
    vpc_id                           VARCHAR,
    direction                        VARCHAR NOT NULL,
    ip_protocol                      VARCHAR NOT NULL,
    from_port                        INTEGER NOT NULL,
    to_port                          INTEGER NOT NULL,
    cidr                             VARCHAR NOT NULL,
    is_public                        BOOLEAN,
    audit_year                       INTEGER,
    source_system                    VARCHAR,
    source_file                      VARCHAR,
    source_row_id                    VARCHAR,
    record_hash                      VARCHAR,
    lineage_batch_id                 VARCHAR,
    mapping_version                  VARCHAR,
    model_version                    VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, sg_id, direction, ip_protocol, from_port, to_port, cidr)
);

CREATE TABLE IF NOT EXISTS gw_silver_ext_telecom_evidence_bundle (
    run_id                           VARCHAR NOT NULL,
    engagement_id                    VARCHAR NOT NULL,
    accept_event_id                  VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    bundle_id                        VARCHAR NOT NULL,
    project_id                       VARCHAR,
    source_lane                      VARCHAR,
    has_report                       BOOLEAN,
    has_receipt                      BOOLEAN,
    has_live_fire                    BOOLEAN,
    has_adversarial_reverify         BOOLEAN,
    is_sandboxed                     BOOLEAN,
    audit_year                       INTEGER,
    source_system                    VARCHAR,
    source_file                      VARCHAR,
    source_row_id                    VARCHAR,
    record_hash                      VARCHAR,
    lineage_batch_id                 VARCHAR,
    mapping_version                  VARCHAR,
    model_version                    VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, bundle_id)
);

CREATE TABLE IF NOT EXISTS gw_silver_ext_telecom_check_run (
    run_id                           VARCHAR NOT NULL,
    engagement_id                    VARCHAR NOT NULL,
    accept_event_id                  VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    started_at                       TIMESTAMP,
    finished_at                      TIMESTAMP,
    status                           VARCHAR,
    population_size                  INTEGER,
    pages_completed                  INTEGER,
    checkpoint_ts                    TIMESTAMP,
    audit_year                       INTEGER,
    source_system                    VARCHAR,
    source_file                      VARCHAR,
    source_row_id                    VARCHAR,
    record_hash                      VARCHAR,
    lineage_batch_id                 VARCHAR,
    mapping_version                  VARCHAR,
    model_version                    VARCHAR,
    PRIMARY KEY (run_id, accept_event_id)
);

CREATE TABLE IF NOT EXISTS gw_silver_ext_telecom_finding_candidate (
    run_id                           VARCHAR NOT NULL,
    engagement_id                    VARCHAR NOT NULL,
    accept_event_id                  VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    candidate_id                     VARCHAR NOT NULL,
    check_id                         VARCHAR,
    finding_key                      VARCHAR,
    dedupe_hash                      VARCHAR,
    passed_deterministic_gate        BOOLEAN,
    llm_lane_entered                 BOOLEAN,
    llm_verdict                      VARCHAR,
    rule_id                          VARCHAR,
    audit_year                       INTEGER,
    source_system                    VARCHAR,
    source_file                      VARCHAR,
    source_row_id                    VARCHAR,
    record_hash                      VARCHAR,
    lineage_batch_id                 VARCHAR,
    mapping_version                  VARCHAR,
    model_version                    VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, candidate_id)
);

CREATE TABLE IF NOT EXISTS gw_silver_ext_telecom_rule (
    run_id                           VARCHAR NOT NULL,
    engagement_id                    VARCHAR NOT NULL,
    accept_event_id                  VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    rule_id                          VARCHAR NOT NULL,
    rule_name                        VARCHAR,
    source_technique                 VARCHAR,
    rule_kind                        VARCHAR,
    active                           BOOLEAN,
    audit_year                       INTEGER,
    source_system                    VARCHAR,
    source_file                      VARCHAR,
    source_row_id                    VARCHAR,
    record_hash                      VARCHAR,
    lineage_batch_id                 VARCHAR,
    mapping_version                  VARCHAR,
    model_version                    VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, rule_id)
);
