-- 003_ext_telecom_offsec_asmvm_process_silver.sql - process ledger: evidence bundles,
-- the finding-candidate queue (finding_candidate contract shape, the same
-- columns as ext_telecom_offsec_aws_finding_candidate), the pack-local candidate
-- SUBJECT binding, the generalized rule corpus, and the source-run ledger with
-- ingest-computed freshness.
--
-- ext_telecom_offsec_asmvm_candidate_subject exists because the finding_candidate
-- contract carries no subject/asset binding, no severity and no first/last-seen
-- timestamps. An ASM/VM candidate is address-scoped and its age is the audit
-- question (T7 backlog), so the extension lives in a pack-local table joined on
-- candidate_id instead of an altered contract table. See
-- docs/findings/README.md, section 'Contract gaps this pack works around'.

-- ext_telecom_offsec_asmvm_evidence_bundle - Evidence-bundle ledger: provenance and reproduction state of each accepted artifact.
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_evidence_bundle (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    bundle_id                          VARCHAR NOT NULL,
    project_id                         VARCHAR,
    source_lane                        VARCHAR,             -- asm_export|vm_export|probe|manual
    has_report                         BOOLEAN,
    has_receipt                        BOOLEAN,             -- hash / signature receipt for the artifact
    has_live_fire                      BOOLEAN,             -- an independent active probe reproduced it
    has_adversarial_reverify           BOOLEAN,             -- a second reviewer or model tried to disprove it
    is_sandboxed                       BOOLEAN,             -- reproduction ran in isolated compute
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, bundle_id)
);

-- ext_telecom_offsec_asmvm_finding_candidate - Candidate queue in the finding_candidate contract shape (same columns as ext_telecom_offsec_aws_finding_candidate).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_finding_candidate (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    candidate_id                       VARCHAR NOT NULL,
    check_id                           VARCHAR,             -- producer check / queue id
    finding_key                        VARCHAR,
    dedupe_hash                        VARCHAR,
    passed_deterministic_gate          BOOLEAN,
    llm_lane_entered                   BOOLEAN,
    llm_verdict                        VARCHAR,             -- pending|confirmed|duplicate|rejected
    rule_id                            VARCHAR,
    first_seen_ts                      TIMESTAMP,
    last_seen_ts                       TIMESTAMP,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, candidate_id)
);

-- ext_telecom_offsec_asmvm_candidate_subject - Pack-local candidate subject binding: the finding_candidate contract has no subject column and an ASM/VM finding is address-scoped.
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_candidate_subject (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    candidate_id                       VARCHAR NOT NULL,
    check_id                           VARCHAR,
    finding_key                        VARCHAR,
    subject_ip                         VARCHAR,             -- the IP the candidate is about
    subject_kind                       VARCHAR,             -- ip|service|website|alert|cve|network
    candidate_source_system            VARCHAR,             -- cortex_xpanse|ivanti_neurons|... (the source that raised the candidate, not the ingest source)
    severity                           VARCHAR,             -- vendor severity at queue time
    rule_name                          VARCHAR,             -- ASM attack-surface rule / scanner family
    detail_ref                         VARCHAR,             -- pointer back to the source row
    evidence_ref                       VARCHAR,             -- pointer to the evidence bundle / artifact
    dedupe_hash                        VARCHAR,
    first_seen_ts                      TIMESTAMP,
    last_seen_ts                       TIMESTAMP,
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, candidate_id)
);

-- ext_telecom_offsec_asmvm_rule - Generalized rule corpus (ASM attack-surface rules plus proposed scanner-family rules).
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_rule (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    rule_id                            VARCHAR NOT NULL,
    rule_name                          VARCHAR,             -- join key for detection-class generalization
    source_technique                   VARCHAR,             -- T1..T7
    rule_kind                          VARCHAR,             -- asm_asr|scanner_family|deterministic
    active                             BOOLEAN,             -- false = proposed or retired, not deployed
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, rule_id)
);

-- ext_telecom_offsec_asmvm_check_run - Source-run ledger (ASM exports, scanner network runs) plus freshness bookkeeping.
-- Spine: (run_id, engagement_id, accept_event_id) + entity key + source/lineage columns.
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_check_run (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    source_run_id                      VARCHAR NOT NULL,
    started_at                         TIMESTAMP,
    finished_at                        TIMESTAMP,
    status                             VARCHAR,             -- completed|interrupted|running
    population_size                    BIGINT,              -- records the source run covered
    pages_completed                    BIGINT,
    checkpoint_ts                      TIMESTAMP,           -- last checkpoint (freshness anchor)
    reference_ts                       TIMESTAMP,           -- observation reference time the freshness was measured against
    freshness_sla_days                 INTEGER,             -- declared freshness SLA for this source
    stale_days                         INTEGER,             -- INGEST-COMPUTED reference_ts - checkpoint_ts in whole days (NULL when checkpoint_ts is NULL; never a 0 default)
    -- source provenance + ingest lineage
    audit_year                         INTEGER,
    source_system                      VARCHAR,
    source_file                        VARCHAR,
    source_row_id                      VARCHAR,
    record_hash                        VARCHAR,
    lineage_batch_id                   VARCHAR,
    mapping_version                    VARCHAR,
    model_version                      VARCHAR,
    PRIMARY KEY (run_id, accept_event_id, source_run_id)
);
