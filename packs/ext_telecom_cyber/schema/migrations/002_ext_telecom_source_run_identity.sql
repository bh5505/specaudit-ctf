-- Separate the source ledger identity from the ambient engine run scope.
-- The runner wraps this file in a transaction and records its hash. The probe
-- handles a committed migration whose ledger record was interrupted.
-- @applied-probe SELECT 1 FROM information_schema.columns WHERE table_name = 'gw_silver_ext_telecom_check_run' AND column_name = 'source_run_id'

CREATE TABLE gw_silver_ext_telecom_check_run_v2 (
    run_id                           VARCHAR NOT NULL,
    engagement_id                    VARCHAR NOT NULL,
    accept_event_id                  VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    source_run_id                    VARCHAR NOT NULL,
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
    PRIMARY KEY (run_id, accept_event_id, source_run_id)
);

INSERT INTO gw_silver_ext_telecom_check_run_v2 (
    run_id, engagement_id, accept_event_id, source_run_id,
    started_at, finished_at, status, population_size, pages_completed,
    checkpoint_ts, audit_year, source_system, source_file, source_row_id,
    record_hash, lineage_batch_id, mapping_version, model_version
)
SELECT
    run_id, engagement_id, accept_event_id, run_id AS source_run_id,
    started_at, finished_at, status, population_size, pages_completed,
    checkpoint_ts, audit_year, source_system, source_file, source_row_id,
    record_hash, lineage_batch_id, mapping_version, model_version
FROM gw_silver_ext_telecom_check_run;

DROP TABLE gw_silver_ext_telecom_check_run;
ALTER TABLE gw_silver_ext_telecom_check_run_v2 RENAME TO gw_silver_ext_telecom_check_run;
