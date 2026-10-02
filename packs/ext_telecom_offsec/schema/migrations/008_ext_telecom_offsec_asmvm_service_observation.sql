-- Additive live-service observation landing zone for predicted telecom-service
-- endpoints (P7).
--
-- The telecom-service endpoints (SNMP 161/udp, IKE 500/tcp, SSH 22/tcp, NTP
-- 123/udp, DNS 53/udp) are source-declared (seed), not live-observed. This
-- table records whether a service was actually observed on the target IP, from
-- either indirect recon (passive third-party intel, e.g. shodan.host) or a lab
-- stand-in probe (governed snmp_readtier / ike_readtier arm, is_sandboxed=true).
--
-- The t1_telecom_control_plane_exposed and t1_exposed_mgmt_ports checks join this
-- table to tag each endpoint observed vs predicted: an observed service (a live
-- probe or passive intel confirmed the service is present) raises the risk score
-- (corroborated); a predicted-only service (source seed, no observation) keeps
-- the base score (unconfirmed). A NEGATIVE observation (observed = false, e.g.
-- shodan.host reports the IP is absent) does not raise the score; it records the
-- gap. An attribution note (the observed owner differs from the expected owner)
-- may be carried in observation_source. A NULL observed value is treated as not
-- observed (predicted, unconfirmed).
CREATE TABLE IF NOT EXISTS ext_telecom_offsec_asmvm_service_observation (
    -- accept spine (required on every pack-owned silver table)
    run_id                             VARCHAR NOT NULL,
    engagement_id                      VARCHAR NOT NULL,
    accept_event_id                    VARCHAR NOT NULL DEFAULT '00000000-0000-0000-0000-0000-000000000000',
    service_observation_id             VARCHAR,             -- stable id (svcobs-<key>)
    ip                                 VARCHAR NOT NULL,    -- target IP
    port                               INTEGER NOT NULL,    -- service port
    protocol                           VARCHAR NOT NULL,    -- tcp / udp
    service_name                       VARCHAR,             -- e.g. SnmpServer, IkeServer, SshServer, NtpServer, DnsServer
    observed                           BOOLEAN,             -- TRUE if the service was observed (present)
    observation_source                 VARCHAR,             -- e.g. 'shodan.host', 'snmp_readtier stand-in', 'ike_readtier stand-in'
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
    PRIMARY KEY (run_id, accept_event_id, service_observation_id)
);
