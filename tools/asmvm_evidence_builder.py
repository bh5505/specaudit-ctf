#!/usr/bin/env python3
"""build_pack_evidence.py — project the Glasswing dev silver DB into the real
pack-shaped tables of packs/ext_telecom_asmvm and write one CSV per table.

The dev workspace (glasswing_silver.duckdb, built by build_glasswing_silver.py)
uses gw_silver_ext_* staging tables whose columns are close to, but not equal
to, the pack schema. This script creates the pack's own DDL (from the pack
migrations), inserts with explicit column lists, and exports pack-shaped CSVs
into pack_evidence/ so the pack's checks can be run unmodified by
ctf_run_checks.py against real ASM/VM evidence under both DuckDB and SQLite.

Derived-at-ingest columns the pack contract requires (prefix_16/prefix_24,
check_run.reference_ts / freshness_sla_days / stale_days, surrogate keys,
accept_event_id for derived rows) are computed here — exactly what the runtime
ingest mapper would do.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

import duckdb

RUN_ID = "gw-asmvm-20260902"
ENGAGEMENT = "glasswing-2026"
BATCH = "glasswing-asmvm-20260902"
VERSION = "asmvm-v1"
REFERENCE_TS = "2026-09-02 12:00:00"
SLA_DAYS = 14

XPANSE_FILE = "UNIFIED_ASSETS_TABLE_2026-09-02T12_10_57.csv"


def spine(src_system: str, src_file: str, order_key: str, hash_key: str,
          tag: str, *, spine_from_src: bool = False) -> str:
    """Trailing spine columns for an INSERT ... SELECT.

    spine_from_src=True copies the source table's own lineage columns (base
    silver tables carry them); otherwise they are synthesised (derived rows).
    """
    if spine_from_src:
        return f"""
            audit_year, source_system, source_file, source_row_id, record_hash,
            lineage_batch_id, mapping_version, model_version, run_id,
            engagement_id, COALESCE(accept_event_id,
              md5(concat('accept|{tag}|', {hash_key}))) AS accept_event_id"""
    return f"""
            2026 AS audit_year,
            '{src_system}' AS source_system,
            '{src_file}' AS source_file,
            row_number() OVER (ORDER BY {order_key}) AS source_row_id,
            md5(concat('{tag}|', {hash_key})) AS record_hash,
            '{BATCH}' AS lineage_batch_id,
            '{VERSION}' AS mapping_version,
            '{VERSION}' AS model_version,
            '{RUN_ID}' AS run_id,
            '{ENGAGEMENT}' AS engagement_id,
            md5(concat('accept|{tag}|', {hash_key})) AS accept_event_id"""


def prefix_expr(ip: str, octets: int, bits: int) -> str:
    """Ingest-computed grouping key: '<a>.<b>.0.0/16' or '<a>.<b>.<c>.0/24'.

    Stored as a column because string/date functions differ between DuckDB and
    SQLite - the checks group on this instead of computing it.
    """
    parts = [f"SPLIT_PART({ip}, '.', {i + 1})" for i in range(octets)]
    tail = "'" + ".0" * (4 - octets) + f"/{bits}" + "'"
    return "concat(" + ", '.', ".join(parts) + ", " + tail + ")"


def inserts(dev: str) -> list[tuple[str, str]]:
    """(pack table, INSERT statement) in dependency-free order."""
    d = f"{dev}.main."
    out: list[tuple[str, str]] = []
    add = out.append

    add(("ext_telecom_asmvm_audit_period", f"""
        INSERT INTO ext_telecom_asmvm_audit_period
          (audit_year, period_start, period_end, is_open)
        VALUES (2026, DATE '2026-01-01', DATE '2026-12-31', TRUE)"""))

    add(("ext_telecom_asmvm_asset", f"""
        INSERT INTO ext_telecom_asmvm_asset
          (run_id, engagement_id, accept_event_id, asset_id, asset_name,
           asset_type, ipv4_list, ipv6_list, has_active_services,
           has_related_alerts, has_related_incidents, inferred_vuln_score,
           inferred_cves, business_units, sources, active_service_types,
           asn_handles, date_added, last_observed, audit_year, source_system,
           source_file, source_row_id, record_hash, lineage_batch_id,
           mapping_version, model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|asset|', asset_id))),
               asset_id, asset_name, asset_type, ipv4_list, ipv6_list,
               has_active_services, has_related_alerts, has_related_incidents,
               inferred_vuln_score, inferred_cves, business_units, sources,
               active_service_types, asn_handles, date_added, last_observed,
               audit_year, source_system, source_file, source_row_id,
               record_hash, lineage_batch_id, mapping_version, model_version
        FROM {d}gw_silver_ext_asmvm_asm_asset"""))

    add(("ext_telecom_asmvm_service", f"""
        INSERT INTO ext_telecom_asmvm_service
          (run_id, engagement_id, accept_event_id, service_id, service_name,
           service_type, ipv4_list, ipv6_list, port, protocol, is_active,
           domain, providers, active_classifications, product_version,
           inferred_vuln_score, inferred_cves, has_inferred_cve_signal,
           first_observed, last_observed, audit_year, source_system,
           source_file, source_row_id, record_hash, lineage_batch_id,
           mapping_version, model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|service|', service_id))),
               service_id, service_name, service_type, ipv4_list, ipv6_list,
               port, protocol, is_active, domain, providers,
               active_classifications, product_version, inferred_vuln_score,
               inferred_cves, has_inferred_cve_signal, first_observed,
               last_observed, audit_year, source_system, source_file,
               source_row_id, record_hash, lineage_batch_id, mapping_version,
               model_version
        FROM {d}gw_silver_ext_asmvm_asm_service"""))

    add(("ext_telecom_asmvm_website", f"""
        INSERT INTO ext_telecom_asmvm_website
          (run_id, engagement_id, accept_event_id, website_id, host, port,
           is_active, http_type, site_category, technologies,
           failed_security_assessments, has_failed_assessment, authentication,
           root_http_status, is_non_configured_host, ipv4_list,
           third_party_script_domains, inferred_vuln_score, inferred_cves,
           country, first_observed, last_observed, audit_year, source_system,
           source_file, source_row_id, record_hash, lineage_batch_id,
           mapping_version, model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|website|', website_id))),
               website_id, host, port, is_active, http_type, site_category,
               technologies, failed_security_assessments, has_failed_assessment,
               authentication, root_http_status, is_non_configured_host,
               ipv4_list, third_party_script_domains, inferred_vuln_score,
               inferred_cves, country, first_observed, last_observed,
               audit_year, source_system, source_file, source_row_id,
               record_hash, lineage_batch_id, mapping_version, model_version
        FROM {d}gw_silver_ext_asmvm_asm_website"""))

    add(("ext_telecom_asmvm_alert", f"""
        INSERT INTO ext_telecom_asmvm_alert
          (run_id, engagement_id, accept_event_id, alert_id, vendor_alert_id,
           alert_version, alert_name, asr_rule, asr_category, severity,
           resolution_status, is_excluded, is_active_state, ipv4_list,
           domain_names, incident_ref, incident_status, mitre_tactic,
           mitre_technique, observed_at, last_observed, audit_year,
           source_system, source_file, source_row_id, record_hash,
           lineage_batch_id, mapping_version, model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|alert|', alert_id))),
               alert_id, vendor_alert_id, alert_version, alert_name, asr_rule,
               asr_category, severity, resolution_status, is_excluded,
               is_active_state, ipv4_list, domain_names, incident_id,
               incident_status, mitre_tactic, mitre_technique, observed_at,
               last_observed, audit_year, source_system, source_file,
               source_row_id, record_hash, lineage_batch_id, mapping_version,
               model_version
        FROM {d}gw_silver_ext_asmvm_asm_alert"""))

    add(("ext_telecom_asmvm_incident", f"""
        INSERT INTO ext_telecom_asmvm_incident
          (run_id, engagement_id, accept_event_id, incident_id,
           vendor_incident_id, asr_rule, status, score, total_alerts,
           critical_alerts, high_alerts, medium_alerts, low_alerts, ipv4_list,
           domain_names, port, mitre_tactic, mitre_technique, created_at,
           last_observed, resolved_at, audit_year, source_system, source_file,
           source_row_id, record_hash, lineage_batch_id, mapping_version,
           model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|incident|', incident_id))),
               incident_id, vendor_incident_id, asr_rule, status, score,
               total_alerts, critical_alerts, high_alerts, medium_alerts,
               low_alerts, ipv4_list, domain_names, port, mitre_tactic,
               mitre_technique, created_at, last_observed, resolved_at,
               audit_year, source_system, source_file, source_row_id,
               record_hash, lineage_batch_id, mapping_version, model_version
        FROM {d}gw_silver_ext_asmvm_asm_incident"""))

    add(("ext_telecom_asmvm_owned_ip_range", f"""
        INSERT INTO ext_telecom_asmvm_owned_ip_range
          (run_id, engagement_id, accept_event_id, range_id, ip_version,
           first_ip, last_ip, ip_from, ip_to, ips_count,
           active_responsive_ips, business_units, asn_handles, is_subrange,
           date_added, audit_year, source_system, source_file, source_row_id,
           record_hash, lineage_batch_id, mapping_version, model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|range|', range_id))),
               range_id, ip_version, first_ip, last_ip, ip_from, ip_to,
               ips_count, active_responsive_ips, business_units, asn_handles,
               is_subrange, date_added, audit_year, source_system, source_file,
               source_row_id, record_hash, lineage_batch_id, mapping_version,
               model_version
        FROM {d}gw_silver_ext_asmvm_owned_ip_range
        WHERE ip_version = 4"""))

    add(("ext_telecom_asmvm_ip", f"""
        INSERT INTO ext_telecom_asmvm_ip
          (run_id, engagement_id, accept_event_id, ip, ip_bigint, seen_via,
           has_active_service, asm_observations, audit_year, source_system,
           source_file, source_row_id, record_hash, lineage_batch_id,
           mapping_version, model_version)
        SELECT '{RUN_ID}', '{ENGAGEMENT}', md5(concat('accept|ip|', ip)), ip,
               ip_bigint, seen_via, has_active_service, asm_observations, 2026,
               'cortex_xpanse', '{XPANSE_FILE}',
               row_number() OVER (ORDER BY ip_bigint),
               md5(concat('ip|', ip)), '{BATCH}', '{VERSION}', '{VERSION}'
        FROM {d}gw_silver_ext_asmvm_asm_ip"""))

    add(("ext_telecom_asmvm_service_endpoint", f"""
        INSERT INTO ext_telecom_asmvm_service_endpoint
          (run_id, engagement_id, accept_event_id, service_endpoint_id,
           service_id, ip, service_name, service_type, port, protocol,
           is_active, inferred_vuln_score, inferred_cves, product_version,
           audit_year, source_system, source_file, source_row_id, record_hash,
           lineage_batch_id, mapping_version, model_version)
        SELECT '{RUN_ID}', '{ENGAGEMENT}',
               md5(concat('accept|svc_ep|', service_id, '|', ip)),
               md5(concat('svc_ep|', service_id, '|', ip)), service_id, ip,
               service_name, service_type, port, protocol, is_active,
               inferred_vuln_score, inferred_cves, product_version, 2026,
               'cortex_xpanse', '{XPANSE_FILE}',
               row_number() OVER (ORDER BY ip, service_id),
               md5(concat('svc_ep|', service_id, '|', ip)), '{BATCH}',
               '{VERSION}', '{VERSION}'
        FROM {d}gw_silver_ext_asmvm_service_ip"""))

    add(("ext_telecom_asmvm_website_endpoint", f"""
        INSERT INTO ext_telecom_asmvm_website_endpoint
          (run_id, engagement_id, accept_event_id, website_endpoint_id,
           website_id, ip, host, port, is_active, http_type,
           has_failed_assessment, failed_security_assessments, inferred_cves,
           audit_year, source_system, source_file, source_row_id, record_hash,
           lineage_batch_id, mapping_version, model_version)
        SELECT '{RUN_ID}', '{ENGAGEMENT}',
               md5(concat('accept|web_ep|', website_id, '|', ip)),
               md5(concat('web_ep|', website_id, '|', ip)), website_id, ip,
               host, port, is_active, http_type, has_failed_assessment,
               failed_security_assessments, inferred_cves, 2026,
               'cortex_xpanse', '{XPANSE_FILE}',
               row_number() OVER (ORDER BY ip, website_id),
               md5(concat('web_ep|', website_id, '|', ip)), '{BATCH}',
               '{VERSION}', '{VERSION}'
        FROM {d}gw_silver_ext_asmvm_website_ip"""))

    add(("ext_telecom_asmvm_alert_endpoint", f"""
        INSERT INTO ext_telecom_asmvm_alert_endpoint
          (run_id, engagement_id, accept_event_id, alert_endpoint_id,
           alert_id, ip, severity, resolution_status, is_active_state,
           asr_rule, audit_year, source_system, source_file, source_row_id,
           record_hash, lineage_batch_id, mapping_version, model_version)
        SELECT '{RUN_ID}', '{ENGAGEMENT}',
               md5(concat('accept|alert_ep|', alert_id, '|', ip)),
               md5(concat('alert_ep|', alert_id, '|', ip)), alert_id, ip,
               severity, resolution_status, is_active_state, asr_rule, 2026,
               'cortex_xpanse', '{XPANSE_FILE}',
               row_number() OVER (ORDER BY ip, alert_id),
               md5(concat('alert_ep|', alert_id, '|', ip)), '{BATCH}',
               '{VERSION}', '{VERSION}'
        FROM {d}gw_silver_ext_asmvm_alert_ip"""))

    add(("ext_telecom_asmvm_cve_observation", f"""
        INSERT INTO ext_telecom_asmvm_cve_observation
          (run_id, engagement_id, accept_event_id, cve_observation_id, ip, cve,
           sources, evidence_ref, inferred_score, is_active, audit_year,
           source_system, source_file, source_row_id, record_hash,
           lineage_batch_id, mapping_version, model_version)
        SELECT '{RUN_ID}', '{ENGAGEMENT}', md5(concat('accept|asm_cve|', ip, '|', cve)),
               md5(concat('asm_cve|', ip, '|', cve)), ip, cve, sources,
               evidence_ref, inferred_score, is_active, 2026, 'cortex_xpanse',
               '{XPANSE_FILE}', row_number() OVER (ORDER BY ip, cve),
               md5(concat('asm_cve|', ip, '|', cve)), '{BATCH}', '{VERSION}',
               '{VERSION}'
        FROM {d}gw_silver_ext_asmvm_cve_observation"""))

    add(("ext_telecom_asmvm_vm_asset", f"""
        INSERT INTO ext_telecom_asmvm_vm_asset
          (run_id, engagement_id, accept_event_id, asset_id, ip, hostname,
           network_name, scanner, is_external, last_scan_ts,
           last_credentialed_scan_ts, has_credentialed_scan, open_cve_count,
           open_threat_count, total_finding_count, vrr_critical_max,
           vrr_high_max, os_detected, audit_year, source_system, source_file,
           source_row_id, record_hash, lineage_batch_id, mapping_version,
           model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|vm_asset|', asset_id))),
               asset_id, ip, hostname, network_name, scanner, is_external,
               last_scan_ts, last_credentialed_scan_ts, has_credentialed_scan,
               open_cve_count, open_threat_count, total_finding_count,
               vrr_critical_max, vrr_high_max, os_detected, audit_year,
               source_system, source_file, source_row_id, record_hash,
               lineage_batch_id, mapping_version, model_version
        FROM {d}gw_silver_ext_asmvm_vm_asset"""))

    add(("ext_telecom_asmvm_vm_finding", f"""
        INSERT INTO ext_telecom_asmvm_vm_finding
          (run_id, engagement_id, accept_event_id, finding_id, ip, title, qid,
           plugin_family, port, protocol, severity, risk_rating, status,
           is_open, last_found_ts, resolved_ts, scanner, audit_year,
           source_system, source_file, source_row_id, record_hash,
           lineage_batch_id, mapping_version, model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|vm_find|', finding_id, '|', ip))),
               finding_id, ip, title, qid, plugin_family, port, protocol,
               severity, risk_rating, status, is_open, last_found_ts,
               resolved_ts, scanner, audit_year, source_system, source_file,
               source_row_id, record_hash, lineage_batch_id, mapping_version,
               model_version
        FROM {d}gw_silver_ext_asmvm_vm_finding"""))

    add(("ext_telecom_asmvm_vm_cve_finding", f"""
        INSERT INTO ext_telecom_asmvm_vm_cve_finding
          (run_id, engagement_id, accept_event_id, ip, cve, finding_id,
           severity, is_open, last_found_ts, audit_year, source_system,
           source_file, source_row_id, record_hash, lineage_batch_id,
           mapping_version, model_version)
        -- the dev staging table can repeat an (ip, cve, finding_id) triple with
        -- differing severity/timestamps; the pack table is keyed on the triple,
        -- so the ingest collapses duplicates (worst severity, open if any row is
        -- open, most recent sighting).
        SELECT '{RUN_ID}', '{ENGAGEMENT}',
               md5(concat('accept|vm_cve_f|', ip, '|', cve, '|', finding_id)),
               ip, cve, finding_id, max(severity), bool_or(is_open),
               max(last_found_ts), 2026, max(source_system),
               'ivanti_external_findings.duckdb',
               row_number() OVER (ORDER BY ip, cve, finding_id),
               md5(concat('vm_cve_f|', ip, '|', cve, '|', finding_id)),
               '{BATCH}', '{VERSION}', '{VERSION}'
        FROM {d}gw_silver_ext_asmvm_vm_cve_finding
        GROUP BY ip, cve, finding_id"""))

    add(("ext_telecom_asmvm_vm_cve_observation", f"""
        INSERT INTO ext_telecom_asmvm_vm_cve_observation
          (run_id, engagement_id, accept_event_id, ip, cve, evidence_ref,
           severity, is_open, finding_count, last_found_ts, scan_mode,
           scan_confidence, audit_year, source_system, source_file,
           source_row_id, record_hash, lineage_batch_id, mapping_version,
           model_version)
        SELECT '{RUN_ID}', '{ENGAGEMENT}',
               md5(concat('accept|vm_cve|', ip, '|', cve, '|', source_system)),
               ip, cve, max(evidence_ref), max(severity), bool_or(is_open),
               sum(finding_count), max(last_found_ts), max(scan_mode),
               max(scan_confidence), 2026, source_system,
               'ivanti_external_findings.duckdb',
               row_number() OVER (ORDER BY ip, cve, source_system),
               md5(concat('vm_cve|', ip, '|', cve, '|', source_system)),
               '{BATCH}', '{VERSION}', '{VERSION}'
        FROM {d}gw_silver_ext_asmvm_vm_cve_observation
        GROUP BY ip, cve, source_system"""))

    add(("ext_telecom_asmvm_asm_vm_surface", f"""
        INSERT INTO ext_telecom_asmvm_asm_vm_surface
          (run_id, engagement_id, accept_event_id, ip, ip_bigint, prefix_16,
           prefix_24, seen_via, has_active_service, inside_owned_range,
           in_vm_estate, vm_asset_id, vm_last_scan_ts,
           vm_has_credentialed_scan, vm_open_findings, vm_open_critical,
           vm_max_severity, asm_inferred_cves, asm_active_alerts,
           asm_high_alerts, asm_exposed_services, asm_exposed_websites,
           audit_year, source_system, source_file, source_row_id, record_hash,
           lineage_batch_id, mapping_version, model_version)
        SELECT '{RUN_ID}', '{ENGAGEMENT}', md5(concat('accept|surface|', ip)),
               ip, ip_bigint, {prefix_expr('ip', 2, 16)},
               {prefix_expr('ip', 3, 24)}, seen_via, has_active_service,
               inside_owned_range, in_vm_estate, vm_asset_id, vm_last_scan_ts,
               vm_has_credentialed_scan, vm_open_findings, vm_open_critical,
               vm_max_severity, asm_inferred_cves, asm_active_alerts,
               asm_high_alerts, asm_exposed_services, asm_exposed_websites,
               2026, 'cortex_xpanse+ivanti_neurons', 'reconciled',
               row_number() OVER (ORDER BY ip_bigint),
               md5(concat('surface|', ip)), '{BATCH}', '{VERSION}',
               '{VERSION}'
        FROM {d}gw_silver_ext_asmvm_surface"""))

    add(("ext_telecom_asmvm_evidence_bundle", f"""
        INSERT INTO ext_telecom_asmvm_evidence_bundle
          (run_id, engagement_id, accept_event_id, bundle_id, project_id,
           source_lane, has_report, has_receipt, has_live_fire,
           has_adversarial_reverify, is_sandboxed, audit_year, source_system,
           source_file, source_row_id, record_hash, lineage_batch_id,
           mapping_version, model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|bundle|', bundle_id))),
               bundle_id, project_id, source_lane, has_report, has_receipt,
               has_live_fire, has_adversarial_reverify, is_sandboxed,
               audit_year, src_system, src_file, source_row_id, record_hash,
               lineage_batch_id, mapping_version, model_version
        FROM {d}gw_silver_ext_telecom_evidence_bundle"""))

    add(("ext_telecom_asmvm_finding_candidate", f"""
        INSERT INTO ext_telecom_asmvm_finding_candidate
          (run_id, engagement_id, accept_event_id, candidate_id, check_id,
           finding_key, dedupe_hash, passed_deterministic_gate,
           llm_lane_entered, llm_verdict, rule_id, first_seen_ts, last_seen_ts,
           audit_year, source_system, source_file, source_row_id, record_hash,
           lineage_batch_id, mapping_version, model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|cand|', candidate_id))),
               candidate_id, check_id, finding_key, dedupe_hash,
               passed_deterministic_gate, llm_lane_entered, llm_verdict,
               rule_id, first_seen_ts, last_seen_ts, audit_year, src_system,
               src_file, source_row_id, record_hash, lineage_batch_id,
               mapping_version, model_version
        FROM {d}gw_silver_ext_telecom_finding_candidate"""))

    add(("ext_telecom_asmvm_candidate_subject", f"""
        INSERT INTO ext_telecom_asmvm_candidate_subject
          (run_id, engagement_id, accept_event_id, candidate_id, check_id,
           finding_key, subject_ip, subject_kind, candidate_source_system,
           severity, rule_name, detail_ref, evidence_ref, dedupe_hash,
           first_seen_ts, last_seen_ts, audit_year, source_system, source_file,
           source_row_id, record_hash, lineage_batch_id, mapping_version,
           model_version)
        SELECT '{RUN_ID}', '{ENGAGEMENT}',
               md5(concat('accept|candsubj|', candidate_id)), candidate_id,
               check_id, finding_key, subject_ip,
               CASE WHEN subject_ip IS NULL THEN 'grouping' ELSE 'ip' END,
               source_system, severity, rule_name, detail_ref, NULL,
               dedupe_hash, first_seen_ts, last_seen_ts, 2026,
               'glasswing_rehearsal', 'candidate_ledger.csv',
               row_number() OVER (ORDER BY candidate_id),
               md5(concat('candsubj|', candidate_id)), '{BATCH}', '{VERSION}',
               '{VERSION}'
        FROM {d}gw_silver_ext_asmvm_candidate_ext"""))

    add(("ext_telecom_asmvm_rule", f"""
        INSERT INTO ext_telecom_asmvm_rule
          (run_id, engagement_id, accept_event_id, rule_id, rule_name,
           source_technique, rule_kind, active, audit_year, source_system,
           source_file, source_row_id, record_hash, lineage_batch_id,
           mapping_version, model_version)
        SELECT run_id, engagement_id,
               COALESCE(accept_event_id, md5(concat('accept|rule|', rule_id))),
               rule_id, rule_name, source_technique, rule_kind, active,
               audit_year, src_system, src_file, source_row_id, record_hash,
               lineage_batch_id, mapping_version, model_version
        FROM {d}gw_silver_ext_telecom_rule"""))

    # One source-run ledger: the VM scan runs plus the ASM/telecom export runs.
    # stale_days is computed at ingest (no date functions in check SQL);
    # a NULL checkpoint_ts stays NULL (unknown), never 0.
    stale = ("CASE WHEN checkpoint_ts IS NULL THEN NULL ELSE "
             "datediff('day', checkpoint_ts, TIMESTAMP '" + REFERENCE_TS + "') END")
    add(("ext_telecom_asmvm_check_run", f"""
        INSERT INTO ext_telecom_asmvm_check_run
          (run_id, engagement_id, accept_event_id, source_run_id, started_at,
           finished_at, status, population_size, pages_completed,
           checkpoint_ts, reference_ts, freshness_sla_days, stale_days,
           audit_year, source_system, source_file, source_row_id, record_hash,
           lineage_batch_id, mapping_version, model_version)
        SELECT '{RUN_ID}', '{ENGAGEMENT}',
               md5(concat('accept|run|', source_run_id)), source_run_id,
               started_at, finished_at, status, population_size,
               pages_completed, checkpoint_ts,
               TIMESTAMP '{REFERENCE_TS}', {SLA_DAYS}, {stale}, 2026,
               'ivanti_neurons', 'ivanti_external_findings.duckdb',
               row_number() OVER (ORDER BY source_run_id),
               md5(concat('run|', source_run_id)), '{BATCH}', '{VERSION}',
               '{VERSION}'
        FROM {d}gw_silver_ext_asmvm_vm_run
        UNION ALL
        SELECT '{RUN_ID}', '{ENGAGEMENT}',
               md5(concat('accept|run|', source_run_id)), source_run_id,
               started_at, finished_at, status, population_size,
               pages_completed, checkpoint_ts,
               TIMESTAMP '{REFERENCE_TS}', {SLA_DAYS}, {stale}, 2026,
               src_system, src_file, 1000 + row_number() OVER (ORDER BY source_run_id),
               md5(concat('run2|', source_run_id)), '{BATCH}', '{VERSION}',
               '{VERSION}'
        FROM {d}gw_silver_ext_telecom_check_run
        -- the three VM scan runs also appear in the export-run ledger; the pack
        -- keys check_run on source_run_id, so keep exactly one row per run
        WHERE source_run_id NOT IN
              (SELECT source_run_id FROM {d}gw_silver_ext_asmvm_vm_run)"""))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev-db", required=True,
                    help="dev silver DuckDB holding the gw_silver_ext_* staging tables")
    ap.add_argument("--pack", required=True, help="pack root (schema/migrations)")
    ap.add_argument("--out", required=True, help="output dir for pack-shaped CSVs")
    args = ap.parse_args()

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    work = pathlib.Path(args.out + ".duckdb")
    if work.exists():
        work.unlink()
    con = duckdb.connect(str(work))
    for p in sorted(pathlib.Path(args.pack, "schema", "migrations").glob("*.sql")):
        con.execute(p.read_text(encoding="utf-8"))
    con.execute(f"ATTACH {args.dev_db!r} AS dev (READ_ONLY)")

    counts: dict[str, int] = {}
    for table, sql in inserts("dev"):
        con.execute(sql)
        counts[table] = con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]

    for table in counts:
        cols = [r[0] for r in con.execute(f'DESCRIBE SELECT * FROM {table} LIMIT 0').fetchall()]
        col_list = ", ".join(f'"{c}"' for c in cols)
        con.execute(f"COPY (SELECT {col_list} FROM {table} ORDER BY 1, 2, 3) "
                    f"TO '{(out_dir / (table + '.csv')).as_posix()}' (HEADER)")

    print(f"{'table':44s} {'rows':>9s}  csv")
    for table, n in sorted(counts.items()):
        size = (out_dir / (table + '.csv')).stat().st_size
        print(f"{table:44s} {n:9,d}  {size:12,d}")
    print(f"\nrun_id={RUN_ID} engagement={ENGAGEMENT} -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
