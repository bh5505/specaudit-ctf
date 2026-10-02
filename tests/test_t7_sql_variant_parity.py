"""T7 diagnostic plans must keep the shipped check's cumulative row contract."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

try:
    import duckdb
except ImportError:  # pragma: no cover - optional local engine
    duckdb = None


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "packs" / "ext_telecom_offsec"
RUN = "synthetic-t7-run"
CHECK = PACK / "checks" / "ext_telecom_offsec_asmvm_t7_asmvm_candidate_backlog.sql"
VARIANTS = (
    ROOT / "tools" / "sql" / "t7_asmvm_candidate_backlog.scalar_eligible.sql",
    ROOT / "tools" / "sql" / "t7_asmvm_candidate_backlog.materialised.sql",
)


@pytest.fixture(params=["sqlite"] + (["duckdb"] if duckdb is not None else []))
def db(request):
    conn = sqlite3.connect(":memory:") if request.param == "sqlite" else duckdb.connect(":memory:")
    for path in sorted((PACK / "schema" / "migrations").glob("*.sql")):
        sql = re.sub(r"--[^\n]*", "", path.read_text(encoding="utf-8"))
        for statement in sql.split(";"):
            if statement.strip():
                conn.execute(statement)
    yield conn
    conn.close()


def insert(conn, table: str, *, accept="accept-a", run=RUN, **values):
    row = {"run_id": run, "engagement_id": "synthetic-engagement",
           "accept_event_id": accept, **values}
    columns = list(row)
    names = ", ".join(f'"{name}"' for name in columns)
    placeholders = ", ".join("?" for _ in columns)
    conn.execute(f'INSERT INTO "{table}" ({names}) VALUES ({placeholders})',
                 list(row.values()))


def rows(conn, path: Path, run=RUN):
    return conn.execute(path.read_text(encoding="utf-8"), (run, 100)).fetchall()


def checked_rows(conn):
    shipped = rows(conn, CHECK)
    for variant in VARIANTS:
        assert rows(conn, variant) == shipped, variant.name
    return {row[0].removeprefix("asmvm:queue:"): row for row in shipped}


def details(row):
    return dict(part.split("=", 1) for part in row[5].split("; "))


def assert_details(row, **expected):
    actual = details(row)
    assert {key: actual[key] for key in expected} == {
        key: str(value) for key, value in expected.items()
    }


def test_variants_match_cumulative_reaccept_zero_queue_and_overqueue(db):
    vm = "ext_telecom_offsec_asmvm_vm_finding"
    surface = "ext_telecom_offsec_asmvm_asm_vm_surface"
    alert = "ext_telecom_offsec_asmvm_alert_endpoint"
    asm_cve = "ext_telecom_offsec_asmvm_cve_observation"
    vm_cve = "ext_telecom_offsec_asmvm_vm_cve_observation"
    vm_cve_finding = "ext_telecom_offsec_asmvm_vm_cve_finding"
    queue = "ext_telecom_offsec_asmvm_finding_candidate"

    # One logical VM finding moves IP across accepts, but is queued once.
    for accept, ip in (("accept-a", "192.0.2.1"),
                       ("accept-b", "192.0.2.2")):
        insert(db, vm, accept=accept, finding_id="vm-one", ip=ip,
               is_open=True, severity=9.8)
        insert(db, surface, accept=accept, ip=ip, has_active_service=True)
    for accept, verdict in (("accept-a", "pending"),
                            ("accept-b", "confirmed")):
        insert(db, queue, accept=accept, candidate_id="vcand-vm-one",
               check_id="vm.scan.critical_open_exposed",
               finding_key="ivanti:finding:vm-one",
               llm_verdict=verdict, passed_deterministic_gate=True)

    # One alert with two affected endpoints contributes two eligible units.
    insert(db, "ext_telecom_offsec_asmvm_alert", alert_id="opaque-alert",
           vendor_alert_id="7007")
    for suffix, ip in (("one", "192.0.2.3"), ("two", "192.0.2.4")):
        insert(db, alert, alert_endpoint_id=f"alert-{suffix}",
               alert_id="opaque-alert", ip=ip, is_active_state=True,
               severity="High")
        insert(db, queue, candidate_id=f"alert-candidate-{suffix}",
               check_id="asm.alert.high_active",
               finding_key=f"xpanse:alert:7007:ip:{ip}",
               llm_verdict="confirmed")

    # One corroborated (IP,CVE) pair has two scanner finding rows but one VM
    # CVE producer unit. Its critical finding is excluded from the separate
    # critical producer, matching the builder's candidate families.
    insert(db, vm, finding_id="vm-cve-one", ip="192.0.2.5",
           is_open=True, severity=9.8)
    insert(db, surface, ip="192.0.2.5", has_active_service=True)
    # The pair has no ASM inference candidate, while two VM candidates are a
    # genuine over-queue.
    for accept in ("accept-a", "accept-b"):
        insert(db, asm_cve, accept=accept,
               cve_observation_id="asm-cve-one", ip="192.0.2.5",
               cve="CVE-2026-0001", is_active=True)
        insert(db, vm_cve, accept=accept, ip="192.0.2.5",
               cve="CVE-2026-0001", is_open=True)
        insert(db, vm_cve_finding, accept=accept, ip="192.0.2.5",
               cve="CVE-2026-0001", finding_id="vm-cve-one", is_open=True)
        insert(db, vm_cve_finding, accept=accept, ip="192.0.2.5",
               cve="CVE-2026-0001", finding_id="second-bridge", is_open=True)
    for suffix in ("one", "two"):
        insert(db, queue, candidate_id=f"vm-cve-candidate-{suffix}",
               check_id="vm.scan.cve",
               finding_key="ivanti:cve:CVE-2026-0001:ip:192.0.2.5",
               llm_verdict="pending")

    # A second run may reuse every logical identifier without changing RUN.
    insert(db, queue, run="other-run", candidate_id="vcand-vm-one",
           check_id="vm.scan.critical_open_exposed",
           finding_key="ivanti:finding:vm-one", llm_verdict="pending")

    result = checked_rows(db)
    assert len(result) == 4
    assert_details(result["vm.scan.critical_open_exposed"],
                   eligible=1, queued=1, backlog=0, over_queued=0,
                   possible_eligible=1, queue_identity_unknown=0,
                   pending_seen=1, confirmed_seen=1, multi_state_candidates=1)
    assert_details(result["asm.alert.high_active"],
                   eligible=2, queued=2, backlog=0, over_queued=0,
                   queue_identity_unknown=0)
    assert_details(result["asm.inferred_cve"],
                   eligible=1, queued=0, backlog=1, over_queued=0)
    assert_details(result["vm.scan.cve"],
                   eligible=1, queued=2, backlog=0, over_queued=1,
                   possible_over_queued=1, queue_identity_unknown=0)


def test_later_cve_pair_does_not_retroactively_unqueue_moved_vm_finding(db):
    finding = "ext_telecom_offsec_asmvm_vm_finding"
    surface = "ext_telecom_offsec_asmvm_asm_vm_surface"
    for accept, ip in (("accept-a", "192.0.2.1"),
                       ("accept-b", "192.0.2.2")):
        insert(db, finding, accept=accept, finding_id="moved",
               ip=ip, is_open=True, severity=9.8)
        insert(db, surface, accept=accept, ip=ip, has_active_service=True)
    insert(db, "ext_telecom_offsec_asmvm_cve_observation", accept="accept-b",
           cve_observation_id="later", ip="192.0.2.2",
           cve="CVE-2026-0001", is_active=True)
    insert(db, "ext_telecom_offsec_asmvm_vm_cve_observation", accept="accept-b",
           ip="192.0.2.2", cve="CVE-2026-0001", is_open=True)
    insert(db, "ext_telecom_offsec_asmvm_vm_cve_finding", accept="accept-b",
           ip="192.0.2.2", cve="CVE-2026-0001",
           finding_id="moved", is_open=True)
    insert(db, "ext_telecom_offsec_asmvm_finding_candidate",
           candidate_id="vcand-moved", check_id="vm.scan.critical_open_exposed",
           finding_key="ivanti:finding:moved", llm_verdict="confirmed")
    result = checked_rows(db)
    assert_details(result["vm.scan.critical_open_exposed"],
                   eligible=1, possible_eligible=1, queued=1,
                   backlog=0, over_queued=0, queue_identity_unknown=0)


def test_later_pair_on_same_ip_bounds_earlier_vm_queue(db):
    finding = "ext_telecom_offsec_asmvm_vm_finding"
    insert(db, finding, finding_id="same", ip="192.0.2.1",
           is_open=True, severity=9.8, last_found_ts="2026-09-01 00:00:00")
    insert(db, "ext_telecom_offsec_asmvm_asm_vm_surface",
           ip="192.0.2.1", has_active_service=True)
    insert(db, "ext_telecom_offsec_asmvm_finding_candidate",
           candidate_id="vcand-same", check_id="vm.scan.critical_open_exposed",
           finding_key="ivanti:finding:same", llm_verdict="pending",
           first_seen_ts="2026-09-01 00:00:00")
    insert(db, finding, accept="accept-b", finding_id="same",
           ip="192.0.2.1", is_open=True, severity=9.8,
           last_found_ts="2026-09-02 00:00:00")
    insert(db, "ext_telecom_offsec_asmvm_cve_observation", accept="accept-b",
           cve_observation_id="later", ip="192.0.2.1",
           cve="CVE-2026-0001", is_active=True,
           first_observed_ts="2026-09-02 00:00:00")
    insert(db, "ext_telecom_offsec_asmvm_vm_cve_observation", accept="accept-b",
           ip="192.0.2.1", cve="CVE-2026-0001", is_open=True,
           last_found_ts="2026-09-02 00:00:00")
    insert(db, "ext_telecom_offsec_asmvm_vm_cve_finding", accept="accept-b",
           ip="192.0.2.1", cve="CVE-2026-0001", finding_id="same",
           is_open=True, last_found_ts="2026-09-02 00:00:00")
    result = checked_rows(db)
    assert_details(result["vm.scan.critical_open_exposed"],
                   eligible=0, possible_eligible=1, queued=1,
                   backlog=0, possible_backlog=0, over_queued=0,
                   possible_over_queued=1, uncertain_sources=1,
                   later_pair_source_seen=1, pair_source_time_unknown=0)


def test_wrong_candidate_and_alert_vendor_ids_do_not_cancel_backlog(db):
    insert(db, "ext_telecom_offsec_asmvm_vm_finding",
           finding_id="real", ip="192.0.2.10", is_open=True, severity=9.8)
    insert(db, "ext_telecom_offsec_asmvm_asm_vm_surface",
           ip="192.0.2.10", has_active_service=True)
    insert(db, "ext_telecom_offsec_asmvm_finding_candidate",
           candidate_id="vcand-other", check_id="vm.scan.critical_open_exposed",
           finding_key="ivanti:finding:real", llm_verdict="pending")

    insert(db, "ext_telecom_offsec_asmvm_alert",
           alert_id="opaque-alert", vendor_alert_id="7007")
    insert(db, "ext_telecom_offsec_asmvm_alert_endpoint",
           alert_endpoint_id="opaque-alert|192.0.2.11", alert_id="opaque-alert",
           ip="192.0.2.11", is_active_state=True, severity="High")
    insert(db, "ext_telecom_offsec_asmvm_finding_candidate",
           candidate_id="wrong-alert", check_id="asm.alert.high_active",
           finding_key="xpanse:alert:9999:ip:192.0.2.11",
           llm_verdict="pending")

    result = checked_rows(db)
    for producer in ("vm.scan.critical_open_exposed", "asm.alert.high_active"):
        assert_details(result[producer], eligible=1, queued=1, backlog=1,
                       over_queued=1, possible_backlog=1,
                       possible_over_queued=1, queue_identity_unknown=0)


@pytest.mark.parametrize("alert_id,candidate_vendor,over_queued,risk", [
    ("internal-alert-17", "17", 0, 26),
    ("internal-alert-17", "internal-alert-17", 1, 34),
    ("xpanse-alert-17", "17", 0, 26),
])
def test_conflicting_accepted_alert_vendor_ids_remain_uncertain(
        db, alert_id, candidate_vendor, over_queued, risk):
    for accept, vendor_id in (("accept-vendor-17", "17"),
                              ("accept-vendor-18", "18")):
        insert(db, "ext_telecom_offsec_asmvm_alert", accept=accept,
               alert_id=alert_id, vendor_alert_id=vendor_id,
               is_active_state=True, severity="High")
    insert(db, "ext_telecom_offsec_asmvm_alert_endpoint",
           accept="accept-endpoint",
           alert_endpoint_id=f"{alert_id}|192.0.2.1", alert_id=alert_id,
           ip="192.0.2.1", is_active_state=True, severity="High")
    insert(db, "ext_telecom_offsec_asmvm_finding_candidate",
           accept="accept-queue", candidate_id="queued-alert",
           check_id="asm.alert.high_active",
           finding_key=f"xpanse:alert:{candidate_vendor}:ip:192.0.2.1")

    row = checked_rows(db)["asm.alert.high_active"]
    assert_details(row, eligible=0, queued=1, backlog=0,
                   over_queued=over_queued, possible_eligible=1,
                   possible_backlog=1, possible_over_queued=1,
                   uncertain_sources=1, source_identity_unknown=1)
    assert row[7] == risk


@pytest.mark.parametrize("second_key", [None, "xpanse:alert:18:ip:192.0.2.1"])
def test_one_conflicted_alert_has_capacity_for_only_one_queue_id(db, second_key):
    for accept, vendor_id in (("accept-vendor-17", "17"),
                              ("accept-vendor-18", "18")):
        insert(db, "ext_telecom_offsec_asmvm_alert", accept=accept,
               alert_id="internal-alert", vendor_alert_id=vendor_id,
               is_active_state=True, severity="High")
    insert(db, "ext_telecom_offsec_asmvm_alert_endpoint",
           accept="accept-endpoint", alert_endpoint_id="internal-alert|192.0.2.1",
           alert_id="internal-alert", ip="192.0.2.1",
           is_active_state=True, severity="High")
    for candidate_id, key in (("known", "xpanse:alert:17:ip:192.0.2.1"),
                              ("second", second_key)):
        insert(db, "ext_telecom_offsec_asmvm_finding_candidate",
               accept="accept-queue", candidate_id=candidate_id,
               check_id="asm.alert.high_active", finding_key=key)

    row = checked_rows(db)["asm.alert.high_active"]
    assert_details(row, eligible=0, queued=2, backlog=0, over_queued=1,
                   possible_eligible=1, source_identity_unknown=1,
                   queue_identity_unknown=int(second_key is None))
    assert row[7] == 34


def test_overlapping_ambiguous_alert_keys_do_not_multiply_one_candidate(db):
    for alert_id in ("internal-a", "internal-b"):
        for accept, vendor_id in (("accept-vendor-17", "17"),
                                  ("accept-vendor-18", "18")):
            insert(db, "ext_telecom_offsec_asmvm_alert", accept=accept,
                   alert_id=alert_id, vendor_alert_id=vendor_id,
                   is_active_state=True, severity="High")
        insert(db, "ext_telecom_offsec_asmvm_alert_endpoint",
               accept="accept-endpoint",
               alert_endpoint_id=f"{alert_id}|192.0.2.1",
               alert_id=alert_id, ip="192.0.2.1",
               is_active_state=True, severity="High")
    for candidate_id, key in (("known", "xpanse:alert:17:ip:192.0.2.1"),
                              ("wrong", "xpanse:alert:99:ip:192.0.2.1")):
        insert(db, "ext_telecom_offsec_asmvm_finding_candidate",
               accept="accept-queue", candidate_id=candidate_id,
               check_id="asm.alert.high_active", finding_key=key)

    row = checked_rows(db)["asm.alert.high_active"]
    assert_details(row, eligible=0, queued=2, backlog=0, over_queued=1,
                   possible_eligible=2, source_identity_unknown=2,
                   queue_identity_unknown=0)
    assert row[7] == 34


def test_unknown_pair_times_bound_possible_vm_backlog(db):
    insert(db, "ext_telecom_offsec_asmvm_vm_finding",
           finding_id="unknown", ip="192.0.2.20", is_open=True,
           severity=9.8, last_found_ts="2026-09-01 00:00:00")
    insert(db, "ext_telecom_offsec_asmvm_asm_vm_surface",
           ip="192.0.2.20", has_active_service=True)
    insert(db, "ext_telecom_offsec_asmvm_cve_observation", accept="accept-b",
           cve_observation_id="unknown-pair", ip="192.0.2.20",
           cve="CVE-2026-0020", is_active=True)
    insert(db, "ext_telecom_offsec_asmvm_vm_cve_observation", accept="accept-b",
           ip="192.0.2.20", cve="CVE-2026-0020", is_open=True)
    insert(db, "ext_telecom_offsec_asmvm_vm_cve_finding", accept="accept-b",
           ip="192.0.2.20", cve="CVE-2026-0020",
           finding_id="unknown", is_open=True)

    result = checked_rows(db)
    assert_details(result["vm.scan.critical_open_exposed"],
                   eligible=0, possible_eligible=1, queued=0,
                   backlog=0, possible_backlog=1, over_queued=0,
                   uncertain_sources=1, later_pair_source_seen=0,
                   pair_source_time_unknown=1)
