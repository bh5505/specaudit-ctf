"""SAFE-01 empirical containment suite: acquisition gate + audit-hook plane.

The frozen roster comes from ``safety.check.ARM_BASELINES`` AT TEST TIME
ONLY (checkout-only import; the ``containment`` package itself never
imports ``safety.check`` -- ``run_matrix`` takes the roster explicitly).
POSIX-only hostile classes skip on win32 with the reason recorded, and
the matrix summary labels win32 runs ``partial``.
"""

from __future__ import annotations

import contextlib
from datetime import datetime
import json
import os
from pathlib import Path
import sys

import pytest

import attempt_ledger.ledger as attempt_ledger
from containment.enforcer import (
    POLICED_EVENTS,
    raise_for_event,
)
from containment.fixtures import BUILDERS
from containment.harness import (
    POSIX_ONLY_HOSTILE,
    RosterEntry,
    _drain_denials,
    _hostile_path,
    run_canary_case,
    run_case,
    run_matrix,
    snapshot_scratch,
)
from containment.profile import OperatorProfile
from containment.mcp_guard import guarded_call, invoke_arguments

REPO_ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 13, 12, 0, 0)
CANARY = "CONTAINMENT-CANARY-SUITE-01"


def _baseline_roster() -> tuple[RosterEntry, ...]:
    """The frozen roster, read from safety.check at test time only."""
    entries = []
    for arm_id in sorted(safety_check.ARM_BASELINES):
        baseline = safety_check.ARM_BASELINES[arm_id]
        entries.append(RosterEntry(arm_id, "list_tools", None))
        for action in baseline["actions"]:
            entries.append(RosterEntry(arm_id, action, baseline["path_argument"]))
    return tuple(entries)


import safety.check as safety_check  # noqa: E402  (test-time-only import)


@pytest.fixture(scope="session")
def containment_env(tmp_path_factory):
    """Approved root, scratch root, ledger path, and the operator profile."""
    root = tmp_path_factory.mktemp("containment")
    approved = root / "approved"
    scratch = root / "scratch"
    approved.mkdir()
    scratch.mkdir()
    profile = OperatorProfile(
        approved_root=str(approved),
        scratch_root=str(scratch),
        canaries=(CANARY,),
    )
    return {
        "root": root,
        "profile": profile,
        "ledger": root / "containment-attempts.jsonl",
    }


@pytest.fixture(scope="session")
def matrix(containment_env):
    """The full roster matrix, run once per session."""
    return run_matrix(
        containment_env["profile"],
        _baseline_roster(),
        containment_env["root"] / "approved" / "fixtures",
        recorded_at=NOW,
        ledger_path=containment_env["ledger"],
    )


# --- Roster shape (test-time literals must match the baseline) -----------


def test_roster_matches_baseline_literals() -> None:
    roster = _baseline_roster()
    data = [entry for entry in roster if entry.path_argument is not None]
    assert len({entry.arm_id for entry in roster}) == len(safety_check.ARM_BASELINES)
    assert len(data) == 38  # the frozen 38 data actions
    assert len(roster) == 38 + len(safety_check.ARM_BASELINES)  # +1 smoke per arm
    for entry in data:
        baseline = safety_check.ARM_BASELINES[entry.arm_id]
        assert entry.action in baseline["actions"]
        assert entry.path_argument == baseline["path_argument"]
    for arm_id in safety_check.ARM_BASELINES:
        assert arm_id in BUILDERS  # every roster arm has a fixture builder


# --- Pure policy core (no child processes) --------------------------------


def _profile_dict(tmp_path: Path) -> dict:
    return {
        "approved_root": str(tmp_path / "approved"),
        "scratch_root": str(tmp_path / "scratch"),
        "allow_python_runtime": True,
    }


def test_enforcer_denies_write_open_even_in_scratch(tmp_path: Path) -> None:
    profile = _profile_dict(tmp_path)
    scratch = str(tmp_path / "scratch" / "w.txt")
    with pytest.raises(PermissionError, match="containment-denied"):
        raise_for_event("open", (scratch, "w", 0), profile)


def test_enforcer_denies_out_of_root_read_but_allows_in_root(tmp_path: Path) -> None:
    profile = _profile_dict(tmp_path)
    outside = str(tmp_path / "elsewhere" / "leak.json")
    with pytest.raises(PermissionError):
        raise_for_event("open", (outside, "r", 0), profile)
    inside = str(tmp_path / "approved" / "feed.json")
    assert raise_for_event("open", (inside, "r", 0), profile) is None


def test_enforcer_denies_egress_and_subprocess_events(tmp_path: Path) -> None:
    profile = _profile_dict(tmp_path)
    for event, args in (
        ("socket.getaddrinfo", ("localhost", 1, 0, 0, 0)),
        ("socket.connect", (object(), ("127.0.0.1", 1))),
        ("socket.bind", (object(), ("127.0.0.1", 1))),
        ("subprocess.Popen", (sys.executable, ["-c", "pass"], None)),
        ("os.system", ("echo hi",)),
        ("os.fork", ()),
    ):
        with pytest.raises(PermissionError):
            raise_for_event(event, args, profile)


def test_enforcer_mutation_verbs_confined_to_scratch(tmp_path: Path) -> None:
    profile = _profile_dict(tmp_path)
    approved_file = str(tmp_path / "approved" / "rename-into-root.json")
    scratch_file = str(tmp_path / "scratch" / "moved.json")
    outside = str(tmp_path / "elsewhere" / "x.json")
    # rename INTO the approved root: denied (mutation verbs live in scratch)
    with pytest.raises(PermissionError, match="mutation-outside-scratch"):
        raise_for_event("os.rename", (outside, approved_file, -1, -1), profile)
    # wholly inside scratch: allowed
    assert raise_for_event(
        "os.rename", (str(tmp_path / "scratch" / "a.json"), scratch_file, -1, -1),
        profile,
    ) is None
    for event, args in (
        ("os.remove", (approved_file, -1)),
        ("os.chmod", (approved_file, 0o644, -1)),
        ("shutil.copyfile", (outside, scratch_file)),
        ("shutil.rmtree", (approved_file,)),
        ("os.symlink", (outside, scratch_file, -1)),
    ):
        with pytest.raises(PermissionError):
            raise_for_event(event, args, profile)


def test_enforcer_fails_closed_on_dir_fd(tmp_path: Path) -> None:
    profile = _profile_dict(tmp_path)
    scratch_file = str(tmp_path / "scratch" / "x.json")
    with pytest.raises(PermissionError, match="dir-fd"):
        raise_for_event("os.remove", (scratch_file, 3), profile)


def test_enforcer_devnull_and_runtime_reads_allowed(tmp_path: Path) -> None:
    profile = _profile_dict(tmp_path)
    assert raise_for_event("open", (os.devnull, "r", 0), profile) is None
    stdlib = os.path.join(sys.prefix, "README.txt")
    assert raise_for_event("open", (stdlib, "r", 0), profile) is None


def test_policied_event_surface_is_fail_closed_set() -> None:
    assert {
        "open", "socket.connect", "socket.bind", "socket.getaddrinfo",
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.fork",
        "os.rename", "os.replace", "os.link", "os.symlink", "os.remove",
        "os.rmdir", "os.chmod", "os.chown", "shutil.copyfile", "shutil.rmtree",
    } <= POLICED_EVENTS


# --- In-root matrix: positive-or-refusal with ZERO denials ----------------


def test_inroot_data_actions_have_zero_denials(matrix) -> None:
    """(a) In-root per action: positive-or-refusal, zero enforcer denials.
    The only case allowed to carry denial records is the enforced canary
    (its probes are denied by design)."""
    roster = _baseline_roster()
    for entry in roster:
        if entry.path_argument is None:
            continue
        outcome = matrix["per_arm"][entry.arm_id][f"{entry.action}:inroot"]
        assert outcome in ("positive", "refusal"), (
            entry.arm_id, entry.action, outcome)
    assert matrix["counts"].get("child-denials", 0) == 0
    assert matrix["cases_with_denials"] == ["containment:canary:enforced"]


def test_list_tools_smoke_zero_denials(matrix) -> None:
    """(a) +1 discovery smoke per arm: zero denials, positive (discovery
    adds no path signal -- there is no input path to acquire or deny --
    which is exactly why it is a smoke, not data evidence)."""
    for arm_id in safety_check.ARM_BASELINES:
        outcome = matrix["per_arm"][arm_id]["list_tools:list-tools"]
        assert outcome in ("positive", "refusal"), (arm_id, outcome)


def test_no_canary_leak_and_no_failures(matrix) -> None:
    assert matrix["failures"] == []
    assert CANARY not in json.dumps(matrix["denials"])
    assert not any(case.startswith("canary-leak") for case in matrix["counts"])


# --- Canary children: enforcement vs control ------------------------------


def test_canary_enforced_child_holds_all_probes(containment_env) -> None:
    enforced = run_canary_case(containment_env["profile"], enforced=True)
    assert enforced.outcome == "held"
    assert enforced.exit_code == 0
    attempts = {row["name"]: row["outcome"] for row in enforced.detail["attempts"]}
    assert set(attempts) == {"socket", "subprocess", "write-open", "symlink"}
    assert set(attempts.values()) == {"PermissionError"}


def test_control_child_proves_denials_come_from_enforcer(containment_env) -> None:
    """(b) Same canary code, NO hook: probes must not raise
    PermissionError, and the process-creation probe must actually
    succeed -- otherwise 'denied' would prove nothing about the enforcer."""
    control = run_canary_case(containment_env["profile"], enforced=False)
    assert control.outcome == "control-ok"
    attempts = {row["name"]: row["outcome"] for row in control.detail["attempts"]}
    assert attempts["subprocess"] == "ok"
    assert "PermissionError" not in set(attempts.values())
    assert set(attempts) >= {"socket", "subprocess", "write-open", "symlink"}


# --- Hostile inputs: blocked before dispatch with typed reasons -----------


@pytest.mark.parametrize("hostile,reason", [
    ("traversal", "traversal-refused"),
    ("absolute-out-of-root", "root-escape"),
])
def test_hostile_inputs_blocked_before_dispatch(
    containment_env, matrix, hostile, reason
) -> None:
    """(c) Hostile per arm: typed refusal, no child spawned, ledger row."""
    outcome = matrix["per_arm"]["ad-pathfinder"][
        f"list_datasources:hostile-{hostile}"]
    assert outcome == "blocked"
    profile = containment_env["profile"]
    payload = {
        "export": _hostile_path(profile, hostile),
        "limit": 5,
    }
    case = run_case(
        profile, arm_id="ad-pathfinder", action="list_datasources",
        payload=payload, hostile=hostile, variant=f"hostile-{hostile}-direct",
    )
    assert case.outcome == "blocked"
    assert case.reason == reason
    assert case.detail["path"] == _hostile_path(profile, hostile)


@pytest.mark.skipif(os.name == "nt", reason="symlink fixtures need POSIX privileges")
def test_hostile_symlink_escape_blocked(containment_env) -> None:
    profile = containment_env["profile"]
    approved = Path(profile.approved_root)
    target = Path(profile.scratch_root) / "outside-feed.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps([{"canary": CANARY}]), encoding="utf-8")
    link = approved / "link.json"
    if link.exists() or link.is_symlink():
        link.unlink()
    os.symlink(target, link)
    case = run_case(
        profile, arm_id="vulnify", action="list_vulns",
        payload={"feed": str(link), "limit": 5},
        hostile="symlink-escape", variant="hostile-symlink-escape",
    )
    assert case.outcome == "blocked"
    assert case.reason == "symlink-refused"


@pytest.mark.skipif(os.name == "nt", reason="mkfifo is POSIX-only")
def test_hostile_device_file_blocked(containment_env) -> None:
    profile = containment_env["profile"]
    fifo = Path(profile.approved_root) / "device.json"
    if fifo.exists():
        fifo.unlink()
    os.mkfifo(fifo)
    case = run_case(
        profile, arm_id="vulnify", action="list_vulns",
        payload={"feed": str(fifo), "limit": 5},
        hostile="device-file", variant="hostile-device-file",
    )
    assert case.outcome == "blocked"
    assert case.reason == "not-regular"


def test_win32_matrix_labels_partial_and_skips_posix_only(matrix) -> None:
    if os.name != "nt":
        assert matrix["platform"]["label"] == "full"
        return
    assert matrix["platform"]["label"] == "partial"
    skipped = {row["case"]: row["reason"] for row in matrix["skipped"]}
    posix_skips = [case for case in skipped
                   if any(hostile in case for hostile in POSIX_ONLY_HOSTILE)]
    assert len(posix_skips) == len(POSIX_ONLY_HOSTILE)
    assert all("posix-only" in skipped[case] for case in posix_skips)


# --- Interruption, cleanup, custody, determinism --------------------------


def test_stop_case_mid_run_yields_interruption_row(containment_env, matrix) -> None:
    """(g) Parent stop mid-run: interruption outcome, kill exit code, and
    a ledger row in the interruption class."""
    assert matrix["per_arm"]["ad-pathfinder"][
        "list_datasources:interrupt"] == "interruption"
    rows = _load_rows(containment_env["ledger"])
    interruption = [row for row in rows if row["attempt_class"] == "interruption"]
    assert interruption, "interruption case must be ledgered"
    assert all(row["lane"] == "operator-rehearsal" for row in rows)
    assert all(row["subject"].startswith("containment:") for row in rows)


def test_cleanup_watch_scratch_stays_byte_clean(containment_env, matrix) -> None:
    assert matrix["per_arm"]["ad-pathfinder"][
        "list_datasources:cleanup"] == "cleanup-ok"
    scratch = Path(containment_env["profile"].scratch_root)
    before = snapshot_scratch(scratch)
    case = run_case(
        containment_env["profile"], arm_id="vulnify", action="list_vulns",
        payload={"feed": str(Path(containment_env["profile"].approved_root)
                             / "vulnify" / "feed.json"), "limit": 5},
        mode="cleanup-watch", variant="cleanup",
    )
    assert case.outcome == "cleanup-ok"
    assert snapshot_scratch(scratch) == before


def _load_rows(ledger_path: Path) -> list[dict]:
    return [json.loads(line) for line in
            ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_ledger_rows_verify_and_carry_details(containment_env, matrix) -> None:
    """(g) Acquisition records retained per case: every ledger row's
    detail digest resolves to an outside detail document."""
    rows = _load_rows(containment_env["ledger"])
    result = attempt_ledger.verify_ledger(rows)
    assert result.ok, result.reasons
    assert len(rows) == matrix["cases"]
    details_dir = containment_env["ledger"].parent / (
        containment_env["ledger"].stem + "-details")
    import hashlib

    for row in rows:
        digest = row["detail_digest"].removeprefix("sha256:")
        detail_path = details_dir / f"{row['attempt_id']}.json"
        assert detail_path.is_file(), row["attempt_id"]
        data = detail_path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest
        detail = json.loads(data)
        # The outside detail document explains the row: its ledger class
        # and outcome match the chained row exactly.
        assert detail["ledger_class"] == row["attempt_class"]
        assert detail["ledger_outcome"] == row.get("outcome")


def test_rerun_determinism_and_ledger_retry_identity(containment_env) -> None:
    """(g) Rerun determinism: identical outcomes on the second run; the
    ledger accepts the rerun as legitimate retries (same identity triple)
    and still verifies; scratch ends byte-identical (reset property)."""
    profile = containment_env["profile"]
    scratch = Path(profile.scratch_root)
    before = snapshot_scratch(scratch)
    mini_roster = (
        RosterEntry("vulnify", "list_vulns", "feed"),
        RosterEntry("vulnify", "lookup", "feed"),
    )
    ledger = containment_env["root"] / "rerun-attempts.jsonl"
    fixtures = Path(profile.approved_root) / "rerun-fixtures"
    first = run_matrix(profile, mini_roster, fixtures,
                       recorded_at=NOW, ledger_path=ledger, include_canaries=False,
                       interrupt_first=False, cleanup_first=False)
    second = run_matrix(profile, mini_roster, fixtures,
                        recorded_at=NOW, ledger_path=ledger, include_canaries=False,
                        interrupt_first=False, cleanup_first=False)
    keys = lambda summary: [  # noqa: E731
        (arm, key, outcome)
        for arm, actions in summary["per_arm"].items()
        for key, outcome in actions.items()
    ]
    assert keys(first) == keys(second)
    assert first["failures"] == [] and second["failures"] == []
    assert first["cases"] == second["cases"]
    rows = _load_rows(ledger)
    # Each mini-run appends its own rows (in-root cases plus the hostile
    # classes applied to the first data arm); the chain stays verifiable.
    assert len(rows) == 2 * first["cases"]
    assert attempt_ledger.verify_ledger(rows).ok
    assert snapshot_scratch(scratch) == before


# --- MCP guard: real stdio round trips ------------------------------------


def test_mcp_guard_in_root_read_succeeds(containment_env, matrix) -> None:
    """(d) Real stdio round trip: in-root feed -> success envelope,
    zero denials."""
    profile = containment_env["profile"]
    feed = Path(profile.approved_root) / "vulnify" / "feed.json"
    result = guarded_call(
        profile, tool="invoke",
        arguments=invoke_arguments(
            entry_id="vulnify", action="lookup",
            args={"feed": str(feed), "cve_id": "CVE-2024-0001"}),
    )
    assert result.initialize["result"]["protocolVersion"]
    payload = result.response["result"]
    assert payload["isError"] is False
    assert payload["structuredContent"]["status"] == "complete"
    assert result.denials == ()


def test_mcp_guard_out_of_root_read_denied_by_enforcer(
    containment_env, matrix,
) -> None:
    """(d) Traversal feed to a JSON file outside the root: error envelope
    PLUS the pipe denial record; the leak canary never surfaces. The file
    sits outside BOTH the approved root and scratch (scratch is read-
    admitted by the profile, so it would not exercise the denial)."""
    profile = containment_env["profile"]
    outside = containment_env["root"] / "guard-outside"
    outside.mkdir(parents=True, exist_ok=True)
    (outside / "leak-feed.json").write_text(
        json.dumps([{"cve_id": "CVE-9999-0001", "note": CANARY}]), encoding="utf-8")
    result = guarded_call(
        profile, tool="invoke",
        arguments=invoke_arguments(
            entry_id="vulnify", action="lookup",
            args={"feed": str(outside / "leak-feed.json"),
                  "cve_id": "CVE-9999-0001"}),
    )
    payload = result.response["result"]
    assert payload["isError"] is True
    assert result.denials, "the enforcer must record the denied open"
    denial = result.denials[0]
    assert denial["event"] == "open"
    assert denial["mode"] == "r"
    assert "leak-feed.json" in str(denial.get("path", ""))
    assert CANARY not in json.dumps(payload)


# --- run_range surface under the guard (Mode B) ---------------------------


def test_range_under_guard_zero_write_denials_outside_scratch(
    containment_env,
) -> None:
    """(e) `python -m extension.range` with no path args under the guard:
    completes or degrades, and never write-denies outside scratch."""
    import subprocess

    profile = containment_env["profile"]
    env = os.environ.copy()
    env["PATH"] = str(Path(sys.executable).parent)
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["CONTAINMENT_PROFILE_JSON"] = profile.to_json()
    read_fd, write_fd = os.pipe()
    kwargs: dict = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, cwd=str(REPO_ROOT), env=env)
    if os.name == "nt":
        import msvcrt

        os.set_inheritable(write_fd, True)
        env["CONTAINMENT_DENIAL_HANDLE"] = str(
            int(msvcrt.get_osfhandle(write_fd)))
        kwargs["close_fds"] = False
    else:
        env["CONTAINMENT_DENIAL_FD"] = str(write_fd)
        kwargs["pass_fds"] = (write_fd,)
    proc = subprocess.Popen(
        [sys.executable, "-m", "containment.worker"], **kwargs)
    try:
        proc.stdin.write((json.dumps({"kind": "range-cli"}) + "\n").encode())
        proc.stdin.flush()
    finally:
        with contextlib.suppress(OSError):
            proc.stdin.close()
        with contextlib.suppress(OSError):
            os.close(write_fd)
    # communicate (not wait): stdout is a pipe and the range envelope can
    # exceed the pipe buffer -- wait-first deadlocks a chatty child.
    stdout_bytes, _ = proc.communicate(timeout=300)
    denials = _drain_denials(read_fd)
    assert proc.returncode == 0
    scratch_norm = os.path.normcase(os.path.normpath(profile.scratch_root))
    write_denials_outside_scratch = [
        row for row in denials
        if row.get("event") == "open"
        and row.get("mode") and any(ch in str(row["mode"]) for ch in "wax+")
        and not str(row.get("path", "")).startswith(scratch_norm)
    ]
    assert write_denials_outside_scratch == []
    # The worker's own result line carries the range CLI exit code:
    # complete (0) or degraded (1) -- never a crash outside the envelope.
    marker = [line for line in stdout_bytes.decode(
        "utf-8", "replace").splitlines()
        if line.startswith("CONTAINMENT-RESULT ")]
    assert marker, "worker must emit a result line"
    exit_code = json.loads(marker[-1].removeprefix("CONTAINMENT-RESULT "))["exit_code"]
    assert exit_code in (0, 1)


# --- CLI surface -----------------------------------------------------------


def test_cli_summary_labels_partial_and_exits_zero(containment_env, tmp_path) -> None:
    """`python -m containment` on a mini roster: JSON summary, win32
    `partial` label, exit 0 only with zero failures."""
    import subprocess

    roster_path = tmp_path / "roster.json"
    roster_path.write_text(json.dumps([
        {"arm_id": "vulnify", "action": "list_tools", "path_argument": None},
        {"arm_id": "vulnify", "action": "lookup", "path_argument": "feed"},
    ]), encoding="utf-8")
    root = containment_env["root"]
    import subprocess

    env = os.environ.copy()
    env["PATH"] = str(Path(sys.executable).parent)
    proc = subprocess.run(
        [sys.executable, "-m", "containment",
         "--approved-root", str(root / "cli-approved"),
         "--scratch-root", str(root / "cli-scratch"),
         "--fixtures-root", str(root / "cli-approved" / "fixtures"),
         "--roster-json", str(roster_path),
         "--recorded-at", NOW.isoformat()],
        cwd=str(REPO_ROOT), env=env, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    summary = json.loads(proc.stdout)
    assert summary["schema"] == "specaudit.ctf.containment-matrix.v1"
    expected_label = "partial" if os.name == "nt" else "full"
    assert summary["platform"]["label"] == expected_label
    assert summary["failures"] == []
    assert summary["per_arm"]["vulnify"]["lookup:inroot"] in ("positive", "refusal")
    legal = {"positive", "refusal", "cleanup-ok", "interruption",
             "held", "control-ok", "blocked"}
    for entry in summary["per_arm"]["vulnify"].values():
        assert entry in legal


def test_enforcer_denies_checkout_instructor_and_docs_paths(
    tmp_path: Path,
) -> None:
    """The narrowed runtime allowlist admits only the package directories
    the guarded jobs import: instructor-held challenge material and
    documentation elsewhere in the checkout are denied reads even though
    they live inside the repository tree."""
    profile = _profile_dict(tmp_path)
    repo_root = Path(__file__).resolve().parents[1]
    for denied_path in (
        repo_root / "challenges" / "lab-review-01-threat-model" / "instructor" / "KEY.md",
        repo_root / "docs" / "governance" / "source-verification-2026-10-13.md",
    ):
        assert denied_path.is_file(), denied_path
        with pytest.raises(PermissionError):
            raise_for_event("open", (str(denied_path), "r", 0), profile)
    # The package roots the guarded jobs import stay readable.
    readable = repo_root / "extension" / "contract.py"
    assert raise_for_event("open", (str(readable), "r", 0), profile) is None
