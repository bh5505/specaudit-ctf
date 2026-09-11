"""Regression tests for the ctf_run_checks --export-bin subprocess path.

Uses a minimal synthetic pack plus stub export binaries (no Rust build, no
sleep): success writes the export manifest, a failing child keeps the run
reports and returns an honest failure, and a timing-out child does the same.
CLI-level dependency validation (missing binary, --export-dir without
--export-bin) goes through main().
"""

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _portable_stub_launcher(monkeypatch):
    """Run test scripts with Python on both Windows and POSIX hosts."""
    real_run = subprocess.run

    def launch(cmd, *args, **kwargs):
        if Path(cmd[0]).name in {
            "fake-export-bin", "failing-export-bin", "slow-export-bin",
        }:
            cmd = [sys.executable, *cmd]
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", launch)


CHECK_SQL = """\
SELECT 'k1' AS finding_key, 'stub check' AS title, 1 AS affected_count,
       1 AS exposure_estimate, 'loc' AS record_locator, 'det' AS details,
       ?1 AS run_id, 7 AS risk_score
LIMIT ?2;
"""

SUCCESS_STUB = """\
#!/usr/bin/env python3
import hashlib
import json
import shutil
import sys
from pathlib import Path

args = sys.argv[1:]


def take(flag):
    return args[args.index(flag) + 1]


# The stub parses the child's own contract, mirroring what the real
# `export-tool pack export` consumes: report + sarif in, manifest out.
assert "pack" in args and "export" in args
assert "--require-workpaper" in args
report = Path(take("--report"))
sarif = Path(take("--sarif"))
out = Path(take("--out"))
engagement = take("--engagement-id")
assert report.is_file(), "missing report: %s" % report
assert sarif.is_file(), "missing sarif: %s" % sarif
out.mkdir(parents=True, exist_ok=True)
shutil.copyfile(report, out / "report.json")
shutil.copyfile(sarif, out / "report.sarif")
(out / "workpaper.md").write_text("stub workpaper")
source = json.loads(report.read_text())
artifacts = []
for name in ["report.json", "report.sarif", "workpaper.md"]:
    data = (out / name).read_bytes()
    artifacts.append({"path": name, "bytes": len(data),
                      "sha256": hashlib.sha256(data).hexdigest()})
(out / "export_manifest.json").write_text(json.dumps({
    "pack_id": source["pack_id"],
    "run_id": source["run_id"],
    "engagement_id": engagement,
    "workpaper": {"status": "rendered"},
    "sarif": {"status": "exported"},
    "artifacts": artifacts,
    "report": str(report),
    "sarif_input": str(sarif),
}) + "\\n")
"""

FAIL_STUB = """\
#!/usr/bin/env python3
import sys

sys.stderr.write("stub export: pack failed workpaper validation\\n")
sys.exit(3)
"""


def _load_runner():
    path = Path(__file__).parents[1] / "tools" / "ctf_run_checks.py"
    spec = importlib.util.spec_from_file_location("ctf_run_checks_export", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_pack_and_evidence(root):
    pack = root / "pack"
    (pack / "checks").mkdir(parents=True)
    migrations = pack / "schema" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "001_things.sql").write_text(
        "CREATE TABLE things (\n"
        "  name VARCHAR, run_id VARCHAR, engagement_id VARCHAR,\n"
        "  accept_event_id VARCHAR\n);", encoding="utf-8")
    (pack / "manifest.yaml").write_text(
        "pack_id: stub-pack\nchecks:\n"
        "  - id: T9\n    file: checks/t9.sql\n    severity: low\n",
        encoding="utf-8",
    )
    (pack / "checks" / "t9.sql").write_text(CHECK_SQL, encoding="utf-8")
    evidence = root / "evidence"
    evidence.mkdir()
    (evidence / "things.csv").write_text("name\nwidget\n", encoding="utf-8")
    return pack, evidence


def _make_stub(root, name, body):
    stub = root / name
    stub.write_text(body, encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    assert os.access(stub, os.X_OK)
    return stub


def test_export_success_promotes_manifest_with_loopback_engagement(tmp_path):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    out_dir = tmp_path / "out"
    export_dir = tmp_path / "export"
    stub = _make_stub(tmp_path, "fake-export-bin", SUCCESS_STUB)
    rc = runner.run(str(pack), str(evidence), str(out_dir), "sqlite",
                    100, "run-abc",
                    export_bin=str(stub), export_dir=str(export_dir))
    assert rc == 0
    assert (out_dir / "report.json").is_file()
    assert (out_dir / "report.sarif").is_file()
    manifest = json.loads((export_dir / "export_manifest.json").read_text())
    assert manifest["engagement_id"] == "ctf-loopback:run-abc"
    assert manifest["report"] == str((out_dir / "report.json").resolve())
    assert manifest["sarif_input"] == str((out_dir / "report.sarif").resolve())


def test_export_defaults_to_out_dir_when_no_export_dir(tmp_path):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    out_dir = tmp_path / "out"
    stub = _make_stub(tmp_path, "fake-export-bin", SUCCESS_STUB)
    rc = runner.run(str(pack), str(evidence), str(out_dir), "sqlite",
                    100, "run-abc", export_bin=str(stub))
    assert rc == 0
    assert (out_dir / "export_manifest.json").is_file()
    assert not list(tmp_path.glob(".out.run-reports-*"))


def test_verified_export_reports_retained_inputs_if_cleanup_fails(
        tmp_path, monkeypatch, capsys):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    out = tmp_path / "out"
    stub = _make_stub(tmp_path, "fake-export-bin", SUCCESS_STUB)

    def fail_cleanup(path):
        raise PermissionError("input reports are busy")

    monkeypatch.setattr(runner.shutil, "rmtree", fail_cleanup)
    assert runner.run(pack, evidence, out, "sqlite", 100, "run-abc",
                      export_bin=stub) == 0
    captured = capsys.readouterr()
    assert "(unified run export)" in captured.out
    assert "export is complete" in captured.err
    assert "input reports are busy" in captured.err
    reports_dir, = tmp_path.glob(".out.run-reports-*")
    assert str(reports_dir) in captured.err
    assert (reports_dir / "report.json").read_bytes() == (out / "report.json").read_bytes()
    assert (reports_dir / "report.sarif").read_bytes() == (out / "report.sarif").read_bytes()
    assert (out / "export_manifest.json").is_file()


def test_successful_export_forwards_child_stderr(tmp_path, capsys):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    body = SUCCESS_STUB + '\nimport sys\nprint("export diagnostic", file=sys.stderr)\n'
    stub = _make_stub(tmp_path, "fake-export-bin", body)
    assert runner.run(pack, evidence, tmp_path / "out", "sqlite", 100,
                      "run-abc", export_bin=stub) == 0
    assert "export diagnostic" in capsys.readouterr().err


@pytest.mark.parametrize("damage", ["no-output", "stale-export", "bad-json",
                                     "corrupt-workpaper", "wrong-report",
                                     "symlink-manifest", "symlink-report"])
def test_zero_exit_without_this_runs_verified_artifacts_retains_reports(
        tmp_path, capsys, damage):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    out = tmp_path / "out"
    if damage.startswith("symlink-"):
        probe = tmp_path / "symlink-probe"
        target = tmp_path / "symlink-target"
        target.write_bytes(b"probe")
        try:
            probe.symlink_to(target)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"host cannot create symlinks: {error}")
        probe.unlink()
        target.unlink()
    if damage == "stale-export":
        good = _make_stub(tmp_path, "fake-export-bin", SUCCESS_STUB)
        assert runner.run(pack, evidence, out, "sqlite", 100, "run-A",
                          export_bin=good) == 0
        old = {p.name: p.read_bytes() for p in out.iterdir()}
    if damage in ("no-output", "stale-export"):
        body = "#!/usr/bin/env python3\n"
    elif damage == "bad-json":
        body = SUCCESS_STUB + '\n(out / "export_manifest.json").write_text("{broken")\n'
    elif damage == "corrupt-workpaper":
        body = SUCCESS_STUB + '\n(out / "workpaper.md").write_text("corrupt")\n'
    elif damage.startswith("symlink-"):
        name = "export_manifest.json" if damage == "symlink-manifest" else "report.json"
        # Preserve the exact bytes and digest so only the symlink guard can
        # reject this output; no malformed metadata masks the regression.
        body = SUCCESS_STUB + f'''
artifact = out / {name!r}
original = out.parent / "original-export-artifact"
artifact.rename(original)
artifact.symlink_to(original)
'''
    else:
        # A digest-consistent artifact can still be the wrong source report.
        body = SUCCESS_STUB + '''
data = b'{"pack_id":"stub-pack","run_id":"run-B","findings":[]}'
(out / "report.json").write_bytes(data)
m = json.loads((out / "export_manifest.json").read_text())
for a in m["artifacts"]:
    if a["path"] == "report.json":
        a.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
(out / "export_manifest.json").write_text(json.dumps(m))
'''
    stub = _make_stub(tmp_path, "fake-export-bin", body)
    capsys.readouterr()
    assert runner.run(pack, evidence, out, "sqlite", 100, "run-B",
                      export_bin=stub) == 1
    captured = capsys.readouterr()
    assert "returned success but verification failed" in captured.err
    if damage.startswith("symlink-"):
        assert "regular file" in captured.err
    assert "(unified run export)" not in captured.out
    reports_dir, = tmp_path.glob(".out.run-reports-*")
    assert str(reports_dir) in captured.err
    report = json.loads((reports_dir / "report.json").read_text())
    assert report["run_id"] == "run-B" and len(report["findings"]) == 1
    assert (reports_dir / "report.sarif").is_file()
    if damage == "stale-export":
        assert {p.name: p.read_bytes() for p in out.iterdir()} == old


def test_export_child_failure_keeps_reports_and_fails_honestly(tmp_path):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    out_dir = tmp_path / "out"
    stub = _make_stub(tmp_path, "failing-export-bin", FAIL_STUB)
    rc = runner.run(str(pack), str(evidence), str(out_dir), "sqlite",
                    100, "run-abc", export_bin=str(stub))
    assert rc == 1
    # The run reports remain usable even though the export failed.
    reports_dir, = tmp_path.glob(".out.run-reports-*")
    report = json.loads((reports_dir / "report.json").read_text())
    assert report["run_id"] == "run-abc"
    assert len(report["findings"]) == 1
    assert (reports_dir / "report.sarif").is_file()
    assert not out_dir.exists()


def test_export_child_timeout_keeps_reports_and_fails_honestly(tmp_path,
                                                               monkeypatch):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    out_dir = tmp_path / "out"
    stub = _make_stub(tmp_path, "slow-export-bin", SUCCESS_STUB)

    def _timeout(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 600)

    monkeypatch.setattr(subprocess, "run", _timeout)
    rc = runner.run(str(pack), str(evidence), str(out_dir), "sqlite",
                    100, "run-abc", export_bin=str(stub))
    assert rc == 1
    reports_dir, = tmp_path.glob(".out.run-reports-*")
    assert (reports_dir / "report.json").is_file()
    assert (reports_dir / "report.sarif").is_file()
    assert not out_dir.exists()


def test_main_rejects_missing_export_binary(tmp_path):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    rc = runner.main(["--pack", str(pack), "--evidence-dir", str(evidence),
                      "--out-dir", str(tmp_path / "out"),
                      "--export-bin", str(tmp_path / "no-such-binary")])
    assert rc == 1


@pytest.mark.parametrize("out_name", ["out", "out[1]"])
def test_export_timeout_after_move_aside_reports_recovery_paths(
        tmp_path, monkeypatch, capsys, out_name):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    out = tmp_path / out_name
    out.mkdir()
    (out / "report.json").write_bytes(b"old export")
    backup = tmp_path / (".%s.export-backup-injected" % out_name)
    staging = tmp_path / (".%s.export-staging-injected" % out_name)
    stub = _make_stub(tmp_path, "slow-export-bin", SUCCESS_STUB)

    def interrupted_promotion(cmd, **kwargs):
        out.rename(backup)
        staging.mkdir()
        (staging / "report.json").write_bytes(b"new native export")
        raise subprocess.TimeoutExpired(cmd, 600)

    monkeypatch.setattr(subprocess, "run", interrupted_promotion)
    assert runner.run(pack, evidence, out, "sqlite", 100, "run-B",
                      export_bin=stub) == 1
    message = capsys.readouterr().err
    assert "export destination is absent" in message
    assert str(backup) in message and str(staging) in message
    assert not out.exists()
    assert (backup / "report.json").read_bytes() == b"old export"
    assert (staging / "report.json").read_bytes() == b"new native export"
    reports_dir, = (p for p in tmp_path.iterdir()
                   if p.name.startswith(".%s.run-reports-" % out_name))
    assert str(reports_dir) in message
    assert json.loads((reports_dir / "report.json").read_text())["run_id"] == "run-B"


def test_main_rejects_export_dir_without_export_bin(tmp_path):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    rc = runner.main(["--pack", str(pack), "--evidence-dir", str(evidence),
                      "--out-dir", str(tmp_path / "out"),
                      "--export-dir", str(tmp_path / "export")])
    assert rc == 1


@pytest.mark.parametrize("export_mode", ["failure", "timeout", "reports-only", "separate-export"])
def test_reused_complete_export_survives_failed_or_reports_only_run(
        tmp_path, monkeypatch, export_mode):
    runner = _load_runner()
    pack, evidence = _make_pack_and_evidence(tmp_path)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    old = {
        "report.json": b'{"run_id":"run-A"}',
        "report.sarif": b"old SARIF",
        "workpaper.md": b"old workpaper",
        "export_manifest.json": b"old manifest",
    }
    for name, data in old.items():
        (out_dir / name).write_bytes(data)
    stub = _make_stub(tmp_path, "failing-export-bin", FAIL_STUB)
    kwargs = {}
    if export_mode != "reports-only":
        kwargs["export_bin"] = str(stub)
    if export_mode == "separate-export":
        kwargs["export_dir"] = str(tmp_path / "different-export")
    if export_mode == "timeout":
        def timeout(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 600)
        monkeypatch.setattr(subprocess, "run", timeout)
    if export_mode in ("reports-only", "separate-export"):
        with pytest.raises(runner.RunnerError, match="completed export"):
            runner.run(pack, evidence, out_dir, "sqlite", 100, "run-B", **kwargs)
    else:
        assert runner.run(pack, evidence, out_dir, "sqlite", 100, "run-B", **kwargs) == 1
        reports_dir, = tmp_path.glob(".out.run-reports-*")
        assert json.loads((reports_dir / "report.json").read_text())["run_id"] == "run-B"
    assert {p.name: p.read_bytes() for p in out_dir.iterdir()} == old
