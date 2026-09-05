"""Stdin-preference class-sweep regression tests (2026-09-05).

Defect class: subprocess.run(argv, capture_output=True) without stdin=
lets the child inherit the parent's stdin. When the parent runs under
CI or a pipe, the child sees a non-tty pipe, and upstreams that parse
input from stdin in that state can silently ignore the argv target
(commix >= 4 did exactly that — PR #43). Every spawn in the extension
package now controls stdin explicitly: stdin=DEVNULL for argv-driven
tools, input= for the three deliberate stdin feeders (zgrab2's host
channel, page-fetch's URL line, the MCP stdio transport).

Two defense layers are pinned here:
- an AST invariant (every subprocess spawn in extension/ sets stdin=
  or input=), so future arms cannot silently regress; and
- per-arm behavioral tests: a fake echo binary records the stdin the
  child actually received; each fixed arm must hand the child an EMPTY
  stdin while argv still carries the target.
"""

from __future__ import annotations

import ast
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from tests.test_arm_batch4 import _fake_binary
from extension.contract import ArmSpec

REPO_ROOT = Path(__file__).resolve().parent.parent
EXTENSION_ROOT = REPO_ROOT / "extension"

ECHO_ARGV_AND_STDIN = (
    "import json, sys\n"
    "print(json.dumps({'argv': sys.argv[1:], 'stdin': sys.stdin.read()}))\n"
)

# Every subprocess.* spawning API the package is allowed to use; the
# invariant demands an explicit stdin= or input= keyword on each call.
_SPAWN_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}


def _spawn_calls(tree: ast.AST) -> list[tuple[ast.Call, str]]:
    """Every spawn call in a module: (call, label).

    Matches subprocess.<func>(...) attribute calls AND bare <func>(...)
    calls where <func> was imported from subprocess (the
    `from subprocess import run` bypass).
    """
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
            imported_names.update(
                alias.asname or alias.name
                for alias in node.names
                if (alias.asname or alias.name) in _SPAWN_FUNCS
            )
    calls: list[tuple[ast.Call, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _SPAWN_FUNCS
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
        ):
            calls.append((node, f"subprocess.{func.attr}"))
        elif isinstance(func, ast.Name) and func.id in imported_names:
            calls.append((node, f"subprocess.{func.id} (imported)"))
    return calls


def test_every_subprocess_spawn_controls_stdin() -> None:
    checked = 0
    offenders: list[str] = []
    for path in sorted(EXTENSION_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for call, label in _spawn_calls(tree):
            checked += 1
            names = [kw.arg for kw in call.keywords if kw.arg is not None]
            if "stdin" not in names and "input" not in names:
                offenders.append(f"{path}:{call.lineno} {label}")
    assert checked >= 20, (
        f"spawn-site walk found only {checked} calls — the invariant "
        "is broken"
    )
    assert not offenders, (
        "subprocess spawns without explicit stdin control (inherited "
        "stdin is the commix-class silent-no-scan vector): "
        + ", ".join(offenders)
    )


def _spec(entry_id: str) -> ArmSpec:
    return ArmSpec(
        id=entry_id,
        protocols=("cli",),
        curated=True,
        notes="Fixture arm for stdin hygiene.",
        tier="research",
    )


def _echoed(result) -> dict:
    assert result.ok is True, getattr(result, "error", None)
    output = result.output
    if isinstance(output, dict) and "output" in output:
        output = output["output"]
    if isinstance(output, str):
        output = json.loads(output)
    return output


def _stdin_and_argv(result) -> tuple[str, list[str]]:
    echoed = _echoed(result)
    return echoed["stdin"], echoed["argv"]


# --- fixed-argv network arms ---------------------------------------------


def test_wapiti_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.wapiti.arm import WapitiArm
    from extension.arms.wapiti.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "wapiti", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    stdin_text, argv = _stdin_and_argv(
        WapitiArm().invoke(
            _spec("wapiti"), "scan", {"url": "http://10.10.0.1/app.php?id=1"}
        )
    )
    assert stdin_text == ""
    assert "-u" in argv and "http://10.10.0.1/app.php?id=1" in argv


def test_commix_fix_held_ignore_stdin_and_devnull(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.commix.arm import CommixArm
    from extension.arms.commix.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "commix", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    stdin_text, argv = _stdin_and_argv(
        CommixArm().invoke(
            _spec("commix"), "scan", {"url": "http://10.10.0.1/f?id=1"}
        )
    )
    assert stdin_text == ""
    assert "--ignore-stdin" in argv
    assert "-u" in argv and "http://10.10.0.1/f?id=1" in argv


def test_nmap_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.nmap.arm import NmapArm
    from extension.arms.nmap.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "nmap", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    stdin_text, argv = _stdin_and_argv(
        NmapArm().invoke(
            _spec("nmap"), "scan", {"target": "10.10.0.5", "ports": [22]}
        )
    )
    assert stdin_text == ""
    assert "10.10.0.5" in argv


def test_routersploit_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.routersploit.arm import RoutersploitArm
    from extension.arms.routersploit.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "routersploit", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    stdin_text, argv = _stdin_and_argv(
        RoutersploitArm().invoke(
            _spec("routersploit"),
            "run",
            {
                "module": "scanners/autopwn",
                "target": "10.10.0.1",
                "port": 80,
            },
        )
    )
    assert stdin_text == ""
    assert "target 10.10.0.1" in argv


def test_osmedeus_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Real finding: osmedeus pkg/cli/run.go opportunistically reads
    # piped stdin ("Read targets from stdin if data is piped") and
    # merges it into the -t target list — an inherited pipe with data
    # would scan uninvited hosts. DEVNULL keeps targeting argv-only.
    from extension.arms.osmedeus.arm import OsmedeusArm
    from extension.arms.osmedeus.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "osmedeus", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "lab.internal")
    stdin_text, argv = _stdin_and_argv(
        OsmedeusArm().invoke(
            _spec("osmedeus"), "scan", {"target": "http://lab.internal/"}
        )
    )
    assert stdin_text == ""
    assert "-t" in argv and "http://lab.internal/" in argv


def test_page_fetch_feeds_url_on_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.pagefetch.arm import PageFetchArm
    from extension.arms.pagefetch.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "page-fetch", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    stdin_text, argv = _stdin_and_argv(
        PageFetchArm().invoke(
            _spec("page-fetch"), "fetch", {"url": "http://10.10.0.1/"}
        )
    )
    # Upstream (detectify/page-fetch) reads URLs from stdin only and
    # silently ignores positional argv — the URL is the single stdin
    # line and argv carries no target at all.
    assert stdin_text == "http://10.10.0.1/\n"
    assert argv == []


def test_zdns_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.zdns.arm import ZdnsArm
    from extension.arms.zdns.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "zdns", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "example.com")
    stdin_text, argv = _stdin_and_argv(
        ZdnsArm().invoke(
            _spec("zdns"),
            "lookup",
            {"domain": "example.com", "record_type": "A"},
        )
    )
    assert stdin_text == ""
    assert argv == ["A", "example.com"]


def test_sniper_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Sn1per's bash launcher reads stdin only for interactive y/N
    # prompts (update check, workspace delete); EOF-on-DEVNULL answers
    # them with the safe default instead of an ambient pipe's bytes.
    from extension.arms.sniper.arm import SniperArm
    from extension.arms.sniper.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "sniper", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    stdin_text, argv = _stdin_and_argv(
        SniperArm().invoke(
            _spec("sniper"),
            "scan",
            {"target": "10.10.0.1", "mode": "fullportonly"},
        )
    )
    assert stdin_text == ""
    assert argv == ["-t", "10.10.0.1", "-m", "fullportonly"]


# --- listing / read arms --------------------------------------------------


def test_garak_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.garak.arm import GarakArm
    from extension.arms.garak.policy import ENV_BIN, ENV_TARGET

    binary = _fake_binary(tmp_path, "garak", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_TARGET, "local")
    stdin_text, argv = _stdin_and_argv(
        GarakArm().invoke(_spec("garak"), "list_probes", {})
    )
    assert stdin_text == ""
    assert "--list_probes" in argv


def test_mitreattack_child_gets_empty_stdin_and_subcommand_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Sweep finding (argv shape, verified against upstream v6.2.0
    # attackToExcel.py): attack-to-excel is a Typer app whose file
    # input is the from-stix --stix-file option; a bare positional
    # bundle path is an unrecognized command upstream.
    from extension.arms.mitreattack.arm import MitreattackArm
    from extension.arms.mitreattack.policy import ENV_BIN

    bundle = tmp_path / "enterprise.bundle.json"
    bundle.write_text('{"type": "bundle", "id": "x"}', encoding="utf-8")
    binary = _fake_binary(tmp_path, "attack-to-excel", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    stdin_text, argv = _stdin_and_argv(
        MitreattackArm().invoke(
            _spec("mitreattack-python"), "to_excel", {"input": str(bundle)}
        )
    )
    assert stdin_text == ""
    assert argv == ["from-stix", "--stix-file", str(bundle)]


def test_checkov_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.checkov.arm import CheckovArm
    from extension.arms.checkov.policy import ENV_BIN, ENV_SCAN_ROOT

    binary = _fake_binary(tmp_path, "checkov", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.delenv(ENV_SCAN_ROOT, raising=False)
    stdin_text, argv = _stdin_and_argv(
        CheckovArm().invoke(_spec("checkov"), "scan", {})
    )
    assert stdin_text == ""
    assert "scan" in argv and "-d" in argv


def test_pyrit_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.pyrit.arm import PyritArm
    from extension.arms.pyrit.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "pyrit_scan", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    stdin_text, argv = _stdin_and_argv(
        PyritArm().invoke(
            _spec("pyrit"),
            "scan",
            {"scenario": "airt.cyber", "target": "10.10.0.1"},
        )
    )
    assert stdin_text == ""
    assert argv == ["airt.cyber", "--target", "10.10.0.1"]


# --- dispatch arms ---------------------------------------------------------


def test_vuls_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # vuls reads stdin only behind an explicit --pipe flag (subcmds/
    # scan.go); DEVNULL keeps even that door closed to ambient pipes.
    from extension.arms.vuls.arm import VulsArm
    from extension.arms.vuls.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "vuls", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    stdin_text, argv = _stdin_and_argv(
        VulsArm().invoke(_spec("vuls"), "scan", {})
    )
    assert stdin_text == ""
    assert argv == ["scan"]


def test_stratus_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.stratus.arm import StratusArm
    from extension.arms.stratus.policy import ENV_BIN, ENV_DISPATCH_SCOPE

    binary = _fake_binary(tmp_path, "stratus", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "aws-account-lab")
    stdin_text, argv = _stdin_and_argv(
        StratusArm().invoke(
            _spec("stratus-red-team"),
            "detonate",
            {"technique": "aws.exfiltration.s3"},
        )
    )
    assert stdin_text == ""
    assert "aws.exfiltration.s3" in argv


def test_darkmoon_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.darkmoon.arm import DarkMoonArm
    from extension.arms.darkmoon.policy import (
        DISPATCH_ACTIONS,
        ENV_BIN,
        ENV_DISPATCH_SCOPE,
    )

    binary = _fake_binary(tmp_path, "darkmoon", ECHO_ARGV_AND_STDIN)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "10.10.0.0/16")
    action = sorted(DISPATCH_ACTIONS)[0]
    stdin_text, argv = _stdin_and_argv(
        DarkMoonArm().invoke(
            _spec("dark-moon"), action, {"target": "10.10.0.1"}
        )
    )
    assert stdin_text == ""
    assert argv == ["TARGET: 10.10.0.1"]


# --- opaque vendor SAST CLIs (defense-only: no public source) --------------


def _scan_tree(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "scanroot"
    repo = root / "target"
    repo.mkdir(parents=True)
    return root, repo


def test_deepsec_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.deepsec.arm import DeepsecArm
    from extension.arms.deepsec.policy import (
        ENV_BIN,
        ENV_DISPATCH_SCOPE,
        ENV_SCAN_ROOT,
    )

    binary = _fake_binary(tmp_path, "deepsec", ECHO_ARGV_AND_STDIN)
    repo = tmp_path / "repo"
    workspace = repo / ".deepsec"
    workspace.mkdir(parents=True)
    (workspace / "deepsec.config.ts").write_text(
        "export default {}\n", encoding="utf-8"
    )
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_SCAN_ROOT, str(workspace))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "localhost")
    stdin_text, argv = _stdin_and_argv(
        DeepsecArm().invoke(
            _spec("deepsec"), "process", {"project_id": "my-app"}
        )
    )
    assert stdin_text == ""
    assert argv == ["process", "--project-id", "my-app"]


def test_vvah_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.vvah.arm import VvahArm
    from extension.arms.vvah.policy import (
        ENV_BIN,
        ENV_DISPATCH_SCOPE,
        ENV_SCAN_ROOT,
    )

    binary = _fake_binary(tmp_path, "vvaharness", ECHO_ARGV_AND_STDIN)
    root, repo = _scan_tree(tmp_path)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_SCAN_ROOT, str(root))
    monkeypatch.setenv(ENV_DISPATCH_SCOPE, "localhost")
    stdin_text, argv = _stdin_and_argv(
        VvahArm().invoke(_spec("vvah"), "scan", {"repo": str(repo)})
    )
    assert stdin_text == ""
    assert "scan" in argv and "--repo" in argv


def test_aideepsast_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.aideepsast.arm import AiDeepSastArm
    from extension.arms.aideepsast.policy import (
        ENV_BIN,
        ENV_SCAN_ROOT,
        ENV_SEMGREP_CONFIG,
    )

    binary = _fake_binary(tmp_path, "aideepsast", ECHO_ARGV_AND_STDIN)
    root, repo = _scan_tree(tmp_path)
    rules = root / "local-rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_SCAN_ROOT, str(root))
    monkeypatch.setenv(ENV_SEMGREP_CONFIG, str(rules))
    stdin_text, argv = _stdin_and_argv(
        AiDeepSastArm().invoke(_spec("ai-deep-sast"), "scan", {"target": str(repo)})
    )
    assert stdin_text == ""
    assert "--skip-llm" in argv and "--target" in argv


def test_agentwiz_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.arms.agentwiz.arm import AgentWizArm
    from extension.arms.agentwiz.policy import ENV_BIN, ENV_SCAN_ROOT

    binary = _fake_binary(tmp_path, "agent-wiz", ECHO_ARGV_AND_STDIN)
    root = tmp_path / "scanroot"
    root.mkdir()
    graph = root / "graph.json"
    graph.write_text("{}", encoding="utf-8")
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_SCAN_ROOT, str(root))
    stdin_text, argv = _stdin_and_argv(
        AgentWizArm().invoke(
            _spec("agent-wiz"), "visualize", {"input": str(graph)}
        )
    )
    assert stdin_text == ""
    assert argv[0] == "visualize" and "--input" in argv


def test_semgrep_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # semgrep reads stdin only for a literal "-" target
    # (target_manager.write_pipes_to_disk); the fixed argv passes an
    # explicit containment-checked path, and DEVNULL closes the door.
    # The fake must emit a semgrep report shape; the probe rides along
    # inside a finding's evidence (the arm passes the doc through).
    from extension.arms.semgrep.arm import SemgrepArm
    from extension.arms.semgrep.policy import ENV_BIN, ENV_SCAN_ROOT

    body = (
        "import json, sys\n"
        "evidence = {'argv': sys.argv[1:], 'stdin': sys.stdin.read()}\n"
        "print(json.dumps({'results': [{'check_id': 'demo', 'path': 'a.py',"
        " 'evidence': evidence}], 'errors': []}))\n"
    )
    binary = _fake_binary(tmp_path, "semgrep", body)
    monkeypatch.setenv(ENV_BIN, str(binary))
    monkeypatch.setenv(ENV_SCAN_ROOT, str(tmp_path))
    result = SemgrepArm().invoke(
        _spec("semgrep-mcp"), "semgrep_scan", {"config": "rules: []\n"}
    )
    assert result.ok is True, result.error
    evidence = result.output["results"][0]["evidence"]
    assert evidence["stdin"] == ""
    assert "scan" in evidence["argv"] and "--config" in evidence["argv"]


# --- the two deliberate stdin feeders stay explicit ------------------------


def test_zgrab2_still_feeds_host_on_stdin() -> None:
    # The exception is deliberate and already behaviorally pinned in
    # test_arm_batch4 (armed host arrives on stdin, never argv); the
    # AST invariant above is what keeps it honest (input= counts).
    from extension.arms.zgrab2.policy import argv_for

    argv = argv_for("/usr/bin/zgrab2", "http", 443)
    assert argv[0] == "/usr/bin/zgrab2"
    assert "--port" in argv or "http" in argv


def test_cli_transport_child_gets_empty_stdin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from extension.transports.cli import CliTransport

    binary = _fake_binary(tmp_path, "generic-arm", ECHO_ARGV_AND_STDIN)
    transport = CliTransport(commands={"generic-arm": [str(binary)]})
    spec = ArmSpec(
        id="generic-arm",
        protocols=("cli",),
        curated=True,
        notes="synthetic spec for the generic CLI transport",
        tier="research",
    )
    result = transport.invoke(spec, "demoaction", {"k": "v"})
    assert result.ok is True
    echoed = result.output  # the transport decodes stdout JSON already
    assert echoed["stdin"] == ""
    # argv after the binary: the action plus the JSON payload.
    assert echoed["argv"] == ["demoaction", '{"k":"v"}']
