"""OS-enforced E1 isolation suite: kernel namespace jail, run outside the
learner process (containment/os_isolation.py + isolate_launcher.sh).

These tests are the EMPIRICAL evidence for the OS layer the audit-hook
plane cannot provide: filesystem bounds (pivot_root + read-only jail root
+ the two granted dirs), a kernel-offline network namespace, rlimits
(declared by the profile, applied in-jail), independent supervisor stop,
and answer-key separation by mount construction. Where the host cannot
build the jail the jail tests SKIP with the honest reason; the typed
unsupported-host refusal test runs everywhere (including Windows, where
the module must refuse cleanly). On a Linux host where the kernel denies
unshare, the jail tests DO NOT run silently: the module-level probe
records the refusal and the skip reason says so -- the suite gate
(WSL) is expected to RUN these, not skip them.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time

import pytest

from containment import os_isolation
from containment.os_isolation import (
    IsolationError,
    IsolationProfile,
    IsolationProfileError,
    stop_all,
)

INSTRUCTOR_CANARY = "INSTRUCTOR-CANARY-OSISO-01"
PROBE = os_isolation.probe_host_support()
NAMESPACES = PROBE.supported
_requires_namespaces = pytest.mark.skipif(
    not NAMESPACES,
    reason=f"os isolation requires Linux namespaces (host verdict: {PROBE.detail})")
PY3 = "/usr/bin/python3"


def _fields(text: str) -> dict[str, str]:
    """First word -> rest of line, for the jailed one-liners' reports."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if line.strip():
            key, _, rest = line.partition(" ")
            out[key] = rest
    return out


def _run_one(profile: IsolationProfile, code: str, **kwargs):
    """Run one jailed python one-liner; a completed nonzero exit comes
    back as the typed IsolationError (its stdout/stderr still carry the
    evidence), so tests can assert on the evidence either way."""
    try:
        return os_isolation.run_isolated(profile, [PY3, "-c", code], **kwargs)
    except IsolationError as exc:
        return exc


def _assert_ran(outcome, context: str) -> os_isolation.IsolationResult:
    if isinstance(outcome, IsolationError):
        pytest.fail(
            f"{context}: jail/target failed "
            f"(reason={outcome.reason}, exit={outcome.exit_code})\n"
            f"stdout={outcome.stdout!r}\nstderr={outcome.stderr!r}")
    return outcome


@pytest.fixture(scope="module")
def jail(tmp_path_factory):
    """Shared jail layout: approved inputs, writable scratch, and the
    instructor keys deliberately NEXT TO (not inside) the approved inputs.
    The profile mounts the two granted dirs ONLY, so the keys are absent
    from the jail by construction."""
    root = tmp_path_factory.mktemp("os-iso")
    approved = root / "approved"
    scratch = root / "scratch"
    keys = root / "instructor-keys"
    approved.mkdir()
    scratch.mkdir()
    keys.mkdir()
    (approved / "feed.txt").write_text("ANSWER-FREE-FEED\n", encoding="utf-8")
    (keys / "answer.key").write_text(INSTRUCTOR_CANARY + "\n", encoding="utf-8")
    profile = IsolationProfile(
        approved_inputs=str(approved),
        scratch=str(scratch),
        limits={
            "RLIMIT_NPROC": 64,
            "RLIMIT_NOFILE": 256,
            "RLIMIT_AS": 2 ** 31,
            "RLIMIT_FSIZE": 1 << 20,
            "RLIMIT_CPU": 60,
        },
        timeout_s=60.0,
    )
    return {"root": root, "approved": approved, "scratch": scratch,
            "keys": keys, "profile": profile}


def _bounded_profile(jail, limits: dict[str, int]) -> IsolationProfile:
    return IsolationProfile(
        approved_inputs=jail["profile"].approved_inputs,
        scratch=jail["profile"].scratch,
        limits=limits,
        timeout_s=60.0,
    )


@_requires_namespaces
class TestFilesystemBounds:
    def test_read_approved_input_succeeds_and_procfs_is_fresh(self, jail):
        code = (
            "import json, os\n"
            "print('READ', open('/inputs/feed.txt').read().strip())\n"
            "print('PROC', json.dumps(sorted(p for p in os.listdir('/proc') if p.isdigit())))\n"
            "print('SELF', os.getpid())\n"
        )
        result = _assert_ran(_run_one(jail["profile"], code), "jailed read")
        fields = _fields(result.stdout)
        assert fields["READ"] == "ANSWER-FREE-FEED"
        # fresh procfs: the jail's own PID namespace, no host processes
        pids = set(json.loads(fields["PROC"]))
        assert pids.issubset({"1", fields["SELF"]}), pids

    def test_write_scratch_succeeds_and_is_host_visible(self, jail):
        result = _assert_ran(
            _run_one(jail["profile"],
                     "open('/scratch/out.txt', 'w').write('jailed'); print('WROTE')"),
            "scratch write")
        assert "WROTE" in result.stdout
        # /scratch IS the host directory: the write is real, not simulated
        assert (jail["scratch"] / "out.txt").read_text() == "jailed"

    def test_write_outside_scratch_refused(self, jail):
        code = (
            "for path in ('/inputs/evil.txt', '/evil.txt', '/usr/evil.txt', '/tmp/ok.txt'):\n"
            "    try:\n"
            "        open(path, 'w').write('x')\n"
            "        print('DENY', path, 'ALLOWED')\n"
            "    except OSError as exc:\n"
            "        print('DENY', path, 'errno', str(exc.errno))\n"
        )
        result = _assert_ran(_run_one(jail["profile"], code), "denial probe")
        denials = {}
        for line in result.stdout.splitlines():
            _, path, verdict = line.split(" ", 2)
            denials[path] = verdict
        # /inputs, / (jail root) and /usr are read-only at the kernel plane:
        # EROFS(30)/EACCES(13)/EPERM(1), never 'ALLOWED'
        assert set(denials) == {"/inputs/evil.txt", "/evil.txt", "/usr/evil.txt",
                                "/tmp/ok.txt"}
        for path in ("/inputs/evil.txt", "/evil.txt", "/usr/evil.txt"):
            verdict = denials[path]
            assert verdict.startswith("errno "), (path, verdict)
            assert int(verdict.split()[1]) in (1, 13, 30), (path, verdict)
        # /tmp is the one scratch-adjacent writable area (fresh private tmpfs)
        assert denials["/tmp/ok.txt"] == "ALLOWED"

    def test_host_paths_absent_from_jail(self, jail):
        code = (
            "import json, os\n"
            "print('HOME', str(os.path.exists('/home')).lower())\n"
            "print('ETC', str(os.path.exists('/etc')).lower())\n"
            "print('MNT', str(os.path.exists('/mnt')).lower())\n"
            "print('MEDIA', str(os.path.exists('/media')).lower())\n"
            "print('ROOT', json.dumps(sorted(os.listdir('/'))))\n"
        )
        result = _assert_ran(_run_one(jail["profile"], code), "layout probe")
        fields = _fields(result.stdout)
        for key in ("HOME", "ETC", "MNT", "MEDIA"):
            assert fields[key] == "false", (key, fields[key])
        listed = set(json.loads(fields["ROOT"]))
        assert not listed & {"home", "root", "etc", "mnt", "media"}, listed


@_requires_namespaces
class TestNetworkOffline:
    def test_loopback_connect_refused_and_dns_dead(self, jail):
        code = (
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('127.0.0.1', 80), timeout=5)\n"
            "    print('CONNECT ALLOWED')\n"
            "except OSError as exc:\n"
            "    print('CONNECT errno', str(exc.errno))\n"
            "try:\n"
            "    socket.getaddrinfo('specaudit-offline-probe.invalid', 443)\n"
            "    print('GETADDR RESOLVED')\n"
            "except socket.gaierror as exc:\n"
            "    print('GETADDR errno', str(exc.args[0]))\n"
        )
        result = _assert_ran(_run_one(jail["profile"], code), "network probe")
        fields = _fields(result.stdout)
        # down-loopback netns: kernel-refused errnos, not exception names --
        # EADDRNOTAVAIL(99)/ENETUNREACH(101)/ECONNREFUSED(111)
        assert fields.get("CONNECT", "ALLOWED").startswith("errno"), fields
        assert int(fields["CONNECT"].split()[1]) in (99, 101, 111), fields
        assert fields.get("GETADDR", "RESOLVED").startswith("errno"), fields
        assert int(fields["GETADDR"].split()[1]) in (
            socket.EAI_NONAME, socket.EAI_AGAIN, socket.EAI_FAIL,
            socket.EAI_NODATA), fields


@_requires_namespaces
class TestAnswerKeySeparation:
    def test_instructor_keys_next_to_inputs_absent(self, jail):
        # the keys directory is a SIBLING of the approved inputs on the
        # host; the jail mounts the approved dir ONLY, at /inputs.
        code = (
            "import json, os\n"
            "print('LISTING', json.dumps(sorted(os.listdir('/'))))\n"
            "print('DIR', str(os.path.exists('/instructor-keys')).lower())\n"
            "print('TRAVERSAL', str(os.path.exists('/inputs/../instructor-keys')).lower())\n"
            "try:\n"
            "    open('/inputs/../instructor-keys/answer.key').read()\n"
            "    print('READ LEAKED')\n"
            "except OSError as exc:\n"
            "    print('READ errno', str(exc.errno))\n"
        )
        result = _assert_ran(_run_one(jail["profile"], code), "separation probe")
        fields = _fields(result.stdout)
        listed = set(json.loads(fields["LISTING"]))
        assert "instructor-keys" not in listed
        assert fields["DIR"] == "false"
        assert fields["TRAVERSAL"] == "false"
        assert fields["READ"].startswith("errno"), fields
        assert INSTRUCTOR_CANARY not in result.stdout
        assert INSTRUCTOR_CANARY not in result.stderr


@_requires_namespaces
class TestResourceBounds:
    def test_nproc_bound_refuses_extra_spawn(self, jail):
        profile = _bounded_profile(jail, {
            "RLIMIT_NPROC": 2, "RLIMIT_NOFILE": 256,
            "RLIMIT_AS": 2 ** 31, "RLIMIT_CPU": 60,
        })
        code = (
            "import subprocess\n"
            "first = subprocess.Popen(['/usr/bin/sleep', '30'])\n"
            "try:\n"
            "    subprocess.Popen(['/usr/bin/sleep', '30'])\n"
            "    print('SPAWN ALLOWED')\n"
            "except OSError as exc:\n"
            "    print('SPAWN errno', str(exc.errno))\n"
            "first.kill()\n"
            "first.wait()\n"
        )
        result = _assert_ran(_run_one(profile, code), "nproc probe")
        fields = _fields(result.stdout)
        # EAGAIN(11)/EACCES(13): the KERNEL refused the task, not a hook
        assert fields.get("SPAWN", "ALLOWED").startswith("errno"), fields
        assert int(fields["SPAWN"].split()[1]) in (11, 13), fields

    def test_fsize_bound_blocks_large_write(self, jail):
        profile = _bounded_profile(jail, {
            "RLIMIT_FSIZE": 65536, "RLIMIT_NPROC": 64,
            "RLIMIT_NOFILE": 256, "RLIMIT_AS": 2 ** 31, "RLIMIT_CPU": 60,
        })
        code = (
            "import signal\n"
            "signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n"
            "try:\n"
            "    with open('/tmp/big.bin', 'wb') as fh:\n"
            "        fh.write(b'x' * (4 * 1024 * 1024))\n"
            "    print('FSIZE ALLOWED')\n"
            "except OSError as exc:\n"
            "    print('FSIZE errno', str(exc.errno))\n"
        )
        result = _assert_ran(_run_one(profile, code), "fsize probe")
        fields = _fields(result.stdout)
        assert fields.get("FSIZE", "ALLOWED").startswith("errno"), fields
        assert int(fields["FSIZE"].split()[1]) == 27, fields  # EFBIG: bounded


@_requires_namespaces
class TestIndependentStop:
    def test_wall_clock_timeout_kills_uncooperative_target(self, jail):
        profile = IsolationProfile(
            approved_inputs=jail["profile"].approved_inputs,
            scratch=jail["profile"].scratch,
            limits={"RLIMIT_NPROC": 64, "RLIMIT_NOFILE": 256,
                    "RLIMIT_AS": 2 ** 31, "RLIMIT_CPU": 600},
            timeout_s=3.0,
        )
        started = time.monotonic()
        with pytest.raises(IsolationError) as excinfo:
            os_isolation.run_isolated(
                profile,
                [PY3, "-c",
                 "import time; print('UP', flush=True); time.sleep(10_000)"],
                env={"PATH": "/usr/bin:/bin", "HOME": "/scratch",
                     "PYTHONUTF8": "1", "LC_ALL": "C"},
            )
        elapsed = time.monotonic() - started
        assert excinfo.value.reason == "timeout-killed"
        assert "UP" in excinfo.value.stdout  # the target ran, then died anyway
        assert elapsed < 30.0, elapsed

    def test_stop_all_kills_running_jail_independently(self, jail):
        marker = jail["scratch"] / "stop-marker"
        profile = IsolationProfile(
            approved_inputs=jail["profile"].approved_inputs,
            scratch=jail["profile"].scratch,
            limits={"RLIMIT_NPROC": 64, "RLIMIT_NOFILE": 256,
                    "RLIMIT_AS": 2 ** 31, "RLIMIT_CPU": 600},
            timeout_s=60.0,
        )
        outcomes: list = []

        def target():
            try:
                outcomes.append(os_isolation.run_isolated(
                    profile,
                    [PY3, "-c",
                     "open('/scratch/stop-marker', 'w').write('up'); "
                     "print('UP', flush=True); import time; time.sleep(10_000)"],
                ))
            except IsolationError as exc:
                outcomes.append(exc)

        worker = threading.Thread(target=target)
        worker.start()
        deadline = time.monotonic() + 30.0
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert marker.exists(), "jailed target never signalled readiness"
        started = time.monotonic()
        stop_all()
        worker.join(timeout=30.0)
        elapsed = time.monotonic() - started
        assert not worker.is_alive()
        assert len(outcomes) == 1
        # an external stop surfaces as the kernel's SIGKILL verdict (-9)
        killed = outcomes[0]
        assert isinstance(killed, IsolationError)
        assert killed.reason == "target-failed"
        assert killed.exit_code == -9
        assert elapsed < profile.timeout_s, elapsed
        stop_all()  # idempotent, nothing left live


class TestUnsupportedHost:
    """Runs on EVERY host (collectible on Windows, green under WSL)."""

    def test_typed_refusal_when_host_cannot_build_the_jail(
            self, monkeypatch, tmp_path):
        # the platform check is the FIRST host gate and must refuse with
        # the stable reason, never fall back to running unjailed.
        monkeypatch.setattr(os_isolation, "_is_linux", lambda: False)
        approved = tmp_path / "approved"
        scratch = tmp_path / "scratch"
        approved.mkdir()
        scratch.mkdir()
        profile = IsolationProfile(
            approved_inputs=str(approved), scratch=str(scratch))
        with pytest.raises(IsolationError) as excinfo:
            os_isolation.run_isolated(profile, [PY3, "-c", "pass"])
        assert excinfo.value.reason == "unsupported-host"
        assert excinfo.value.detail.get("reason") == "not-linux"

    def test_caller_input_validation_precedes_any_dispatch(self, tmp_path):
        approved = tmp_path / "approved"
        scratch = tmp_path / "scratch"
        approved.mkdir()
        scratch.mkdir()
        with pytest.raises(IsolationProfileError):
            IsolationProfile(approved_inputs=str(tmp_path / "missing"),
                             scratch=str(scratch))
        with pytest.raises(IsolationProfileError):
            IsolationProfile(approved_inputs=str(approved), scratch=str(scratch),
                             limits={"RLIMIT_STACK": 1024})
        profile = IsolationProfile(
            approved_inputs=str(approved), scratch=str(scratch))
        with pytest.raises(IsolationProfileError):
            os_isolation.run_isolated(profile, ["relative/python3", "-c", "pass"])
        with pytest.raises(IsolationProfileError):
            os_isolation.run_isolated(profile, [PY3, "-c", "pass"],
                                      env={"ISO_EVIL": "1"})
        with pytest.raises(IsolationProfileError):
            os_isolation.run_isolated(profile, ["/etc/passwd"])
