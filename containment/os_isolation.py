"""OS-enforced E1 isolation supervisor: Linux namespace jail OUTSIDE the
learner process.

This is the third, strongest layer of the containment package. It is
COMPLEMENTARY to the PEP 578 audit-hook plane (``containment/enforcer.py``):

* the audit hook polices the PYTHON plane and produces per-event evidence
  (one JSON line per denial) -- it is NOT an OS sandbox;
* this module runs the target inside a Linux mount/net/PID namespace jail
  built by ``isolate_launcher.sh``: the kernel, not an in-process hook,
  refuses the escape. Where the host refuses the primitives, the module
  refuses cleanly with ``IsolationError("unsupported-host")`` -- it never
  degrades to running unjailed.

What the jail enforces (kernel plane, empirically testable):

* FILESYSTEM: a fresh mount namespace whose visible root is a private
  tmpfs holding ONLY: the approved-inputs directory bound read-only at
  ``/inputs``; the scratch directory bound read-write at ``/scratch``; the
  minimal runtime needed to execute the target (system python + stdlib:
  explicit bind mounts of ``/usr`` plus ``/bin``/``/sbin``/``/lib``/
  ``/lib64`` when they are real directories -- the mount list is built
  explicitly below and every mount is documented); a private tmpfs at
  ``/tmp``; a fresh procfs at ``/proc``. The host root is pivoted out with
  ``pivot_root(2)`` and lazy-detached, so ``/home``, ``/root``, ``/etc``,
  ``/mnt``, ``/media`` and every other host path are unreachable BY
  CONSTRUCTION, and the jail root is remounted read-only (writes fail with
  EROFS everywhere except ``/scratch`` and ``/tmp``).
* NETWORK: a fresh network namespace whose only interface is a DOWN
  loopback. There are no routes and no usable nameserver, so egress and
  DNS are impossible in this namespace by construction.
* PROCESS/RESOURCES: rlimits (RLIMIT_NPROC, RLIMIT_NOFILE, RLIMIT_AS,
  RLIMIT_FSIZE, RLIMIT_CPU) applied by the in-jail stage from the profile
  before exec. When the supervisor runs as root, the stage also drops the
  target to ``drop_uid``/``drop_gid`` (default nobody): unprivileged uid
  makes RLIMIT_NPROC actually enforceable (the kernel exempts the
  namespace root) and leaves the target without any capability, so no
  mount/chroot syscall is available to it at all.
* INDEPENDENT STOP: the supervisor owns the child's process group
  (``start_new_session`` at spawn) and keeps it registered; ``stop`` /
  ``stop_all`` SIGKILL the whole group regardless of child cooperation,
  and the wall-clock ``timeout_s`` does the same independently of any
  timer the target might set. The launcher deliberately does NOT setsid:
  a launcher-side setsid would orphan the target outside the group the
  supervisor kills. Any grandchild that escapes the group by setsid is
  still killed by PID-namespace teardown when pid 1 dies.
* ANSWER-KEY SEPARATION: only the two granted directories are mounted.
  Instructor keys placed anywhere else on the host -- including NEXT TO
  the approved inputs -- are simply not present in the jail; there is no
  path to reach them from inside.

Honest scope (do not over-claim):

* This is E1 evidence for Linux hosts that permit the namespace syscalls
  (WSL2's default distro qualifies; plain Windows does NOT and gets the
  typed refusal). It is NOT a full container runtime: no seccomp profile,
  no cgroup pressure controls, no device cgroup. E0 is static review and
  stays static; E2/E3 remain operator-gated environments per
  OPERATIONS.md -- this path grants NO E2/E3 authority and no live
  targets. The supervisor runs outside the learner process; the learner
  context is the jailed child.
* On hosts where the supervisor is not root, the stage cannot drop the
  uid (``--user --map-root-user`` has no second mapping), so the target
  stays namespace root and RLIMIT_NPROC is advisory there (kernel
  exemption); every other control is unchanged.
* Kernel mount helpers used: ``unshare(1)`` (probed before use), and
  in-jail ``pivot_root(2)``/``umount2(2)``/``mount(2)`` via the stage
  below; hosts without ``unshare --mount --pid --fork`` are
  ``unsupported-host``, never silently unjailed.

Clock discipline: like the rest of the package this module never reads
the wall clock; ``duration_seq`` is a ``time.monotonic`` delta (a
sequence counter usable for ordering, not a timestamp).
"""
from __future__ import annotations

import atexit
import base64
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
import uuid
from typing import Sequence

LAUNCHER_SCRIPT = Path(__file__).resolve().with_name("isolate_launcher.sh")
REPO_ROOT = Path(__file__).resolve().parents[1]

# The explicit runtime allowlist. Each entry becomes EITHER one symlink
# recreation (merged-/usr hosts: /bin -> usr/bin, ...) OR one read-only
# recursive bind (non-merged hosts), plus read-only binds for every
# submount found beneath a bound directory. Nothing else from the host
# filesystem is mounted -- that is the whole filesystem story.
_ALLOWED_FS_ROOTS = ("/usr", "/sbin", "/lib64", "/lib", "/bin")
# Device nodes the stdlib may legitimately need; bound individually so
# the jail has no full /dev. /dev/null stays writable (harmless sink).
_DEV_NODES_WRITABLE = ("/dev/null",)
_DEV_NODES_READABLE = ("/dev/zero", "/dev/urandom", "/dev/random")
# rlimit names the profile may bound (applied in-jail via setrlimit,
# i.e. the prlimit(2) family, before exec).
_RLIMIT_KEYS = (
    "RLIMIT_NPROC", "RLIMIT_NOFILE", "RLIMIT_AS", "RLIMIT_FSIZE", "RLIMIT_CPU",
)
_UNSHARE_CANDIDATES = ("/usr/bin/unshare", "/bin/unshare",
                       "/usr/sbin/unshare", "/sbin/unshare")
_SYSTEM_PYTHON_CANDIDATES = ("/usr/bin/python3", "/usr/local/bin/python3",
                             "/bin/python3")
_SPEC_MAX_BYTES = 64 * 1024
_EXIT_LAUNCHER_FAILURE = 125
_MNT_DETACH = 2
_MS_REMOUNT = 32
_MS_RDONLY = 1
_ENV_PREFIX = "ISO_"
_EVENT_MARKER = "ISO-EVENT "
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Live jail registry: child pid (== process-group id) -> Popen. stop_all
# SIGKILLs every registered group; run_isolated unregisters on exit.
_LIVE: dict[int, subprocess.Popen] = {}
_HOST_SUPPORT: "HostSupport | None" = None


class IsolationProfileError(ValueError):
    """Typed caller-input refusal (bad profile / argv / env); this is a
    caller mistake, distinct from the runtime :class:`IsolationError`."""


class IsolationError(RuntimeError):
    """Typed refusal/failure of the isolation plane.

    ``reason`` is a stable machine-readable code, one of:
    ``unsupported-host`` (not Linux / unshare unavailable / privileges
    missing), ``mount-failed`` (jail setup failed -- fail-closed, nothing
    ran), ``target-failed`` (the jailed target exited nonzero, including
    externally-killed -9), ``timeout-killed`` (wall-clock supervisor
    timeout fired independently of the target).
    """

    def __init__(
        self,
        reason: str,
        detail: dict | None = None,
        *,
        exit_code: int | None = None,
        stdout: str = "",
        stderr: str = "",
        denied_events: tuple[dict, ...] = (),
        duration_seq: float | None = None,
    ) -> None:
        super().__init__(f"{reason}: {detail or ''}")
        self.reason = reason
        self.detail = dict(detail or {})
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.denied_events = tuple(denied_events)
        self.duration_seq = duration_seq


@dataclass(frozen=True)
class HostSupport:
    """Probe verdict for the effective host (never assumed, always run)."""

    supported: bool
    mode: str | None  # "root" (plain unshare) or "userns" (--user --map-root-user)
    detail: str | None


@dataclass(frozen=True)
class IsolationProfile:
    """The operator-approved jail boundaries (plain data, validated).

    ``approved_inputs`` is bound read-only at ``/inputs``; ``scratch`` is
    the ONLY writable directory, bound read-write at ``/scratch`` (when
    the supervisor is root it is opened to ``drop_uid``). ``limits`` maps
    a subset of the ``RLIMIT_*`` names to byte/count bounds applied in the
    jail before exec. ``timeout_s`` is the supervisor's wall-clock kill
    deadline, independent of the target's cooperation. ``drop_uid``/
    ``drop_gid`` is the unprivileged identity the target is dropped to on
    root hosts (default nobody); set to None only for targets that must
    stay namespace root (which forfeits RLIMIT_NPROC enforcement).
    """

    approved_inputs: str
    scratch: str
    limits: dict[str, int] = field(default_factory=dict)
    timeout_s: float = 60.0
    drop_uid: int | None = 65534
    drop_gid: int | None = 65534

    def __post_init__(self) -> None:
        _existing_dir(self.approved_inputs, label="approved_inputs")
        _existing_dir(self.scratch, label="scratch")
        unknown = set(self.limits) - set(_RLIMIT_KEYS)
        if unknown:
            raise IsolationProfileError(
                f"unknown rlimit keys (allowed: {sorted(_RLIMIT_KEYS)}): {sorted(unknown)}")
        for key, value in self.limits.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise IsolationProfileError(f"{key} must be a positive int")
        if not isinstance(self.timeout_s, (int, float)) or self.timeout_s <= 0:
            raise IsolationProfileError("timeout_s must be a positive number")
        for label, value in (("drop_uid", self.drop_uid), ("drop_gid", self.drop_gid)):
            if value is not None and (not isinstance(value, int) or value < 0):
                raise IsolationProfileError(f"{label} must be a non-negative int or None")


@dataclass(frozen=True)
class IsolationResult:
    """One completed jailed run (exit 0); evidence planes stay separate."""

    exit_code: int
    stdout: str
    stderr: str
    denied_events: tuple[dict, ...]
    duration_seq: float


def _is_linux() -> bool:
    """The effective-host check; monkeypatched by tests to exercise the
    typed unsupported-host refusal on a capable host."""
    return sys.platform == "linux"


def _existing_dir(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IsolationProfileError(f"{label} must be a nonempty path string")
    absolute = os.path.abspath(value)
    if not os.path.isdir(absolute):
        raise IsolationProfileError(f"{label} must be an existing directory: {absolute}")
    return absolute


def _find_unshare() -> str:
    found = shutil.which("unshare")
    if found:
        return found
    for candidate in _UNSHARE_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError("unshare")


def _probe_mode(unshare: str, userns: bool) -> bool:
    cmd = [unshare, "--mount", "--pid", "--fork"]
    if userns:
        # util-linux's --map-root-user: map the invoking uid to namespace
        # root; needed only when the supervisor is not root.
        cmd += ["--user", "--map-root-user"]
    cmd += ["--", "/bin/true"]
    try:
        probe = subprocess.run(
            cmd, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


def probe_host_support() -> HostSupport:
    """Probe (and cache) whether THIS host can build the jail.

    The probe is the real ``unshare --mount --pid --fork true`` (plus the
    userns variant when plain unshare is denied); nothing is assumed from
    the platform string alone. On Windows this returns unsupported before
    any probe.
    """
    global _HOST_SUPPORT
    if _HOST_SUPPORT is not None:
        return _HOST_SUPPORT
    if not _is_linux():
        _HOST_SUPPORT = HostSupport(False, None, "not-linux")
        return _HOST_SUPPORT
    try:
        unshare = _find_unshare()
    except FileNotFoundError:
        _HOST_SUPPORT = HostSupport(False, None, "unshare-unavailable")
        return _HOST_SUPPORT
    if _probe_mode(unshare, userns=False):
        _HOST_SUPPORT = HostSupport(True, "root", None)
        return _HOST_SUPPORT
    if _probe_mode(unshare, userns=True):
        _HOST_SUPPORT = HostSupport(True, "userns", None)
        return _HOST_SUPPORT
    _HOST_SUPPORT = HostSupport(False, None, "unshare-denied-by-kernel")
    return _HOST_SUPPORT


# --- mount plan (built once per run, from /proc/self/mountinfo) -----------

def _decode_mountinfo(raw: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), raw)


def _mount_points() -> list[str]:
    points: list[str] = []
    try:
        text = Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return points
    for line in text.splitlines():
        head, sep, _tail = line.partition(" - ")
        if not sep:
            continue
        fields = head.split(" ")
        if len(fields) >= 5:
            points.append(_decode_mountinfo(fields[4]))
    return points


def _submounts_under(root: str, points: list[str]) -> list[str]:
    prefix = root.rstrip("/") + "/"
    return sorted(p for p in points if p.startswith(prefix))


def _build_mount_plan(approved_inputs: str, scratch: str) -> str:
    """The explicit, minimal mount list handed to the launcher.

    Lines are ``kind<TAB>src<TAB>dst``; kinds: ``symlink`` (recreate a
    merged-/usr symlink), ``rbind-ro`` (recursive bind, then read-only
    remount), ``rbind-rw`` (recursive bind, read-write -- scratch only),
    ``node`` (bind one device node). /tmp (private tmpfs), /proc (fresh
    procfs) and the read-only jail root are launcher/stage-fixed behavior,
    documented in ``isolate_launcher.sh``.
    """
    points = _mount_points()
    rows: list[tuple[str, str, str]] = []
    bound_realpaths: list[str] = []
    for root in _ALLOWED_FS_ROOTS:
        if not os.path.lexists(root):
            continue
        if os.path.islink(root):
            # merged-/usr layout: the jail must reproduce the symlink so
            # ABI loader paths like /lib64/ld-linux-*.so.2 resolve.
            rows.append(("symlink", os.readlink(root), root))
            continue
        real = os.path.realpath(root)
        if any(real == seen or real.startswith(seen.rstrip("/") + "/")
               for seen in bound_realpaths):
            continue  # already covered by an earlier (parent) bind
        rows.append(("rbind-ro", root, root))
        bound_realpaths.append(real)
        for sub in _submounts_under(root, points):
            sub_real = os.path.realpath(sub)
            if any(sub_real == seen or sub_real.startswith(seen.rstrip("/") + "/")
                   for seen in bound_realpaths):
                continue
            rows.append(("rbind-ro", sub, sub))
    for node in _DEV_NODES_WRITABLE:
        if os.path.exists(node):
            rows.append(("node-rw", node, node))
    for node in _DEV_NODES_READABLE:
        if os.path.exists(node):
            rows.append(("node-ro", node, node))
    rows.append(("rbind-ro", approved_inputs, "/inputs"))
    for sub in _submounts_under(os.path.realpath(approved_inputs), points):
        rows.append(("rbind-ro", sub, sub))
    rows.append(("rbind-rw", scratch, "/scratch"))
    for row in rows:
        for cell in row:
            if "\t" in cell or "\n" in cell:
                raise IsolationProfileError(f"path with tab/newline is not transportable: {cell!r}")
    return "".join(f"{kind}\t{src}\t{dst}\n" for kind, src, dst in rows)


# --- target/env preparation ------------------------------------------------

def _resolve_system_python() -> str:
    """The jailed runtime is the SYSTEM python (system python + stdlib is
    what the allowlist mounts); the supervisor's own interpreter may be a
    venv outside the allowlist and is deliberately not usable in-jail."""
    found = shutil.which("python3")
    candidates = ([found] if found else []) + list(_SYSTEM_PYTHON_CANDIDATES)
    allowed_real = [os.path.realpath(root) for root in _ALLOWED_FS_ROOTS]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            real = os.path.realpath(candidate)
            if any(real == root or real.startswith(root.rstrip("/") + "/")
                   for root in allowed_real):
                return candidate
    raise IsolationError(
        "unsupported-host",
        {"reason": "no-system-python-under-allowlisted-mounts",
         "candidates": [c for c in candidates if c]},
    )


def _default_target_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/scratch",
        "TMPDIR": "/tmp",
        "LC_ALL": "C",
        "PYTHONUTF8": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _validate_env(env: dict[str, str]) -> dict[str, str]:
    for name, value in env.items():
        if not _NAME_RE.match(name):
            raise IsolationProfileError(f"invalid env name: {name!r}")
        if name.startswith(_ENV_PREFIX):
            raise IsolationProfileError(
                f"env names with the {_ENV_PREFIX} prefix are reserved for the "
                "launcher transport")
        if not isinstance(value, str):
            raise IsolationProfileError(f"env value for {name} must be a string")
    return dict(env)


def _validate_argv(argv: Sequence[str]) -> list[str]:
    """Structural, host-independent validation: on Windows the typed
    unsupported-host refusal must stay reachable, so existence of argv[0]
    is checked later, behind the host gate."""
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise IsolationProfileError("argv must be a nonempty sequence of nonempty strings")
    executable = argv[0]
    if not os.path.isabs(executable):
        raise IsolationProfileError(f"argv[0] must be an absolute in-jail path: {executable!r}")
    allowed = [root for root in _ALLOWED_FS_ROOTS
               if executable == root or executable.startswith(root.rstrip("/") + "/")]
    if not allowed:
        raise IsolationProfileError(
            f"argv[0] must live under the allowlisted mounts {list(_ALLOWED_FS_ROOTS)}: "
            f"{executable!r}")
    return list(argv)


# --- the supervisor ---------------------------------------------------------

def _launcher_env(stage: str, plan: str, spec_b64: str) -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        f"{_ENV_PREFIX}STAGE": stage,
        f"{_ENV_PREFIX}MOUNT_PLAN": plan,
        f"{_ENV_PREFIX}SPEC_B64": spec_b64,
    }


def _stage_path() -> str:
    """Per-run staging directory for the jail root tmpfs (host side; the
    directory itself stays empty after the run and is rmdir'd best
    effort). /run is preferred (already a tmpfs), / is the fallback."""
    base = "/run" if os.path.isdir("/run") else "/"
    return os.path.join(base, f"iso-stage-{uuid.uuid4().hex[:12]}")


def _parse_events(stderr_text: str) -> tuple[dict, ...]:
    events: list[dict] = []
    for line in stderr_text.splitlines():
        if line.startswith(_EVENT_MARKER):
            try:
                row = json.loads(line[len(_EVENT_MARKER):])
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                events.append(row)
    return tuple(events)


def _kill_group(pid: int) -> None:
    """SIGKILL the whole process group; the launcher never setsid's, so
    the group id is the supervisor child's pid. PID-namespace teardown
    reclaims anything that escaped the group via its own setsid."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def stop(pid: int) -> None:
    """Independent operator stop: SIGKILL the jail's process group."""
    _kill_group(pid)


def stop_all() -> None:
    """Independent stop for EVERY live jail (idempotent, safe when none)."""
    for pid in list(_LIVE):
        _kill_group(pid)


atexit.register(stop_all)


def run_isolated(
    profile: IsolationProfile,
    argv: Sequence[str],
    *,
    env: dict[str, str] | None = None,
) -> IsolationResult:
    """Run ``argv`` inside the namespace jail and return its result.

    Raises :class:`IsolationError` with ``unsupported-host`` (host cannot
    build the jail), ``mount-failed`` (jail setup failed; the target never
    ran), ``target-failed`` (nonzero exit, including an external
    SIGKILL's -9) or ``timeout-killed`` (the supervisor's wall-clock
    deadline fired). Exit 0 returns the :class:`IsolationResult`.
    Structural caller-input mistakes (bad argv/env/profile) raise
    :class:`IsolationProfileError` on EVERY host, before any host gate;
    the argv[0] EXISTENCE check sits behind the host gate because it is
    host-relative (see _validate_argv).
    """
    started = time.monotonic()
    argv = _validate_argv(argv)
    child_env = _default_target_env() if env is None else _validate_env(env)
    if not _is_linux():
        raise IsolationError("unsupported-host", {"reason": "not-linux"})
    support = probe_host_support()
    if not support.supported:
        raise IsolationError("unsupported-host", {"reason": support.detail})
    if not os.path.exists(argv[0]):
        raise IsolationProfileError(
            f"argv[0] does not exist on this host: {argv[0]!r}")

    scratch = os.path.realpath(profile.scratch)
    os.makedirs(scratch, exist_ok=True)
    if profile.drop_uid is not None and os.geteuid() == 0:
        # The ONLY writable jail directory must be writable by the drop
        # identity; everything else stays closed to it.
        os.chmod(scratch, 0o777)

    plan = _build_mount_plan(os.path.realpath(profile.approved_inputs), scratch)
    limits = [[name, profile.limits[name]] for name in _RLIMIT_KEYS
              if name in profile.limits]
    drop = (None if profile.drop_uid is None or profile.drop_gid is None
            else {"uid": profile.drop_uid, "gid": profile.drop_gid})
    spec = {"argv": argv, "env": child_env, "limits": limits, "drop": drop}
    spec_bytes = json.dumps(spec, sort_keys=True).encode("utf-8")
    if len(spec_bytes) > _SPEC_MAX_BYTES:
        raise IsolationProfileError(
            f"spec exceeds {_SPEC_MAX_BYTES} bytes ({len(spec_bytes)}); keep argv/env small")
    spec_b64 = base64.b64encode(spec_bytes).decode("ascii")

    stage = _stage_path()
    unshare = _find_unshare()
    cmd = [unshare, "--mount", "--net", "--pid", "--fork", "--mount-proc"]
    if support.mode == "userns":
        cmd += ["--user", "--map-root-user"]
    cmd += ["--", "/bin/sh", str(LAUNCHER_SCRIPT)]

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=_launcher_env(stage, plan, spec_b64),
            start_new_session=True,  # the jail's group leader: killpg owns it all
            cwd=str(REPO_ROOT),
        )
    except OSError as exc:
        _cleanup_stage(stage)
        # fail-closed: a launcher that cannot even be spawned is a jail
        # setup failure, never a silent unjailed run
        raise IsolationError(
            "mount-failed",
            {"reason": "launcher-spawn-failed", "error": str(exc)}) from exc
    _LIVE[proc.pid] = proc
    timed_out = False
    try:
        try:
            stdout_bytes, stderr_bytes = proc.communicate(timeout=profile.timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc.pid)
            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=30)
            except subprocess.SubprocessError:
                stdout_bytes, stderr_bytes = b"", b""
    finally:
        _LIVE.pop(proc.pid, None)
        _cleanup_stage(stage)
    duration = time.monotonic() - started
    stdout_text = stdout_bytes.decode("utf-8", errors="replace")
    stderr_text = stderr_bytes.decode("utf-8", errors="replace")
    events = _parse_events(stderr_text)
    common = dict(stdout=stdout_text, stderr=stderr_text, denied_events=events,
                  duration_seq=duration)

    if timed_out:
        raise IsolationError("timeout-killed", {"timeout_s": profile.timeout_s},
                             exit_code=None, **common)
    if proc.returncode == _EXIT_LAUNCHER_FAILURE:
        raise IsolationError("mount-failed", {"launcher_events": list(events)},
                             exit_code=proc.returncode, **common)
    if proc.returncode != 0:
        raise IsolationError(
            "target-failed",
            {"reason": "nonzero-exit" if proc.returncode > 0 else "killed-by-signal"},
            exit_code=proc.returncode, **common)
    return IsolationResult(exit_code=0, **common)


def _cleanup_stage(stage: str) -> None:
    """The staging dir is empty again once the jail's tmpfs unmounted with
    the namespace; best-effort rmdir (a live jail would EBUSY, which we
    ignore -- the namespace death completes the cleanup)."""
    try:
        os.rmdir(stage)
    except OSError:
        pass
