# containment/ — operator rehearsal of the containment layers (SAFE-01, empirical)

This package rehearses, against the repo's own reader arms, the layered
containment an operator chains before pointing any arm at hostile input:

1. **Acquisition gate** — `reader_evidence.acquire` applied by the
   harness BEFORE dispatch. Hostile inputs (traversal,
   absolute-out-of-root, symlink-escape, device-file) are typed-refused
   there and never reach a child (`blocked` outcome with the stable
   refusal reason).
2. **Audit-hook enforcement plane** — `containment/enforcer.py` installs
   a PEP 578 `sys.addaudithook` hook in a CHILD interpreter before target
   code runs (`containment/worker.py`). The hook denies egress
   (socket connect/bind/getaddrinfo), subprocess/process creation
   (Popen/system/exec/posix_spawn/fork), write opens everywhere, any open
   outside the profile's resolved allowlist, and file-mutation verbs
   (rename/replace/link/symlink/remove/rmdir/chmod/chown/copyfile/rmtree)
   whose endpoints resolve outside the scratch root. Every denial raises
   `PermissionError` AND appends one JSON line
   (`{"event", "path"?, "mode"?, "ts_seq"}`) to an inherited pipe the
   child can only append to; the parent reads it. An installed audit hook
   cannot be removed or replaced from inside the process (PEP 578
   no-cooperation property).
3. **OS-enforced namespace jail** — `containment/os_isolation.py` (with
   `containment/isolate_launcher.sh`) runs a target command inside a
   Linux mount/net/PID namespace jail, supervised from OUTSIDE the
   learner process. Where the host permits the namespaces (WSL2's default
   distro qualifies) the kernel itself refuses the escape; elsewhere the
   module refuses typed. See "OS-enforced E1 isolation (Linux/WSL)"
   below — this is the kernel-enforced E1 floor beneath layer 2, not a
   replacement for it.

## Rehearsal vs strict scope (counts, caller roster, positive vs refusal)

The default `run_matrix` rehearsal covers hostile/cleanup/interruption
for the FIRST data action only: 38 in-root data actions + 14
`list_tools` smokes + 4 hostile + 1 cleanup + 1 interrupt + 2 canaries =
60 POSIX cases. Its completeness scope is `partial-rehearsal` and the
CLI labels it `partial` — never `full` simply because `os.name` is
POSIX.

`run_matrix(..., strict=True)` (`python -m containment --strict`)
requires the MANDATORY controls -- the standard four hostile classes,
cleanup, interruption, and both canaries -- for EVERY supplied data
action plus the discovery/canary cells, reusing the existing fixtures,
acquisition gate, enforcement, and ledger: 38x7 + 14 + 2 = 282 POSIX
cases with the canonical 14-reader/38-data roster and the default four
hostile classes plus cleanup plus interrupt. Execution-selection flags
(`hostile_classes`, `include_canaries`, `cleanup_first`,
`interrupt_first`, CLI `--no-canaries`) only select which runs execute;
omitted runs stay expected and surface as missing/incomplete with a
`partial` platform label (strict CLI exits nonzero even with zero
runtime failures). The summary carries explicit
expected/executed/skipped/missing/duplicate coverage, the supplied
roster count/digest, and the scope `strict-supplied-roster`.

The package never imports `safety.check`: the caller supplies the
frozen roster. A caller-supplied subset proves only that subset, never
universal SAFE acceptance; a full-baseline claim needs an independent
comparison against the canonical 14/38 roster in tests/evidence, not a
re-derivation of expected cells from actually executed cells. Strict
completeness fails closed on absent fixture args, omitted execution
cells, duplicate roster or result cells, truncated or missing worker
results, dirty cleanup, unexpected outcomes, and skips (skips count as
unevidenced). `--strict` exits nonzero for incomplete coverage even
with zero runtime failures.

In-root `positive` (arm ok) OR policy `refusal` (arm policy refused a
minimal input) is preserved separately with zero child denials — a
valid containment result, never claimed as successful consumption. The
worker deliberately bypasses normal catalog/dispatch admission (arm-layer
rehearsal, like the governance probes); interruption kills the delayed
child before its handler runs, not mid-parse.

## What the suite proves (empirically, in this checkout)

- Strict mode with the canonical roster: all 38 data actions x (1
  in-root + 4 hostile + 1 cleanup + 1 interrupt) plus 14 `list_tools`
  smokes (discovery carries no input path to acquire or deny) plus 2
  canaries = 282 POSIX cases, with the per-variant outcomes above and
  zero enforcer denials outside the enforced canary.
- The four escape probes (loopback socket, subprocess, write-open, symlink)
  are all denied in the enforced canary child; the same probes in a
  CONTROL child WITHOUT the hook run host-native (subprocess succeeds),
  proving the denials come from the enforcer, not from host hardening.
- Hostile inputs are blocked before dispatch with typed reasons, each
  recorded as a ledger row.
- MCP-mediated out-of-root reads are denied under the guard
  (`containment/mcp_guard.py`): a real stdio round trip — in-root feed
  completes; a feed outside the approved root yields the error envelope
  plus the pipe denial record.
- `python -m extension.range` with no path arguments under the guard
  completes or degrades with zero write-denial violations outside scratch.
- Instructor-plane separation at the operator-profile layer: the
  instructor keys are outside every approved root the harness admits, so
  direct and reader-mediated access are typed-refused; canary strings
  (`INSTRUCTOR-CANARY-*`) are absent from `exercise_operator` prepare
  exports, and a deliberate leak fixture proves the detector fires.
- Interruption (parent `stop_case` kills the delayed child before its
  handler), cleanup (scratch byte-identical after a run), rerun
  determinism, and per-case custody retention (acquisition records live
  in the outside detail documents, referenced by digest).

## What it does NOT prove (honest limits)

- **Not an OS sandbox.** The enforcement plane polices the Python
  audit-hook level only. Residual bypasses: C-extension internal I/O that
  raises no audited event; raw syscalls via ctypes/cffi; file descriptors
  already inherited across the spawn; processes that outlive the child.
  The operator's E2/E3 OS sandbox remains the real boundary. (Locally,
  `containment/os_isolation.py` is the complementary kernel-enforced E1
  floor where the host permits Linux namespaces — see below; the
  audit-hook plane remains the evidence layer, and the two compose.)
- **Not adversarial-process-proof.** The child is repo code under
  hostile inputs, not a committed adversary co-designing escapes; in a
  checkout layout the runtime read allowlist admits exactly four package
  directories (`containment`, `extension`, `reader_evidence`,
  `attempt_ledger` — see `_REPO_PACKAGE_DIRS` in
  `containment/enforcer.py`), not the entire checkout, so reads elsewhere
  in the repo (instructor keys, contracts, docs, tests) are denied even
  though they live inside the repository tree.
- **HZ-INPUT-PATH-UNBOUND remains open** for direct in-process arm use
  without this harness/guard: an arm invoked in-process with a hostile
  path and no acquisition gate is not contained by anything in this
  package.
- On Windows the trusted acquisition gate itself is typed-refused
  (`platform-unsupported`: no `os.O_NOFOLLOW`), so admitted cases proceed
  with the gate refusal recorded honestly and the CLI labels the run
  `partial`; symlink-escape and device-file hostile classes are POSIX-only.
- **Accepted-context OS proof remains OPEN.** The `os_isolation`
  namespace tests are 10 kernel-denied skips on hosts that refuse the
  namespaces; Python audit hooks are not OS proof. No claim is made that
  all profiles are accepted, that grading is integrated, that
  redirect/subresource coverage holds, that credentials are isolated, or
  that interruption lands mid-parse (it kills the delayed child before
  its handler).
- **Frozen v1 safety stays unverified; W0 helper declarations do not
  close SAFE.** The `containment_evidence` declared-record helpers
  authenticate nothing; this unit supplies full Python-plane
  scheduling/evidence only (282 actual outcomes on POSIX), not W2,
  activation, or real targets.

## Harnessed worker environment transport (U-SAFE.b)

Every guarded worker (`containment.worker`, and the guarded MCP server
/ range CLI which ride the same spawn helper) starts with a fixed
minimal environment built by `containment.harness._child_env` — never
from `os.environ`. Audit hooks cannot stop a child from reading its own
environment, so secrets must never be transported there at all: there is
no secret-name denylist, no prefix filter, and no caller override.

Fixed owned keys (POSIX): `PATH` (interpreter directory only),
`PYTHONPATH` (checkout root), `PYTHONUTF8=1`,
`PYTHONDONTWRITEBYTECODE=1`, `PYTHONNOUSERSITE=1`, `PYTHONSAFEPATH=1`,
`PYTHONIOENCODING=utf-8`, `PYTHONCOERCECLOCALE=0`, `PYTHONBREAKPOINT=0`,
deterministic single-thread caps (`OMP_NUM_THREADS`,
`OPENBLAS_NUM_THREADS`, `MKL_NUM_THREADS`, `NUMEXPR_NUM_THREADS` = 1),
the serialized `CONTAINMENT_PROFILE_JSON`, and the POSIX denial fd
(`CONTAINMENT_DENIAL_FD`) or Windows denial handle
(`CONTAINMENT_DENIAL_HANDLE`). Suppressed by absence: `PYTHONSTARTUP`,
`PYTHONHOME`, `PYTHONWARNINGS`, `PYTHONMALLOC` and other Python
startup/config, proxy (`*_PROXY`), loader injection (`LD_PRELOAD`,
`LD_LIBRARY_PATH`, `DYLD_*`), cloud/provider credentials, trace keys,
profiles, and all other ambient keys. The worker `argv[0]` is the
absolute current interpreter (via `_worker_interpreter`, also used by
the manual range-worker spawn). Environment values are never printed or
persisted in evidence or errors, and regression observers never
serialize a complete child environment: the in-child check returns only
safe booleans and unexpected key names. On Windows only, the single
documented non-secret OS bootstrap key (`SystemRoot`, matched
case-insensitively and emitted as one canonical `SystemRoot`) needed
for side-by-side assemblies is copied verbatim; `WINDIR`/`COMSPEC`/
`PATHEXT` are unneeded (absolute interpreter, `shell=False`) and
`TEMP`/`TMP` have no justified ambient temp dependency, so all stay
dropped. Windows was not executed for this unit (POSIX host); no native
Windows execution is claimed.

Scope, stated exactly: this proves only harness-spawned worker
environment transport. It does not prove file-based credential
isolation, native (non-Python) I/O, ordinary MCP/head launchers,
exercise/real-head secret transport, accepted learner/operator context,
redirects/subresources, mid-parse interruption, Windows execution, or OS
namespaces. It does not close SAFE or W1.

## OS-enforced E1 isolation (Linux/WSL)

`containment/os_isolation.py` + `containment/isolate_launcher.sh` are a
kernel-enforced E1 path: a supervisor OUTSIDE the learner process runs a
target command inside a Linux namespace jail. The audit-hook plane (layer
2) produces Python-plane EVIDENCE; this layer makes the KERNEL refuse the
escape. Both are rehearsal surfaces for E1; neither grants E2/E3.

What it proves (empirically, on hosts that permit the namespaces — WSL2's
default distro qualifies; `tests/test_os_isolation.py` is the evidence and
runs as part of the suite gate under WSL):

- **Filesystem bounds.** The jail root is a private tmpfs holding ONLY:
  the approved inputs bound read-only at `/inputs`; the scratch directory
  bound read-write at `/scratch`; the minimal runtime to execute the
  target (system python + stdlib — an explicit mount plan: `/usr` bound
  read-only, merged-`/usr` symlinks (`/bin`, `/lib`, `/lib64`, `/sbin`)
  recreated, individual device nodes bound; every mount is listed in
  `isolate_launcher.sh` and built by `_build_mount_plan`); a fresh private
  `/tmp`; a fresh procfs. The host root is `pivot_root(2)`-ed out and
  lazy-detached (`MNT_DETACH`), so `/home`, `/root`, `/etc`, `/mnt`,
  `/media` and every other host path are absent BY CONSTRUCTION, and the
  jail root is remounted read-only: writes outside the two granted dirs
  fail with EROFS at the syscall (observed errno 30).
- **Offline by construction.** A fresh network namespace whose only
  interface is a DOWN loopback: `connect(2)` to 127.0.0.1 fails
  ENETUNREACH (101) and `getaddrinfo` fails EAI_AGAIN (-3). There is no
  route and no usable resolver in this namespace; DNS/egress are
  impossible, not merely denied by policy.
- **Resource bounds.** The profile's rlimits (RLIMIT_NPROC, RLIMIT_NOFILE,
  RLIMIT_AS, RLIMIT_FSIZE bounded to scratch-scale, RLIMIT_CPU) are
  applied in-jail before exec (the prlimit(2) family via `setrlimit`). On
  root hosts the target is dropped to `nobody` — which is what makes
  RLIMIT_NPROC kernel-enforced (EAGAIN/11 beyond the bound; the kernel
  exempts the namespace root) and leaves the target with no capability at
  all (no mount, no chroot, nothing).
- **Independent stop.** The supervisor owns the jail's process group
  (`start_new_session`; the launcher deliberately never `setsid`s).
  `stop(pid)`/`stop_all()` SIGKILL the group regardless of target
  cooperation; the wall-clock `timeout_s` does the same on its own
  (`timeout-killed`); PID-namespace teardown reclaims anything that
  escaped the group with its own `setsid` once pid 1 dies.
- **Answer-key separation.** Only the two granted directories are
  mounted. Instructor keys anywhere else on the host — including NEXT TO
  the approved inputs — are not present in the jail: no `/instructor-keys`
  in the listing, no path to reach them, `/inputs/../instructor-keys`
  resolves inside the jail root and is absent.

What it does NOT prove / honest limits:

- Not a full container: no seccomp profile, no cgroup pressure or device
  controls. It bounds filesystem/network/processes exactly as listed
  above, nothing more.
- The host must actually permit the namespaces. The module PROBES the
  effective host (`unshare --mount --pid --fork true`, plus the
  `--user --map-root-user` variant when the supervisor is not root) and
  refuses typed — `IsolationError("unsupported-host")` — on plain Windows
  or any host whose kernel denies unshare. It never degrades to running
  unjailed.
- On non-root supervisors the target stays namespace root (the userns has
  no second uid mapping to drop to), so RLIMIT_NPROC is advisory there;
  every other control is unchanged and the refusal behavior is identical.
- E0 (static review) and E1 (this path) only. E2/E3 remain explicitly
  operator-gated environments per OPERATIONS.md: this path grants no
  E2/E3 authority and no live targets — and the jailed child has no
  network to reach any even if misused.

How to run it:

```bash
# the evidence suite (WSL, or any Linux host that permits the namespaces)
python -m pytest tests/test_os_isolation.py -q
```

```python
from containment.os_isolation import IsolationProfile, run_isolated, stop_all

profile = IsolationProfile(
    approved_inputs="/srv/operator/approved",   # bound ro at /inputs
    scratch="/srv/operator/scratch",            # bound rw at /scratch
    limits={"RLIMIT_NPROC": 64, "RLIMIT_FSIZE": 1 << 20},
    timeout_s=60.0,
)
result = run_isolated(profile, ["/usr/bin/python3", "-c", "..."])
# IsolationError(reason="unsupported-host" | "mount-failed" |
#                "target-failed" | "timeout-killed") otherwise
stop_all()  # independent operator stop for every live jail
```

Relationship to the other layers: the acquisition gate filters hostile
inputs before dispatch; the audit-hook plane records Python-plane denials
as evidence; this layer is the kernel-enforced floor beneath both. They
compose — run the same target under the guard AND the jail and each plane
reports what IT refused. The E2/E3 OS sandbox remains the operator gate
per OPERATIONS.md; nothing here grants it.

## How operators run it

```bash
# the matrix (roster JSON: [{"arm_id","action","path_argument"},...];
# the package never imports safety.check — the caller supplies the roster)
# default: 60-case rehearsal (partial-rehearsal); --strict: 282-case
# complete matrix for the canonical 14/38 roster on POSIX
python -m containment \
  --approved-root /srv/operator/approved \
  --scratch-root /srv/operator/scratch \
  --fixtures-root /srv/operator/approved/fixtures \
  --roster-json roster.json \
  --ledger /srv/operator/containment-attempts.jsonl
python -m containment --strict \
  --approved-root /srv/operator/approved \
  --scratch-root /srv/operator/scratch \
  --fixtures-root /srv/operator/approved/fixtures \
  --roster-json roster.json \
  --ledger /srv/operator/containment-attempts.jsonl
```

```python
# a guarded MCP server round trip
from containment.mcp_guard import guarded_call, invoke_arguments
result = guarded_call(profile, tool="invoke", arguments=invoke_arguments(
    entry_id="vulnify", action="lookup",
    args={"feed": str(approved / "feed.json"), "cve_id": "CVE-2024-0001"}))
```

To launch a long-lived guarded MCP server by hand: start the worker child
with the profile env (`CONTAINMENT_PROFILE_JSON`) and the denial pipe
(`CONTAINMENT_DENIAL_FD`, or `CONTAINMENT_DENIAL_HANDLE` on Windows —
`pass_fds` is unsupported there, so the inheritable handle VALUE is
inherited and re-opened with `msvcrt.open_osfhandle`), write the one job
line `{"kind":"mcp-server"}` to its stdin, then speak ndjson MCP on the
same stream. The child can only append denials to the pipe; read it from
the parent side.

Ledger discipline: rows go to a containment-LOCAL attempt ledger
(`lane="operator-rehearsal"`, subject `containment:<arm>:<action>`,
deterministic attempt ids so re-runs are legitimate retries), never to
any evaluation ledger. The structured detail document lives outside the
ledger, referenced by digest. No network, no clock reads in library code
(caller-supplied timestamps; the CLI owns the clock), no live targets.
