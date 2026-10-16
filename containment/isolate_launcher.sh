#!/bin/sh
# isolate_launcher.sh -- the privileged-side jail builder for
# containment/os_isolation.py (OS-enforced E1 isolation).
#
# Runs INSIDE `unshare --mount --net --pid --fork --mount-proc` (plus
# `--user --map-root-user` only when the supervisor is not root), as the
# PID-namespace's pid 1. Inputs arrive ONLY via ISO_* env vars set by the
# supervisor (never inherited caller env):
#
#   ISO_STAGE        host path for this run's jail-root tmpfs (unique)
#   ISO_MOUNT_PLAN   explicit mount list, one `kind<TAB>src<TAB>dst` per line
#                    (symlink | rbind-ro | rbind-rw | node-rw | node-ro);
#                    /inputs (approved inputs, ro) and /scratch (rw) are
#                    plan entries like everything else
#   ISO_SPEC_B64     base64(JSON): {argv, env, limits, drop} for the target
#
# Fail-closed contract: ANY mount/setup failure prints one structured
# `ISO-EVENT {...}` line on stderr and exits 125; the supervisor maps that
# to IsolationError("mount-failed"). Nothing of the target ever runs
# outside a fully built jail.
#
# Mount list (fixed launcher behavior, not in the plan):
#   /            fresh tmpfs (the whole jail root), remounted READ-ONLY by
#                the stage after setup -- writes fail EROFS outside the
#                two granted dirs
#   /tmp         fresh private tmpfs, mode 1777 (no host /tmp state)
#   /proc        fresh procfs mounted by the stage post-pivot (new PID
#                namespace: no host process is visible)
#   host root    pivoted out with pivot_root(2) and lazy-detached (MNT_DETACH):
#                /home, /root, /etc, /mnt, /media -- everything -- become
#                unreachable BY CONSTRUCTION, not by policy
#
# The final exec is a small python stage (system python, stdlib only --
# /usr is mounted read-only): it performs the pivot + detach + proc +
# ro-root, applies the profile rlimits (the prlimit(2) family) via
# setrlimit, drops to the unprivileged identity on root hosts, and
# execve's the target with the spec's argv/env. pivot_root(2) is used via
# ctypes because this WSL/util-linux build ships no pivot_root(1) binary.
#
# Deliberately NO setsid here: the supervisor kills the jail's process
# group (its own start_new_session group) for independent stop; a
# launcher-side setsid would orphan the target OUTSIDE that group.
set -eu

fail() {
    printf 'ISO-EVENT {"event":"%s","detail":"%s"}\n' "$1" "$2" >&2
    exit 125
}

[ -n "${ISO_STAGE:-}" ]       || fail bad-input "ISO_STAGE missing"
[ -n "${ISO_MOUNT_PLAN:-}" ]  || fail bad-input "ISO_MOUNT_PLAN missing"
[ -n "${ISO_SPEC_B64:-}" ]    || fail bad-input "ISO_SPEC_B64 missing"
[ -x /usr/bin/mount ]         || fail bad-input "mount(8) not at /usr/bin/mount"
[ -x /usr/bin/base64 ]        || fail bad-input "base64 not at /usr/bin/base64"
[ -x /usr/bin/python3 ]       || fail bad-input "system python3 not at /usr/bin/python3"

TAB=$(printf '\t')

# 1. private propagation FIRST (so no later mount can leak out and
#    pivot_root is not blocked by shared mounts), then the jail root tmpfs.
/usr/bin/mount --make-rprivate /      || fail make-rprivate /
mkdir -p "$ISO_STAGE"                 || fail stage-mkdir "$ISO_STAGE"
/usr/bin/mount -t tmpfs -o mode=755,nosuid,nodev \
    tmpfs "$ISO_STAGE"                || fail stage-tmpfs "$ISO_STAGE"

# fixed jail dirs (plan rows create their own destinations: symlink rows
# must NOT meet a pre-created real directory, or ln -s nests inside it)
for d in dev proc tmp inputs scratch iso-old; do
    mkdir -p "$ISO_STAGE/$d"          || fail stage-mkdir "$d"
done

# 2. the explicit mount plan (allowlisted runtime, inputs, scratch, devices).
printf '%s\n' "$ISO_MOUNT_PLAN" | {
    while IFS= read -r line || [ -n "$line" ]; do
        [ -n "$line" ] || continue
        kind=${line%%"$TAB"*}
        rest=${line#*"$TAB"}
        src=${rest%%"$TAB"*}
        dst=${rest#*"$TAB"}
        case "$kind" in
            symlink)
                mkdir -p "$ISO_STAGE${dst%/*}"    || fail symlink-mkdir "$dst"
                /usr/bin/ln -s "$src" "$ISO_STAGE$dst" \
                                             || fail symlink "$dst" ;;
            rbind-ro)
                mkdir -p "$ISO_STAGE$dst"         || fail rbind-mkdir "$dst"
                /usr/bin/mount --rbind "$src" "$ISO_STAGE$dst" \
                                             || fail rbind "$dst"
                /usr/bin/mount -o remount,ro,bind "$ISO_STAGE$dst" \
                                             || fail ro-remount "$dst" ;;
            rbind-rw)
                mkdir -p "$ISO_STAGE$dst"         || fail rbind-mkdir "$dst"
                /usr/bin/mount --rbind "$src" "$ISO_STAGE$dst" \
                                             || fail rbind "$dst" ;;
            node-rw|node-ro)
                mkdir -p "${ISO_STAGE}${dst%/*}" || fail node-mkdir "$dst"
                : > "$ISO_STAGE$dst"             || fail node-mkfile "$dst"
                /usr/bin/mount --bind "$src" "$ISO_STAGE$dst" \
                                             || fail node-bind "$dst"
                if [ "$kind" = node-ro ]; then
                    /usr/bin/mount -o remount,ro,bind "$ISO_STAGE$dst" \
                                             || fail ro-remount "$dst"
                fi ;;
            *)
                fail bad-plan-kind "$kind" ;;
        esac
    done
} || exit 125

# 3. fresh private /tmp and the target spec (decoded onto the jail root).
/usr/bin/mount -t tmpfs -o mode=1777,nosuid,nodev \
    tmpfs "$ISO_STAGE/tmp"            || fail tmp-tmpfs /tmp
printf '%s' "$ISO_SPEC_B64" | /usr/bin/base64 -d > "$ISO_STAGE/iso-spec.json"

# 4. into the jail: cwd = jail root; the stage pivots, seals, bounds, execs.
cd "$ISO_STAGE"                       || fail stage-chdir "$ISO_STAGE"
exec /usr/bin/python3 -c '
import ctypes, json, os, resource, sys

def _die(event, code):
    sys.stderr.write("ISO-EVENT " + json.dumps({"event": event, "errno": code}) + "\n")
    sys.stderr.flush()
    os._exit(125)

try:
    # relative: cwd is the jail root, which only becomes "/" at the pivot
    with open("iso-spec.json") as fh:
        spec = json.load(fh)
except OSError as exc:
    _die("spec-unreadable", exc.errno or 0)

libc = ctypes.CDLL(None, use_errno=True)
# pivot the tmpfs into place and lazy-detach the host tree for good.
if libc.pivot_root(b".", b"iso-old") != 0:
    _die("pivot-failed", ctypes.get_errno())
if libc.umount2(b"iso-old", 2) != 0:
    _die("detach-failed", ctypes.get_errno())
try:
    os.rmdir("iso-old")  # the empty leftover mountpoint (root still rw here)
except OSError:
    pass
# fresh procfs (new PID namespace view), then seal the root read-only.
if libc.mount(b"proc", b"/proc", b"proc", 0, b"") != 0:
    _die("proc-mount-failed", ctypes.get_errno())
if libc.mount(None, b"/", None, 33, None) != 0:  # MS_REMOUNT|MS_RDONLY
    _die("root-ro-failed", ctypes.get_errno())
# rlimits from the profile BEFORE exec (the prlimit(2) family).
for entry in spec.get("limits", []):
    name, value = entry
    res = getattr(resource, name, None)
    if res is None:
        _die("bad-rlimit-name", 0)
    try:
        resource.setrlimit(res, (value, value))
    except (ValueError, OSError) as exc:
        _die("rlimit-refused", getattr(exc, "errno", 0) or 0)
# on root hosts drop to the unprivileged identity: no capabilities at all
# afterwards, and RLIMIT_NPROC becomes kernel-enforced (uid != global root).
drop = spec.get("drop")
if drop and os.geteuid() == 0:
    try:
        os.setgroups([])
        os.setgid(drop["gid"])
        os.setuid(drop["uid"])
    except OSError as exc:
        _die("drop-refused", exc.errno or 0)
try:
    os.unlink("iso-spec.json")  # best effort: the ro root refuses it as nobody
except OSError:
    pass
os.chdir("/scratch")
try:
    os.execve(spec["argv"][0], spec["argv"], spec["env"])
except OSError as exc:
    _die("exec-refused", exc.errno or 0)
_die("exec-unreachable", 0)
'
