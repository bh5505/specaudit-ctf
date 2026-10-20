#!/usr/bin/env bash
# Measure the zdns arm's lookup against a loopback lab zone
# (host resolver untouched). Run from Windows (Git Bash).
#
# dnsmasq binds one loopback IP for the selected lab zone. The
# lookup runs inside a private mount namespace with a resolv.conf
# overlay bind-mounted over /etc/resolv.conf, so ONLY the measurement
# process tree resolves through the lab zone; the distro's own resolver
# is never modified (asserted by a before/after hash, not by eye). If
# unshare is unavailable, a trap-guarded global swap fallback runs
# instead and restores the original before the integrity check.
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_KALI_NAME     registered distro name (kali-linux)
#   LAB_ZDNS_ZONE     lab zone (lab.ctf)
#   LAB_ZDNS_NAME     queried name inside the zone (probe.lab.ctf)
#   LAB_ZDNS_ADDR     A-record answer, a documentation address (192.0.2.10)
#   LAB_ZDNS_DNS      loopback IP dnsmasq binds (127.0.0.2)
#   LAB_ZDNS_RTYPE    record type (A)
set -euo pipefail
# Keep Git Bash from rewriting POSIX-looking paths in wsl.exe argv.
export MSYS_NO_PATHCONV=1

NAME="${LAB_KALI_NAME:-kali-linux}"
ZONE="${LAB_ZDNS_ZONE:-lab.ctf}"
QNAME="${LAB_ZDNS_NAME:-probe.${LAB_ZDNS_ZONE:-lab.ctf}}"
ADDR="${LAB_ZDNS_ADDR:-192.0.2.10}"
DNSIP="${LAB_ZDNS_DNS:-127.0.0.2}"
RTYPE="${LAB_ZDNS_RTYPE:-A}"

wsl -d "$NAME" -u root -e bash -seu -- "$ZONE" "$QNAME" "$ADDR" "$DNSIP" "$RTYPE" <<'EOF'
set -euo pipefail
ZONE="$1"; QNAME="$2"; ADDR="$3"; DNSIP="$4"; RTYPE="$5"

command -v zdns >/dev/null 2>&1 || { echo "[lab] zdns not installed (lab/install-zdns.sh)" >&2; exit 1; }
command -v dnsmasq >/dev/null 2>&1 || { echo "[lab] dnsmasq not installed (lab/install-zdns.sh)" >&2; exit 1; }
cd /root/ctf

WORK="$(mktemp -d /tmp/zdns-lab.XXXXXX)"
DNSMASQ_PID=""
cleanup() {
  [ -n "$DNSMASQ_PID" ] && kill "$DNSMASQ_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# 0. Integrity oracle: hash the host resolver before anything runs.
RESOLV_BEFORE="$(sha256sum /etc/resolv.conf | cut -d' ' -f1)"
restore_resolv() {
  cp --preserve=all "$WORK/resolv.conf.host" /etc/resolv.conf
}

# 1. Loopback lab authority: lab zone only, no upstream, nothing else.
PIDFILE="$WORK/dnsmasq.pid"
if ! dnsmasq --no-resolv --no-hosts --bind-interfaces \
    --listen-address="$DNSIP" --port=53 \
    --address="/${ZONE}/${ADDR}" \
    --txt-record="${QNAME},specaudit-ctf lab measurement" \
    --pid-file="$PIDFILE" --log-facility="$WORK/dnsmasq.log"; then
  echo "[lab] dnsmasq failed to start (is ${DNSIP}:53 already occupied? see ss -tlnup)" >&2
  exit 1
fi
[ -s "$PIDFILE" ] || { echo "[lab] dnsmasq wrote no pid (bind failure?)" >&2; exit 1; }
DNSMASQ_PID="$(cat "$PIDFILE")"
echo "[lab] dnsmasq pid $DNSMASQ_PID on $DNSIP:53, zone $ZONE -> $ADDR"

# 2. Overlay resolv.conf for the measurement only. Values cross the
#    namespace boundary as exported env, never as interpolated strings.
export ZDNS_ARGS WORK
ZDNS_ARGS="$(printf '{"domain": "%s", "record_type": "%s"}' "$QNAME" "$RTYPE")"
printf 'nameserver %s\noptions timeout:2 attempts:1\n' "$DNSIP" >"$WORK/resolv.conf"

if unshare -m --propagation private -- true 2>/dev/null; then
  echo "[lab] resolver overlay: private mount namespace (host resolv.conf untouched)"
  unshare -m --propagation private -- bash -c '
    mount --bind "$WORK/resolv.conf" /etc/resolv.conf || exit 3
    cd /root/ctf || exit 3
    /opt/ctf/bin/python -m extension invoke zdns lookup "$ZDNS_ARGS" \
      >"$WORK/result.json" 2>"$WORK/stderr.txt" || true
  ' || { echo "[lab] namespaced invoke failed" >&2; exit 1; }
else
  echo "[lab] WARNING: unshare unavailable — global resolv.conf swap with trap restore" >&2
  cp --preserve=all /etc/resolv.conf "$WORK/resolv.conf.host"
  trap 'restore_resolv; cleanup' EXIT
  cp "$WORK/resolv.conf" /etc/resolv.conf
  /opt/ctf/bin/python -m extension invoke zdns lookup "$ZDNS_ARGS" \
    >"$WORK/result.json" 2>"$WORK/stderr.txt" || true
  restore_resolv
fi

echo "--- stderr:"
cat "$WORK/stderr.txt"
echo "--- result and measured answer:"
python3 - "$WORK/result.json" "$RTYPE" <<'PY_RESULT'
import json, sys
try:
    result = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("(no result JSON was produced)")
    raise SystemExit(1)
print("ok:", result.get("ok"), "| error:", result.get("error"))
out = result.get("output")
if isinstance(out, str):
    try:
        out = json.loads(out)
    except json.JSONDecodeError:
        pass
if isinstance(out, dict):
    section = (out.get("results") or {}).get(sys.argv[2]) or {}
    data = section.get("data") or {}
    print("answers:", json.dumps(data.get("answers")))
    print("resolver:", json.dumps(data.get("resolver")), "| status:", section.get("status"))
else:
    print("output:", str(out)[:400])
PY_RESULT
# Check that the host resolver is byte-identical after the measurement.
RESOLV_AFTER="$(sha256sum /etc/resolv.conf | cut -d' ' -f1)"
if [ "$RESOLV_BEFORE" != "$RESOLV_AFTER" ]; then
  echo "[lab] HOST RESOLV.CONF CHANGED — before $RESOLV_BEFORE after $RESOLV_AFTER" >&2
  exit 1
fi
echo "[lab] host resolv.conf unchanged (sha256 $RESOLV_AFTER)"
EOF
