#!/usr/bin/env bash
# Measure the zdns arm's admitted lookup against a loopback lab zone
# (untracked-host resolver untouched). Run from Windows (Git Bash).
#
# Shape (the "lab authority on Kali loopback" design, consult-adopted
# 2026-09-04): dnsmasq binds one unoccupied loopback IP, authoritative
# for a lab zone only (--no-resolv: no upstream forwarding — anything
# outside the zone is refused, so the overlay cannot leak to the
# internet). The armed lookup runs inside a private mount namespace
# with a resolv.conf overlay bind-mounted over /etc/resolv.conf, so
# ONLY the measurement process tree resolves through the lab zone;
# the distro's own resolver is never modified. If unshare is
# unavailable, a trap-guarded global swap fallback runs instead.
#
# Honesty note this script exists to preserve: ZDNS_DISPATCH_SCOPE
# authorizes the queried NAME (the dispatch target), not the resolver
# transport — where packets go is decided by resolv.conf. The measured
# record must say which resolver answered.
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

# 1. Loopback lab authority: lab zone only, no upstream, nothing else.
PIDFILE="$WORK/dnsmasq.pid"
dnsmasq --no-resolv --no-hosts --bind-interfaces \
  --listen-address="$DNSIP" --port=53 \
  --address="/${ZONE}/${ADDR}" \
  --txt-record="${QNAME},specaudit-ctf lab measurement" \
  --pid-file="$PIDFILE" --log-facility="$WORK/dnsmasq.log"
DNSMASQ_PID="$(cat "$PIDFILE")"
echo "[lab] dnsmasq pid $DNSMASQ_PID on $DNSIP:53, zone $ZONE -> $ADDR"

# 2. Overlay resolv.conf for the measurement only.
printf 'nameserver %s\noptions timeout:2 attempts:1\n' "$DNSIP" >"$WORK/resolv.conf"

export ZDNS_DISPATCH_SCOPE="$QNAME"
ARGS="{\"domain\": \"$QNAME\", \"record_type\": \"$RTYPE\"}"
ATTEMPT_DIR="$WORK/attempt"
mkdir -p "$ATTEMPT_DIR"
AID="attempt-$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

if unshare -m --propagation private -- true 2>/dev/null; then
  echo "[lab] resolver overlay: private mount namespace (host resolv.conf untouched)"
  unshare -m --propagation private -- bash -c \
    "mount --bind '$WORK/resolv.conf' /etc/resolv.conf && cd /root/ctf && exec /opt/ctf/bin/python -m extension invoke zdns lookup '$ARGS' --attempt-id '$AID' --artifact-dir '$ATTEMPT_DIR'" \
    >"$WORK/envelope.json" 2>"$WORK/stderr.txt"
else
  echo "[lab] WARNING: unshare unavailable — global resolv.conf swap with trap restore" >&2
  cp --preserve=all /etc/resolv.conf "$WORK/resolv.conf.host"
  restore() { cp --preserve=all "$WORK/resolv.conf.host" /etc/resolv.conf; }
  trap 'restore; cleanup' EXIT
  cp "$WORK/resolv.conf" /etc/resolv.conf
  /opt/ctf/bin/python -m extension invoke zdns lookup "$ARGS" \
    --attempt-id "$AID" --artifact-dir "$ATTEMPT_DIR" \
    >"$WORK/envelope.json" 2>"$WORK/stderr.txt"
fi

echo "--- stderr (audit line):"
cat "$WORK/stderr.txt"
echo "--- envelope:"
python3 - "$WORK/envelope.json" <<'PY'
import json, sys
env = json.load(open(sys.argv[1]))
print("status:", env["status"], "| transport_ok:", env["transport_ok"],
      "| capability:", env["capability_id"], "| side_effects:", env["side_effects"])
PY
echo "--- measured answer (from the materialized policy-report artifact):"
python3 - "$ATTEMPT_DIR" <<'PY'
import json, sys
from pathlib import Path
dir_ = Path(sys.argv[1])
blob = sorted(dir_.glob("sha256-*"))[0]
doc = json.loads(blob.read_text(encoding="utf-8"))
stamp = doc.get("dispatch")
out = doc.get("output")
if isinstance(out, str):
    try:
        out = json.loads(out)
    except json.JSONDecodeError:
        pass
print("stamp:", json.dumps(stamp, sort_keys=True))
if isinstance(out, dict):
    # zdns v2 JSON shape: {"name", "results": {"<RTYPE>": {"data": {...}}}}
    section = (out.get("results") or {}).get("A") or {}
    data = section.get("data") or {}
    print("answers:", json.dumps(data.get("answers")))
    print("resolver:", json.dumps(data.get("resolver")), "| status:", section.get("status"))
else:
    print("output:", str(out)[:400])
PY
echo "[lab] host resolv.conf check (must be the original WSL symlink target):"
ls -l /etc/resolv.conf
EOF
