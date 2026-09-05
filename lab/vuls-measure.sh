#!/usr/bin/env bash
# Measure the admitted vuls scan in LOCAL mode against the Kali lab
# host itself. Run from Windows (Git Bash).
#
# Why local mode and not the spawned target: the target's sshd is a
# real banner service with NO login accounts (locked root, no
# authorized keys — build-golden installs openssh-server for the
# banner only), so vuls's remote scan cannot authenticate. Local mode
# (upstream tutorial keys, verified 2026-09-05: [servers.localhost]
# host="localhost" port="local") collects the REAL package inventory
# of the lab host with no SSH and no egress beyond loopback.
#
# Honesty notes this script exists to preserve:
# - VULS_DISPATCH_SCOPE arms the scan ACTION; the scanned host comes
#   from vuls's own config discovery (config.toml in the invoke cwd),
#   so the audit line records target=unknown. The workdir config names
#   exactly one host: localhost, local mode.
# - No CVE dictionaries are fetched (fetch stays blocked on no tier;
#   never spent from the lab), so the report carries no CVE counts.
#   The measured claim is the complete envelope plus the real
#   inventory the scan collected — not findings.
set -euo pipefail
export MSYS_NO_PATHCONV=1

NAME="${LAB_KALI_NAME:-kali-linux}"

wsl -d "$NAME" -u root -e bash -seu <<'EOF'
set -euo pipefail
command -v vuls >/dev/null 2>&1 || { echo "[lab] vuls not installed (lab/install-vuls.sh)" >&2; exit 1; }
cd /root/ctf
git rev-parse --short HEAD

WORK="$(mktemp -d /tmp/vuls-lab.XXXXXX)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# 1. The config is the scope in practice: one host, localhost, local
#    mode (no SSH, loopback collection only).
cat >"$WORK/config.toml" <<'TOML'
[servers]

[servers.localhost]
host = "localhost"
port = "local"
TOML

mkdir -p "$WORK/attempt"
export VULS_DISPATCH_SCOPE="localhost"
export PYTHONPATH=/root/ctf
AID="attempt-$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

# 2. Armed invoke from the workdir so upstream config discovery finds
#    exactly this config (echoed and asserted below).
cd "$WORK"
echo "[lab] invoke cwd: $(pwd)"; echo "[lab] config:"; cat config.toml
/opt/ctf/bin/python -m extension invoke vuls scan \
  --attempt-id "$AID" \
  --artifact-dir "$WORK/attempt" >"$WORK/envelope.json" 2>"$WORK/stderr.txt" || true

echo "--- stderr (audit line):"
cat "$WORK/stderr.txt"
echo "--- envelope:"
python3 - "$WORK/envelope.json" <<'PY'
import json, sys
try:
    env = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("(no envelope JSON was produced)")
    raise SystemExit(1)
print("status:", env["status"], "| transport_ok:", env["transport_ok"],
      "| capability:", env["capability_id"], "| side_effects:", env["side_effects"])
PY
echo "--- scan results (vuls results dir):"
if [ -d "$WORK/results" ]; then
  ls -la "$WORK/results" | head -8
  python3 - "$WORK/results" <<'PY'
import json, sys
from pathlib import Path
results = sorted(Path(sys.argv[1]).glob("*.json"))
if not results:
    print("(no results JSON written)")
    raise SystemExit(0)
doc = json.loads(results[-1].read_text(encoding="utf-8"))
scanned = doc.get("scannedServers") or []
mode = doc.get("scanMode")
print("scannedServers:", scanned, "| scanMode:", mode)
server_info = doc.get("serverInfo") or (doc.get("scannedCves", {}) or {})
if isinstance(server_info, dict):
    for name, info in list(server_info.items())[:1]:
        if isinstance(info, dict):
            print("server:", name,
                  "| packages collected:", len(info.get("packages") or {}))
PY
else
  echo "(no results dir — check the envelope/stderr above)"
fi
EOF
echo "[lab] vuls local-mode measurement done."
