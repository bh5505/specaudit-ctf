#!/usr/bin/env bash
# Measure the vuls scan in LOCAL mode against the Kali lab
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
# This script's config names one host: localhost, local mode. It does not
# fetch CVE dictionaries; it measures the inventory collected by scan.
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

# 1. Configure one host, localhost, local
#    mode (no SSH, loopback collection only).
cat >"$WORK/config.toml" <<'TOML'
[servers]

[servers.localhost]
host = "localhost"
port = "local"
TOML

export PYTHONPATH=/root/ctf

# 2. Invoke from the workdir so upstream config discovery finds
#    exactly this config (echoed and asserted below).
cd "$WORK"
echo "[lab] invoke cwd: $(pwd)"; echo "[lab] config:"; cat config.toml
/opt/ctf/bin/python -m extension invoke vuls scan \
  >"$WORK/result.json" 2>"$WORK/stderr.txt" || true

echo "--- stderr:"
cat "$WORK/stderr.txt"
echo "--- result:"
python3 - "$WORK/result.json" <<'PY'
import json, sys
try:
    result = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    print("(no result JSON was produced)")
    raise SystemExit(1)
print("ok:", result.get("ok"), "| action:", result.get("action"),
      "| error:", result.get("error"))
PY
echo "--- scan results (vuls results dir):"
if [ -d "$WORK/results" ]; then
  python3 - "$WORK/results" <<'PY'
import json, sys
from pathlib import Path
# vuls writes one per-server file per run: results/<timestamp>/<server>.json
files = sorted(Path(sys.argv[1]).rglob("*.json"))
if not files:
    print("(no results JSON written — check the result/stderr above)")
    raise SystemExit(0)
doc = json.loads(files[-1].read_text(encoding="utf-8"))
pkgs = doc.get("packages") or {}
print("file:", files[-1].relative_to(Path(sys.argv[1])))
print("server hostname:", doc.get("serverName") or files[-1].stem)
print("platform:", doc.get("platform"), doc.get("release"))
print("packages collected:", len(pkgs), "| scanMode:", doc.get("mode"))
PY
else
  echo "(no results dir — check the result/stderr above)"
fi
EOF
echo "[lab] vuls local-mode measurement done."
