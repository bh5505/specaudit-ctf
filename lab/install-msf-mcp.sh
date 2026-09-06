#!/usr/bin/env bash
# Install and start the Metasploit MCP bridge (GH05TCREW/MetasploitMCP,
# pinned to commit afc792d, 2026-02-05) plus its msfrpcd backend, both
# loopback-only on the kali lab lane. Verified 2026-09-06: msfrpcd on
# 127.0.0.1:55553 (no SSL), bridge SSE at http://127.0.0.1:8085/sse,
# all listing reads complete through the catalog arm.
#
# Distribution fact encoded here: the bridge's requirements.txt pulls
# current `mcp`, and mcp 2.x renamed mcp.server.fastmcp to MCPServer —
# the bridge fails at import with the upstream error (observed
# verbatim 2026-09-06); this script pins mcp<2 after install.
# Idempotent; run from Windows (Git Bash).
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_KALI_NAME     registered distro name (kali-linux)
#   LAB_MSF_MCP_REF   commit to pin (afc792d)
#   LAB_MSF_PASS      lab-only msfrpcd password (lab-msf-pass)
set -euo pipefail
export MSYS_NO_PATHCONV=1

NAME="${LAB_KALI_NAME:-kali-linux}"
REF="${LAB_MSF_MCP_REF:-afc792d}"
PASS="${LAB_MSF_PASS:-lab-msf-pass}"

wsl -d "$NAME" -u root -e bash -seu -- "$REF" "$PASS" <<'EOF'
set -euo pipefail
REF="$1"; PASS="$2"
BASE=/root/MetasploitMCP
VENV=/root/msfmcp-venv
if [ ! -d "$BASE" ]; then
  git clone --quiet https://github.com/GH05TCREW/MetasploitMCP.git "$BASE"
fi
git -C "$BASE" checkout --quiet "$REF"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --quiet -r "$BASE/requirements.txt"
pip install --quiet "mcp<2"
# idempotent restart of both halves (scoped to the bridge's path)
pkill -f "$BASE/MetasploitMCP.py" 2>/dev/null || true
pkill -f msfrpcd 2>/dev/null || true
sleep 1
# backend: loopback-only RPC daemon, no SSL, lab password
nohup msfrpcd -P "$PASS" -S -a 127.0.0.1 -p 55553 > /tmp/msfrpcd.log 2>&1 &
sleep 6
cd "$BASE"
export MSF_PASSWORD="$PASS" MSF_SERVER=127.0.0.1 MSF_PORT=55553 MSF_SSL=false
nohup python3 MetasploitMCP.py --transport http --host 127.0.0.1 --port 8085 \
  > /tmp/msf-mcp.log 2>&1 &
for i in $(seq 1 25); do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://127.0.0.1:8085/sse 2>/dev/null || true)
  # any HTTP answer from the SSE endpoint (2xx/4xx) means the server is
  # up and speaking; only transport-level failure (000) keeps waiting.
  if [ -n "$code" ] && [ "$code" != "000" ] && [ "$code" != "500" ]; then
    echo "[lab] msf-mcp bridge up at http://127.0.0.1:8085/sse (http $code)"
    exit 0
  fi
  sleep 2
done
echo "[lab] bridge did not answer within 50s; log tail:" >&2
tail -5 /tmp/msf-mcp.log >&2
exit 1
EOF
