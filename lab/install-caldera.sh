#!/usr/bin/env bash
# Install and start Apache Caldera (successor home of MITRE CALDERA)
# at pinned release tag 5.3.0 into the Ubuntu lab lane, venv-isolated,
# API-only (no --build: that flag shells out to `npm run build` for the
# Vue UI, which needs Node; the REST/listing plane does not — verified
# 2026-09-06 on the Ubuntu lane: server listens on 127.0.0.1:8888 in
# ~35s, /api/v2/abilities lists the stockpile catalog, wrong key 401).
# Idempotent; run from Windows (Git Bash).
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_UBUNTU_NAME    registered distro name (Ubuntu)
#   LAB_CALDERA_TAG    release tag to pin (5.3.0)
#   LAB_CALDERA_KEY    value to rotate api_key_red to (default: leave
#                      the shipped ADMIN123 — the lab-emu-01 challenge
#                      grades exactly the shipped default; rotate on
#                      anything non-disposable)
set -euo pipefail
export MSYS_NO_PATHCONV=1

NAME="${LAB_UBUNTU_NAME:-Ubuntu}"
TAG="${LAB_CALDERA_TAG:-5.3.0}"

wsl -d "$NAME" -u root -e bash -seu -- "$TAG" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
TAG="$1"
BASE=/root/caldera
VENV=/root/caldera-venv
if [ ! -d "$BASE" ]; then
  git clone --quiet --recursive --branch "$TAG" --depth 1 \
    --shallow-submodules https://github.com/apache/caldera.git "$BASE"
fi
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install --quiet -r "$BASE/requirements.txt"
# stop any previous instance (idempotent restart)
pkill -f "server.py" 2>/dev/null || true
sleep 1
cd "$BASE"
# --insecure: no TLS on the loopback listener (lab-only posture)
nohup python3 server.py --insecure > /tmp/caldera-server.log 2>&1 &
for i in $(seq 1 45); do
  if curl -s -o /dev/null --max-time 2 http://127.0.0.1:8888/ 2>/dev/null; then
    echo "[lab] caldera listening on http://127.0.0.1:8888 (after ${i}x2s)"
    exit 0
  fi
  sleep 2
done
echo "[lab] caldera did not listen within 90s; log tail:" >&2
tail -5 /tmp/caldera-server.log >&2
exit 1
EOF
