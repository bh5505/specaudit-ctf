#!/usr/bin/env bash
# Tri-host suite for the stdin class-sweep branch, sequenced (WSL
# distros share nothing here but avoid concurrent wsl instances).
set -euo pipefail
export MSYS_NO_PATHCONV=1

BRANCH="agents/20260905-stdin-class-sweep"

echo "=== Ubuntu suite ==="
wsl -d Ubuntu -- bash -seu <<EOF
set -euo pipefail
cd ~/ctf
git fetch origin -q
git checkout -q "$BRANCH" 2>/dev/null || true
git reset --hard -q "origin/$BRANCH"
/opt/ctf/bin/python -m pytest tests/ -q 2>&1 | tail -2
EOF

echo "=== Kali suite ==="
wsl -d kali-linux -u root -- bash -seu <<EOF
set -euo pipefail
cd /root/ctf
git fetch origin -q
git checkout -q "$BRANCH" 2>/dev/null || true
git reset --hard -q "origin/$BRANCH"
/opt/ctf/bin/python -m pytest tests/ -q 2>&1 | tail -2
EOF
echo "=== tri-host done ==="
