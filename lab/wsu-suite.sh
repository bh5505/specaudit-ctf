#!/usr/bin/env bash
# WSL-lane suites (Ubuntu + Kali) for the stdin class-sweep branch;
# the Windows lane runs on the host. Sequenced (avoid concurrent wsl
# instances racing a shared checkout).
set -euo pipefail
export MSYS_NO_PATHCONV=1

BRANCH="${1:-agents/20260905-vuls-scan-admission}"

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
