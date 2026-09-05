#!/usr/bin/env bash
# Lock regen on the Ubuntu lane for the stdin class-sweep branch.
# Run from Windows (Git Bash). Never build on /mnt/c.
set -euo pipefail
export MSYS_NO_PATHCONV=1

BRANCH="agents/20260905-stdin-class-sweep"

wsl -d Ubuntu -- bash -seu <<EOF
set -euo pipefail
cd ~/ctf
git fetch origin
git checkout -q "$BRANCH" 2>/dev/null || true
git reset --hard "origin/$BRANCH"
git log --oneline -1
echo "=== lock-write ==="
/opt/ctf/bin/python -m runtime.build lock-write
echo "=== fetch ==="
/opt/ctf/bin/python -m runtime.build fetch
echo "=== build ==="
/opt/ctf/bin/python -m runtime.build build
echo "=== selfcheck ==="
/opt/ctf/bin/python -m runtime.build selfcheck
EOF
