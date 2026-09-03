#!/usr/bin/env bash
# Tear down the ephemeral lab target (unregister + drop the instance
# filesystem). Run from Windows (Git Bash).
set -euo pipefail

NAME="${LAB_TARGET_NAME:-ctf-target}"
STATE="${LAB_STATE_DIR:-$(cygpath -w "$(dirname "$0")/instances/$NAME")}"

if wsl -l -q 2>/dev/null | tr -d '\0' | grep -qx "$NAME"; then
  echo "[lab] unregistering $NAME"
  wsl --unregister "$NAME"
else
  echo "[lab] no registered instance named '$NAME'"
fi
rm -rf "$STATE"
echo "[lab] done"
