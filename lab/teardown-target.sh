#!/usr/bin/env bash
# Tear down the ephemeral lab target (unregister + drop the instance
# filesystem). Run from Windows (Git Bash).
set -euo pipefail
# Keep Git Bash from rewriting POSIX-looking paths in wsl.exe argv.
export MSYS_NO_PATHCONV=1

NAME="${LAB_TARGET_NAME:-ctf-target}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${LAB_STATE_DIR:-$(cygpath -w "$HERE/instances/$NAME")}"
STATE_POSIX="$(cygpath -u "$STATE")"

# A config-provided rm -rf target must look like a lab instance dir —
# refuse roots, drive roots, and empty values before touching anything.
if [[ -z "$STATE_POSIX" || "$STATE_POSIX" == "/" || ! "$STATE_POSIX" == /*/instances/* ]]; then
  echo "[lab] refusing to remove suspicious state dir: '$STATE_POSIX' (expected .../instances/<name>)" >&2
  exit 1
fi

if wsl -l -q 2>/dev/null | tr -d '\0\r' | grep -qx "$NAME"; then
  echo "[lab] unregistering $NAME"
  wsl --unregister "$NAME"
else
  echo "[lab] no registered instance named '$NAME'"
fi
echo "[lab] removing state dir: $STATE_POSIX"
rm -rf -- "$STATE_POSIX"
echo "[lab] done"
