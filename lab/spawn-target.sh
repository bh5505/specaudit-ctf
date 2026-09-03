#!/usr/bin/env bash
# Spawn an ephemeral lab target from the golden rootfs and print its
# WSL-internal IP plus the arming commands for the dispatch arms.
# Run from Windows (Git Bash). Tear down with lab/teardown-target.sh
# (or wsl --unregister) — instances are disposable by design.
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_TARGET_NAME  registered instance name (ctf-target)
#   LAB_STATE_DIR    Windows-side dir for the instance filesystem
#   LAB_TAR          golden tar path (lab/build-golden.sh output)
set -euo pipefail

NAME="${LAB_TARGET_NAME:-ctf-target}"
TAR="${LAB_TAR:-$(cygpath -w "$(dirname "$0")/ctf-target-base.tar")}"
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE="${LAB_STATE_DIR:-$(cygpath -w "$HERE/instances/$NAME")}"

if wsl -l -q 2>/dev/null | tr -d '\0\r' | grep -qx "$NAME"; then
  echo "[lab] instance '$NAME' already registered (teardown first for a fresh one)" >&2
  exit 1
fi

echo "[lab] importing $NAME from $TAR"
mkdir -p "$(cygpath -u "$STATE")"
wsl --import "$NAME" "$STATE" "$TAR" --version 2

echo "[lab] starting services"
IP=$(MSYS_NO_PATHCONV=1 wsl -d "$NAME" -u root -e /usr/local/lab/start-services.sh \
  | tr -d '\0\r' | tail -n1 | awk '{print $1}')
if [[ -z "${IP//[[:space:]]/}" ]]; then
  echo "[lab] services did not report an IP; tearing the broken instance down" >&2
  wsl --unregister "$NAME" >/dev/null 2>&1 || true
  rm -rf -- "$(cygpath -u "$STATE")"
  exit 1
fi

cat <<EOF

[lab] target '$NAME' is up at $IP  (ports 22 / 8000 / 8080, WSL-internal NAT only)

From the Kali/dev instance, arm the scopes you want and invoke, e.g.:

  export NMAP_DISPATCH_SCOPE=$IP
  python -m extension invoke nmap scan '{"target": "$IP"}'

  export WAPITI_DISPATCH_SCOPE=$IP
  python -m extension invoke wapiti scan '{"url": "http://$IP:8080/"}'

  export PAGE_FETCH_DISPATCH_SCOPE=$IP
  python -m extension invoke page-fetch fetch '{"url": "http://$IP:8080/form.html?q=1"}'

Teardown: lab/teardown-target.sh   (fresh instance next spawn; nothing persists)
EOF
