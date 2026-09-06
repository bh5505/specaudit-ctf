#!/usr/bin/env bash
# Install the pinned Osmedeus release binary (j3ssie/osmedeus v5.1.0,
# 2026-08-08) into the kali lab lane: release tarball with checksum
# verification (the documented install.sh has no version pinning - it
# downloads latest; the pinned tarball URL is from the release assets),
# community workflows via the engine's own installer, and the one-time
# engine init (binaries registry download - takes several minutes on a
# fresh host; observed >10 minutes 2026-09-06).
#
# Distribution facts encoded here (verified 2026-09-06 against the
# pinned binary):
#   - the first real command re-runs setup until the binaries registry
#     finishes; "osmedeus setup" is NOT a subcommand (unknown command).
#   - the DEFAULT flow requires a DOMAIN target; URL targets need the
#     url flow (-f url) - the catalog arm pins this in its argv.
#   - the init is triggered with a loopback dry-run (no command ever
#     executes under --dry-run).
# Idempotent; run from Windows (Git Bash).
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_KALI_NAME     registered distro name (kali-linux)
#   LAB_OSMEDEUS_VER  release tag to pin (v5.1.0)
set -euo pipefail
export MSYS_NO_PATHCONV=1

NAME="${LAB_KALI_NAME:-kali-linux}"
VER="${LAB_OSMEDEUS_VER:-v5.1.0}"

wsl -d "$NAME" -u root -e bash -seu -- "$VER" <<'EOF'
set -euo pipefail
VER="$1"
F="osmedeus_5.1.0_linux_amd64.tar.gz"
case "$VER" in v5.1.0) ;; *) F="osmedeus_${VER#v}_linux_amd64.tar.gz" ;; esac
DEST=/opt/osmedeus
mkdir -p "$DEST"
cd "$DEST"
if [ ! -x "$DEST/osmedeus" ]; then
  curl -sSL "https://github.com/j3ssie/osmedeus/releases/download/${VER}/$F" -o "$F"
  curl -sSL "https://github.com/j3ssie/osmedeus/releases/download/${VER}/checksums.txt" -o checksums.txt
  grep -F " $F" checksums.txt | sha256sum -c -
  tar -xzf "$F" -C "$DEST" osmedeus
  rm -f "$F"
fi
ln -sf "$DEST/osmedeus" /usr/local/bin/osmedeus
"$DEST/osmedeus" version | head -4
# re-run assert: the pinned version must be what runs
"$DEST/osmedeus" version | grep -F "Version: $VER"
# community workflows (the engine's own installer - unpinned HEAD by
# design; the resolved revision is recorded so runs are attributable)
git ls-remote https://github.com/osmedeus/osmedeus-workflow.git HEAD > /tmp/osmedeus-workflow-rev.txt
# community workflows (engine's own installer)
"$DEST/osmedeus" install workflow --preset 2>&1 | tail -2 || \
  "$DEST/osmedeus" install workflow https://github.com/osmedeus/osmedeus-workflow.git 2>&1 | tail -2
# one-time engine init: the binaries registry download. Loopback
# dry-run trigger - no command executes under --dry-run; allow up to
# 30 minutes on a fresh host.
timeout 1800 "$DEST/osmedeus" scan -t http://127.0.0.1:9/ --dry-run \
  --heuristics-check none > /tmp/osmedeus-init.log 2>&1 || {
    echo "[lab] init dry-run did not complete in 30m; log tail:" >&2
    tail -5 /tmp/osmedeus-init.log >&2
    exit 1
  }
echo "[lab] osmedeus $VER installed + initialized (workflows + binaries registry)"
EOF
