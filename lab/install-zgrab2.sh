#!/usr/bin/env bash
# Install zgrab2 into the Kali dev/test instance from source at a
# pinned tag (upstream ships no release binaries; `go install` pins the
# source version and integrity comes from the Go module checksum DB).
# Idempotent. Run from Windows (Git Bash).
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_KALI_NAME     registered distro name (kali-linux)
#   LAB_ZGRAB2_TAG    upstream tag to build (v1.0.0)
set -euo pipefail
# Keep Git Bash from rewriting POSIX-looking paths in wsl.exe argv.
export MSYS_NO_PATHCONV=1

NAME="${LAB_KALI_NAME:-kali-linux}"
TAG="${LAB_ZGRAB2_TAG:-v1.0.0}"

echo "[lab] installing zgrab2 ($TAG) into $NAME (apt golang + go install)"
wsl -d "$NAME" -u root -e bash -seu "$TAG" <<'EOF'
set -eu
export DEBIAN_FRONTEND=noninteractive
TAG="$1"
if ! command -v zgrab2 >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq golang >/dev/null
  GOBIN=/usr/local/bin go install "github.com/zmap/zgrab2/cmd/zgrab2@${TAG}"
fi
# v1.0.0 fatals on a missing blocklist config; an empty file means
# "block nothing" (the suite's scope gate is the actual control).
mkdir -p /root/.config/zgrab2
[ -f /root/.config/zgrab2/blocklist.conf ] || : > /root/.config/zgrab2/blocklist.conf
zgrab2 --version 2>/dev/null || zgrab2 2>&1 | head -1
echo "[lab] zgrab2 at: $(command -v zgrab2)"
EOF

cat <<EOF

[lab] done. The zgrab2 availability row now resolves from PATH; arming
example against a spawned target:

  export ZGRAB2_DISPATCH_SCOPE=<target-ip>
  python -m extension invoke zgrab2 scan \\
    '{"target": "<target-ip>", "module": "http"}'
EOF
