#!/usr/bin/env bash
# Install zdns (ZMap) into the Kali dev/test instance from source at a
# pinned tag, plus dnsmasq for the loopback lab-zone measurement
# (lab/zdns-measure.sh). Upstream ships no release binaries; `go
# install` pins the source version and integrity comes from the Go
# module checksum DB. Idempotent. Run from Windows (Git Bash).
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_KALI_NAME     registered distro name (kali-linux)
#   LAB_ZDNS_TAG      upstream tag to build (v2.1.1). The pin applies
#                     at first install; to re-pin, remove /usr/local/
#                     bin/zdns inside the instance and re-run.
set -euo pipefail
# Keep Git Bash from rewriting POSIX-looking paths in wsl.exe argv.
export MSYS_NO_PATHCONV=1

NAME="${LAB_KALI_NAME:-kali-linux}"
TAG="${LAB_ZDNS_TAG:-v2.1.1}"

echo "[lab] installing zdns ($TAG) + dnsmasq into $NAME"
wsl -d "$NAME" -u root -e bash -seu -- "$TAG" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
TAG="$1"
apt-get update -qq
apt-get install -y -qq dnsmasq >/dev/null
if ! command -v zdns >/dev/null 2>&1; then
  command -v go >/dev/null 2>&1 || apt-get install -y -qq golang >/dev/null
  GOBIN=/usr/local/bin go install "github.com/zmap/zdns/v2@${TAG}"
fi
command -v zdns >/dev/null || { echo "[lab] zdns install failed" >&2; exit 1; }
echo "[lab] zdns at: $(command -v zdns) ($(zdns --version 2>&1 | head -1 || true))"
echo "[lab] dnsmasq at: $(command -v dnsmasq)"
EOF

cat <<EOF

[lab] done. The zdns availability row resolves from PATH once the
binary is on PATH (see lab/README.md). Measured lab lookup (loopback
lab zone, namespace-scoped resolver overlay):

  lab/zdns-measure.sh
EOF
