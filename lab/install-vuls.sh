#!/usr/bin/env bash
# Install vuls into the Kali dev/test instance from source at a pinned
# tag (upstream's docs show clone+make; `go install` pins the same
# source version with integrity from the Go module checksum DB, the
# zgrab2 pattern). Idempotent. Run from Windows (Git Bash).
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_KALI_NAME     registered distro name (kali-linux)
#   LAB_VULS_TAG      upstream tag to build (v0.40.1). The pin applies
#                     at first install; to re-pin, remove /usr/local/
#                     bin/vuls inside the instance and re-run.
set -euo pipefail
# Keep Git Bash from rewriting POSIX-looking paths in wsl.exe argv.
export MSYS_NO_PATHCONV=1

NAME="${LAB_KALI_NAME:-kali-linux}"
TAG="${LAB_VULS_TAG:-v0.40.1}"

echo "[lab] installing vuls ($TAG) into $NAME (apt golang + go install)"
wsl -d "$NAME" -u root -e bash -seu -- "$TAG" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
TAG="$1"
if ! command -v vuls >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq golang >/dev/null
  # v0.40.1's trivy dependency needs the stdlib JSON v2 experiment
  # (encoding/json/v2 is behind GOEXPERIMENT=jsonv2 on Go 1.25/1.26;
  # without it the build fails with excluded build constraints).
  GOEXPERIMENT=jsonv2 GOBIN=/usr/local/bin \
    go install "github.com/future-architect/vuls/cmd/vuls@${TAG}"
fi
command -v vuls >/dev/null || { echo "[lab] vuls install failed" >&2; exit 1; }
echo "[lab] vuls at: $(command -v vuls)"
vuls -v 2>&1 | head -2 || true
EOF

cat <<EOF

[lab] done. The vuls availability row now resolves from PATH. Measured
local-mode scan (lab/vuls-measure.sh):

  bash lab/vuls-measure.sh
EOF
