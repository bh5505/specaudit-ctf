#!/usr/bin/env bash
# Install detectify/page-fetch into the Kali dev/test instance via
# `go install` at a pinned commit (the repo ships no release tags;
# the zgrab2/vuls pattern — the pin gets integrity from the Go module
# checksum DB). Idempotent. Run from Windows (Git Bash).
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_KALI_NAME        registered distro name (kali-linux)
#   LAB_PAGE_FETCH_REF   upstream commit to build. The pin applies at
#                        first install; to re-pin, remove /usr/local/
#                        bin/page-fetch inside the instance and re-run.
set -euo pipefail
# Keep Git Bash from rewriting POSIX-looking paths in wsl.exe argv.
export MSYS_NO_PATHCONV=1

NAME="${LAB_KALI_NAME:-kali-linux}"
REF="${LAB_PAGE_FETCH_REF:-5d8639a4044a41b24b316452f72e123f192c5238}"

echo "[lab] installing page-fetch ($REF) into $NAME (apt golang + go install)"
wsl -d "$NAME" -u root -e bash -seu -- "$REF" <<'EOF'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
REF="$1"
if ! command -v page-fetch >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq golang >/dev/null
  GOBIN=/usr/local/bin go install \
    github.com/detectify/page-fetch@"$REF"
  echo "[lab] installed: $(command -v page-fetch)"
else
  echo "[lab] page-fetch already present: $(command -v page-fetch)"
fi
page-fetch -h 2>&1 | head -3 || true
EOF
echo "[lab] done."
