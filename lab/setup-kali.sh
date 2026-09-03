#!/usr/bin/env bash
# Provision the Kali dev/test WSL instance for specaudit-ctf.
# Idempotent: safe to re-run. Run from Windows (Git Bash) where
# wsl.exe lives.
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_KALI_NAME   registered distro name (kali-linux)
#   LAB_KALI_REPO   clone URL (github https default)
#   LAB_KALI_HOME   repo path inside the instance (/root/ctf)
#   LAB_KALI_VENV   venv path inside the instance (/opt/ctf)
#   LAB_KALI_PKGS   apt packages to install (nmap/wapiti/routersploit/
#                   commix by default — all Kali-packaged scanner arms;
#                   add your own, e.g. zaproxy)
#   LAB_KALI_FULL_TEST  1 to run the full pytest suite at the end
#
# PEP 668: no system pip — everything Python lives in the venv.
set -euo pipefail
# In-instance paths are passed as wsl.exe arguments; stop Git Bash from
# rewriting /opt/... into Windows paths before they reach the distro.
export MSYS_NO_PATHCONV=1

NAME="${LAB_KALI_NAME:-kali-linux}"
REPO="${LAB_KALI_REPO:-https://github.com/bh5505/specaudit-ctf.git}"
HOME_DIR="${LAB_KALI_HOME:-/root/ctf}"
VENV="${LAB_KALI_VENV:-/opt/ctf}"
PKGS="${LAB_KALI_PKGS:-python3-venv python3-pip git nmap wapiti routersploit commix}"

if ! wsl -l -q 2>/dev/null | tr -d '\0' | grep -qx "$NAME"; then
  echo "[lab] installing WSL distro: $NAME"
  wsl --install -d "$NAME" --no-launch
else
  echo "[lab] distro already registered: $NAME"
fi

echo "[lab] installing packages + repo + venv (idempotent)"
wsl -d "$NAME" -u root -e bash -seu "$REPO" "$HOME_DIR" "$VENV" "$PKGS" <<'EOF'
set -eu
export DEBIAN_FRONTEND=noninteractive
REPO="$1"; HOME_DIR="$2"; VENV="$3"; PKGS="$4"
apt-get update -qq
# shellcheck disable=SC2086
apt-get install -y -qq $PKGS >/dev/null
if [ ! -d "$HOME_DIR/.git" ]; then
  git clone -q "$REPO" "$HOME_DIR"
else
  git -C "$HOME_DIR" pull --ff-only -q || echo "[lab] repo has local state; left as-is"
fi
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q -e "$HOME_DIR[dev]"
echo "[lab] versions:"
python3 --version
nmap --version | head -1 || true
echo "[lab] venv: $VENV   repo: $HOME_DIR"
EOF

echo "[lab] collecting the test suite (fast validation)"
wsl -d "$NAME" -u root -e bash -c "cd $HOME_DIR && $VENV/bin/python -m pytest tests/ -q --co -q 2>&1 | grep -E "tests collected|error" | tail -1" | tr -d '\0'

if [[ "${LAB_KALI_FULL_TEST:-0}" == "1" ]]; then
  echo "[lab] running the full suite"
  wsl -d "$NAME" -u root -e bash -c "cd $HOME_DIR && $VENV/bin/python -m pytest tests/ -q 2>&1 | tail -1" | tr -d '\0'
fi

cat <<EOF

[lab] Kali dev/test instance '$NAME' ready.

  wsl -d $NAME -u root
  cd $HOME_DIR && $VENV/bin/python -m pytest tests/ -q        # hermetic suite
  $VENV/bin/python -m extension availability                  # what lights up here

Then spawn an ephemeral target (lab/spawn-target.sh) and arm the
matching *_DISPATCH_SCOPE against its IP for real dispatch runs.
EOF
