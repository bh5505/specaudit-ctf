#!/usr/bin/env bash
# Build the golden lab-target rootfs once, from a freshly installed
# Debian WSL distro. Run from Windows (Git Bash) where wsl.exe lives.
#
# Environment (all optional; see lab/local.example.conf):
#   LAB_GOLDEN_NAME  registered name of the fresh Debian distro (Debian)
#   LAB_TAR          output tar path (Windows-side) for the golden rootfs
#   LAB_KEEP_GOLDEN  1 to keep the golden distro registered afterwards
#
# The golden image is intentionally inert: openssh-server for a banner,
# python3 http.server listeners, and the static content in lab/target/.
# Host keys are generated at build time, so every ephemeral instance
# cloned from this tar shares them — acceptable for a lab target, never
# for anything real.
set -euo pipefail
# Keep Git Bash from rewriting POSIX-looking paths in wsl.exe argv.
export MSYS_NO_PATHCONV=1

GOLDEN="${LAB_GOLDEN_NAME:-Debian}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TAR="${LAB_TAR:-$(cygpath -w "$HERE/ctf-target-base.tar")}"

echo "[lab] configuring golden distro: $GOLDEN"
wsl -d "$GOLDEN" -u root -e bash -seu <<'EOF'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq openssh-server python3 >/dev/null
mkdir -p /srv/lab-www /usr/local/lab /var/log
ssh-keygen -A >/dev/null
printf '\n# lab target marker\n' >>/etc/issue || true
EOF

# Ship the lab content and service starter into the golden image.
for f in start-services.sh index.html form.html; do
  wsl -d "$GOLDEN" -u root -e bash -c "cat > /labstage-$f" <"$HERE/target/$f"
done
wsl -d "$GOLDEN" -u root -e bash -seu <<'EOF'
set -eu
install -m 0755 /labstage-start-services.sh /usr/local/lab/start-services.sh
mv /labstage-index.html /srv/lab-www/index.html
mv /labstage-form.html /srv/lab-www/form.html
rm -f /labstage-*
echo "[lab] golden content installed:"
ls -l /usr/local/lab /srv/lab-www
EOF

echo "[lab] exporting golden rootfs -> $TAR"
wsl --export "$GOLDEN" "$TAR"

if [[ "${LAB_KEEP_GOLDEN:-0}" != "1" ]]; then
  echo "[lab] unregistering golden distro (base tar retained; set LAB_KEEP_GOLDEN=1 to keep)"
  wsl --unregister "$GOLDEN"
fi
echo "[lab] done. Spawn an ephemeral target with lab/spawn-target.sh"
