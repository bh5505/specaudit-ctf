#!/bin/sh
# Lab target services: an SSH banner plus two plain-HTTP listeners
# serving inert content. No real vulnerability is intended or needed —
# the point is a reachable single host for the suite's scope-gated
# dispatch arms (nmap scan, wapiti scan, page-fetch fetch, ...).
set -eu

mkdir -p /run/sshd
/usr/sbin/sshd

cd /srv/lab-www
nohup python3 -m http.server 8080 >/var/log/lab-http-8080.log 2>&1 &
nohup python3 -m http.server 8000 >/var/log/lab-http-8000.log 2>&1 &

# Give the listeners a beat, then prove they are up before returning.
sleep 1
python3 - <<'PY'
import socket
for port in (22, 8000, 8080):
    with socket.create_connection(("127.0.0.1", port), timeout=3):
        print(f"lab-target: port {port} listening")
PY
hostname -I
