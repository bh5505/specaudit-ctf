# Lab: WSL Kali dev/test instance + ephemeral target host

Local, single-host lab tooling for developing and testing this suite
against a real Kali instance and a real (inert) target host. Everything
machine-specific lives in environment variables or `lab/local.conf`
(gitignored; see `local.example.conf`) — the scripts themselves are
generic.

All scripts run from **Windows (Git Bash)** and orchestrate `wsl.exe`.

## Layout

| Script | Purpose |
|---|---|
| `setup-kali.sh` | Provision the Kali dev/test WSL instance (idempotent): distro, apt packages, repo clone, venv, editable install. |
| `install-zgrab2.sh` | Build zgrab2 into the dev instance from a pinned upstream tag (`go install`; Kali does not package it). |
| `install-zgrab2.sh` | Build zgrab2 into the dev instance from a pinned upstream tag (`go install`; Kali does not package it). |
| `build-golden.sh` | One-time: configure a fresh Debian WSL distro into the golden lab-target rootfs and export it to a tar. |
| `spawn-target.sh` | Register a **disposable** target instance from the golden tar, start its services, print its IP + arming commands. |
| `teardown-target.sh` | Unregister the instance and drop its state dir. |
| `target/` | Inert content + the service starter baked into the golden image. |
| `local.example.conf` | The knobs; copy to `local.conf` (gitignored) to override defaults. |

## One-time setup

```text
lab/setup-kali.sh                       # Kali dev/test instance
wsl --install -d debian --no-launch     # fresh Debian for the golden build
lab/build-golden.sh                     # exports lab/ctf-target-base.tar
```

## Per-session flow

```text
lab/spawn-target.sh    # prints the target IP and ready-to-paste arming commands
# ... from the Kali instance: arm *_DISPATCH_SCOPE to the IP, invoke ...
lab/teardown-target.sh
```

The target is deliberately boring: an SSH banner (port 22) and two
plain-HTTP listeners (8000, 8080) serving static content with one inert
form. No real vulnerability exists or is needed — the point is a
reachable single host so the scope-gated dispatch arms (nmap scan,
wapiti scan, page-fetch fetch, …) exercise their real plumbing: gate,
audit line, stamp, envelope. The target answers only on the WSL-internal
NAT network; nothing is published off-host.

Ephemerality: each spawn is a fresh `wsl --import` from the golden tar
and teardown is an unregister — no state survives. (Consequence: every
instance shares the golden's SSH host keys. Fine for a lab target;
never for anything real.)

## Hermeticity note

The test suite strips PATH for every test (`tests/conftest.py`), so a
scanner-equipped Kali behaves like a scanner-less host and the suite
stays hermetic everywhere. To see what the real host lights up, run
`python -m extension availability` — on Kali with the default package
set, nmap/wapiti/routersploit/commix rows resolve from PATH; installing
a binary never arms anything (the `*_DISPATCH_SCOPE` gate is separate).
