# Local CTF lab

The scripts in this directory prepare a Kali WSL development instance and a disposable Debian target with an SSH banner and HTTP services. Run the shell scripts from Windows Git Bash; they call `wsl.exe`. Put machine-specific values in the gitignored `lab/local.conf` (see `local.example.conf`).

Set up the Kali instance and target image once:

```sh
lab/setup-kali.sh
wsl --install -d debian --no-launch
lab/build-golden.sh
```

Start a fresh target, use the printed IP in the arm commands you choose, and tear the target down when finished:

```sh
lab/spawn-target.sh
# From the Kali instance, for example:
python -m extension invoke nmap scan '{"target":"<target-ip>"}'
python -m extension invoke wapiti scan '{"url":"http://<target-ip>:8080/"}'
```

Back in Windows Git Bash:

```sh
lab/teardown-target.sh
```

The target serves static content on ports 8000 and 8080 and an SSH banner on port 22. It is disposable: `spawn-target.sh` imports a fresh copy of the golden image, and `teardown-target.sh` unregisters it. The target has no SSH login account. The scripts print the IP and command results; the human operator selects targets and is accountable for using the tools.

Optional installers (`install-zdns.sh`, `install-zgrab2.sh`, `install-vuls.sh`, `install-osmedeus.sh`, `install-page-fetch.sh`, `install-caldera.sh`, and `install-msf-mcp.sh`) add tools to the Kali instance. `zdns-measure.sh` checks a loopback DNS zone, `vuls-measure.sh` scans the Kali package inventory in local mode, and `osmedeus-measure.sh` compares the arm result with a direct engine run. These scripts measure the current command result; they do not grant or restrict target use.

`matrix-run.sh` and `matrix-variance.sh` exercise challenge attempts with a selected agent CLI. `EXERCISE_HEAD_CLAUDE_CODE_CMD`, `EXERCISE_HEAD_CODEX_CLI_CMD`, and `EXERCISE_HEAD_QWEN_CODE_CMD` are optional command-path overrides; the runner otherwise uses the usual CLI name from `PATH` when `--head-execute` is selected. The dated files under `lab/records/` are observations from earlier runs, not setup instructions for the current tool.
