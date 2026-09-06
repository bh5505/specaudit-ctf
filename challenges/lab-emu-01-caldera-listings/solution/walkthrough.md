# Lab Emu 01 — walkthrough

## 1. Stand up the server

`lab/install-caldera.sh` pins apache/caldera release tag 5.3.0, clones
with submodules (stockpile ships the ability catalog as data), installs
requirements into a venv, and starts `python3 server.py --insecure` —
without `--build`, which is the npm-driven UI step the API plane does
not need. The server listens on 127.0.0.1:8888 (allow ~40s).

## 2. Read through the arm

With `CALDERA_ENDPOINT=http://127.0.0.1:8888` and
`CALDERA_API_KEY=ADMIN123`:

- `caldera abilities` returns the stockpile ability inventory —
  thousands of ATT&CK-mapped abilities, one authenticated call.
- `caldera agents` returns `[]` on a fresh server — the enrolled
  population is empty.
- `caldera adversaries` returns the shipped adversary profiles.

## 3. The boundary probe

Set `CALDERA_API_KEY=wrong-key` and retry the agents read: the arm's
call fails with the server's 401 — the attestation row's evidence.

## 4. The four rows

1. **demo-emu-caldera-abilities-inventoried (low).** The catalog is
   the server's own shipped data — the exposure is that one
   authenticated call yields the full target-selection inventory.
2. **demo-emu-caldera-default-red-key (high).** `api_key_red:
   ADMIN123` ships in conf/default.yml; the finding grades the shipped
   default, and the runbook says rotate on anything non-disposable.
3. **demo-emu-caldera-unauthenticated-refused (none).** The 401
   observation, stated as an attestation.
4. **demo-emu-caldera-no-agents-enrolled (none).** Empty listing,
   absence phrased explicitly.

## 5. Grade and run

Grade the found document against the contract, then run the runner
cell with the three caldera reads as the arms lane. Grading 1.0 with
arms 3/3 and `complete` envelopes is the full cell.
