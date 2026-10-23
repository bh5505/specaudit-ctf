# Property witness — recorded run

Instructor-owned witness for the Fizz-informed invariant **"only the
administrator may change the treasury"** (`test/TreasuryProperty.t.sol`).
This file records what actually ran, with the actual output.

## Toolchain and commands

- forge 1.8.6 (commit `6bad0a66de7c83f7b33695044138f0f5fa4c5990`, build
  2026-10-21), Solc `0.8.28`, EVM version `cancun` (both pinned in
  `foundry.toml`).
- The project declares no remappings, libraries, or dependencies: the
  test declares the two Vm cheatcode functions it needs inline
  (`startPrank(address)`, `stopPrank()` at Foundry's canonical cheatcode
  address `0x7109709ECfa91a80626fF3989D68f67F5b1DD12D`), so the build
  needs no `lib/` and no network beyond the compiler binary itself.

```sh
export PATH="$HOME/.foundry/bin:$PATH"
cd challenges/lab-contract-01-solidity-review
forge build
forge test
```

## Recorded output (verbatim)

```text
forge Version: 1.8.6
Commit SHA: 6bad0a66de7c83f7b33695044138f0f5fa4c5990
Build Timestamp: 2026-10-21T17:38:09.096593000Z (1792604289)
Build Profile: dist

Compiling 3 files with Solc 0.8.28
Solc 0.8.28 finished in 57.15ms
Compiler run successful!
warning[missing-zero-check]: address parameter is used in a state write or value transfer without a zero-address check
   ╭▸ planted/Treasury.sol:15:17
   │
15 │     constructor(address initialTreasury) {
   │                 ━━━━━━━━━━━━━━━━━━━━━━━
   │
   ╰ help: https://getfoundry.sh/forge/linting/missing-zero-check

warning[missing-zero-check]: address parameter is used in a state write or value transfer without a zero-address check
   ╭▸ planted/Treasury.sol:22:26
   │
22 │     function setTreasury(address newTreasury) external {
   │                          ━━━━━━━━━━━━━━━━━━━
   │
   ╰ help: https://getfoundry.sh/forge/linting/missing-zero-check

warning[missing-zero-check]: address parameter is used in a state write or value transfer without a zero-address check
   ╭▸ planted/Treasury.sol:27:30
   │
27 │     function setFeeCollector(address newCollector) external {
   │                              ━━━━━━━━━━━━━━━━━━━━
   │
   ╰ help: https://getfoundry.sh/forge/linting/missing-zero-check

warning[arbitrary-send-eth]: ETH is sent to a user-controlled destination; restrict the destination or the caller
   ╭▸ planted/Treasury.sol:36:23
   │
36 │         (bool ok, ) = treasury.call{value: amount}("");
   │                       ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   │
   ╰ help: https://getfoundry.sh/forge/linting/arbitrary-send-eth


No files changed, compilation skipped

Ran 2 tests for test/TreasuryProperty.t.sol:TreasuryPropertyTest
[PASS] test_FixedVariantUpholdsInvariant() (gas: 588147)
[PASS] test_PlantedVariantViolatesInvariant() (gas: 35544)
Suite result: ok. 2 passed; 0 failed; 0 skipped; finished in 1.17ms (1.40ms CPU time)

Ran 1 test suite in 4.87ms (1.17ms CPU time): 2 tests passed, 0 failed, 0 skipped (2 total tests)
```

(The forge linter's warnings on the shipped file are recorded as they
occurred. They name the same constructs the expected finding does; they
are static-analysis output, not the CTF verdict.)

## Semantics: why a green suite is the witness

The suite is green **exactly because it asserts the two directions of
the invariant**:

- `test_PlantedVariantViolatesInvariant` — a non-admin call to
  `setTreasury` on the planted variant **succeeds and redirects** the
  payout destination, so the property returns `false`, and the test's
  `assertFalse` turns that violation into a passing assertion.
- `test_FixedVariantUpholdsInvariant` — the same call on the fixed
  variant **reverts** at the administrator guard, so the property
  returns `true` and `assertTrue` holds.

A red `test_PlantedVariantViolatesInvariant` means the shipped file no
longer carries the defect (or the property regressed); a red
`test_FixedVariantUpholdsInvariant` means the fixed variant lost its
guard. Both were verified to behave that way.

## Discrimination check (throwaway copy, not part of the challenge)

As a one-off control outside this deliverable, the planted file in a
disposable copy was given the same guard as the fixed variant, and the
suite turned red exactly as intended:

```text
[PASS] test_FixedVariantUpholdsInvariant() (gas: 588147)
[FAIL: planted variant must violate the invariant: a non-admin call redirected the payout destination] test_PlantedVariantViolatesInvariant() (gas: 30312)
Suite result: FAILED. 1 passed; 1 failed; 0 skipped; finished in 1.85ms (1.92ms CPU time)
```

## What this witness does and does not prove

The witness demonstrates the planted condition on the synthetic
contract: an unauthorized caller can move the payout destination. It is
instructor evidence, not a participant's grade: a fuzz/property failure
in a participant's own harness is **not** proof of impact, and the
source-based CTF grade is decided only by the `score` grader against
`artifacts/expected-findings.json`. No RPC, chain, real token, or funded
account is involved anywhere in this run.
