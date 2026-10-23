# Lab Contract 01 — instructor explanation

Instructor ground truth for the planted Solidity review. Participant-facing
material is `../METHODOLOGY.md` and `../README.md`; the graded contract is
`../artifacts/expected-findings.json`.

## The planted defect

`planted/Treasury.sol` — `setTreasury(address)`:

```solidity
function setTreasury(address newTreasury) external {
    treasury = newTreasury;
}
```

The contract's own model makes `admin` the administrator: the constructor
records the deployer, and the sibling setter `setFeeCollector` guards itself
with `require(msg.sender == admin, "admin only")`. `setTreasury` carries no
such check, so **any** external caller can rewrite `treasury` — the payout
destination — to an arbitrary address.

## Impact chain

1. An unauthorized caller invokes `setTreasury(attacker)`. The call succeeds
   and stores the attacker-chosen address in the `treasury` state variable.
2. The payout path `payout(uint256)` sends `amount` of the contract's held
   balance with `treasury.call{value: amount}("")` — it pays **whatever
   address the state variable now names**.
3. Funds therefore leave the contract to the attacker-chosen address on the
   next payout; the legitimate destination never sees them.

No privilege, role, or timelock anywhere else in the contract interrupts the
chain: the only protection that could have done so is the missing check
itself. This is a direct-theft primitive on the synthetic balance, rated
**high** in the expected contract.

## Why the near miss is benign

`setFeeCollector(address)` looks like the defect — same shape, same setter
family — but it **is** guarded by `require(msg.sender == admin, "admin only")`.
A reviewer who pattern-matches on "setter function present" without reading
the guard will report it; that report is the deliberate false-positive trap.
It is benign as shipped, and it is also the evidence that the administrator
check was intended here too: the codebase already knew the pattern for the
sibling destination.

## What the one expected finding covers

Exactly **one** finding, key `treasury-setter-unauthorized`, and it covers
the whole setter-to-payout chain — both constructs in `traces_to`:

- the `setTreasury(address)` setter without an administrator check, and
- the `payout()` path that pays the redirected treasury.

A submission that names only the setter, or only the payout sink, or that
adds the near miss as its own finding, does not pass (miss, miss, and extra
respectively under `score/grading.py`).

## Supporting material the instructor owns

- `TreasuryFixed.sol` — the fixed variant: identical surface with the
  administrator check restored on `setTreasury`.
- `../test/TreasuryProperty.t.sol` — the property witness for the invariant
  "only the administrator may change the treasury"; see
  `../artifacts/property-witness.md` for the recorded offline run.
- The severity calibration: high, not critical, because the synthetic
  contract holds only the balance it is explicitly sent in this lab and the
  exercise never deploys it anywhere.

The instructor separately reviews the truth of a participant's `traces_to`
prose: the grader checks ownership and shape of the evidence, not whether a
nonempty trace names real constructs.
