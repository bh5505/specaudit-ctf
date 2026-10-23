// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Treasury} from "../planted/Treasury.sol";
import {TreasuryFixed} from "../instructor/TreasuryFixed.sol";

/// Minimal inline Vm cheatcode interface so the project builds fully
/// offline (no forge-std dependency). 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D
/// is Foundry's canonical cheatcode address; the declared functions must
/// match the cheatcode ABI selectors exactly.
interface Vm {
    function startPrank(address msgSender) external;
    function stopPrank() external;
}

/// The surface both variants share, cut down to what the invariant
/// needs: where the payout destination points, and who may move it.
/// Both shipped variants expose these functions with these signatures.
interface ITreasuryVariant {
    function treasury() external view returns (address);
    function setTreasury(address newTreasury) external;
}

/// Instructor-owned property witness (Fizz-informed invariant): "only
/// the administrator may change the treasury."
///
/// One property proves both directions. On the planted variant a
/// non-admin setTreasury call succeeds and redirects the payout
/// destination, so the property returns false and assertFalse catches
/// it. On the fixed variant the administrator guard reverts the same
/// call, so the property returns true. The suite is therefore green
/// exactly because the planted variant violates the invariant and the
/// fixed variant upholds it; a red run is the participant's cue that
/// the guard landed in the wrong place.
contract TreasuryPropertyTest {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    // Synthetic accounts only: the deployer (this test contract) becomes
    // admin in both constructors; NON_ADMIN is an arbitrary other address.
    address internal constant NON_ADMIN = address(0xA11CE);
    address internal constant ORIGINAL_TREASURY = address(0xBEEF);

    function _assertTrue(bool condition, string memory reason) internal pure {
        require(condition, reason);
    }

    function _assertFalse(bool condition, string memory reason) internal pure {
        require(!condition, reason);
    }

    /// The property: a non-admin call must not be able to change the
    /// treasury. Returns true when the invariant HOLDS, false when the
    /// unauthorized call redirected the payout destination.
    function _invariantHolds(address variantAddress) internal returns (bool) {
        ITreasuryVariant variant = ITreasuryVariant(variantAddress);
        vm.startPrank(NON_ADMIN);
        try variant.setTreasury(NON_ADMIN) {
            vm.stopPrank();
            // The unauthorized call went through; the invariant is
            // broken exactly if the payout destination actually moved.
            return variant.treasury() == ORIGINAL_TREASURY;
        } catch {
            vm.stopPrank();
            // The administrator guard reverted the change.
            return true;
        }
    }

    function test_PlantedVariantViolatesInvariant() public {
        Treasury planted = new Treasury(ORIGINAL_TREASURY);
        _assertFalse(
            _invariantHolds(address(planted)),
            "planted variant must violate the invariant: a non-admin call redirected the payout destination"
        );
    }

    function test_FixedVariantUpholdsInvariant() public {
        TreasuryFixed fixedVariant = new TreasuryFixed(ORIGINAL_TREASURY);
        _assertTrue(
            _invariantHolds(address(fixedVariant)),
            "fixed variant must uphold the invariant: the guard must revert a non-admin setTreasury"
        );
    }
}
