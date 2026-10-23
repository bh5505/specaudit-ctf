// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title LabTreasuryFixed
/// @notice Instructor-owned fixed variant of the shipped treasury
///         contract: identical surface, with the administrator check
///         restored on the payout-destination setter. Owned by the
///         challenge ground truth, not by the participant review.
contract TreasuryFixed {
    address public admin;
    address public treasury;
    address public feeCollector;

    constructor(address initialTreasury) {
        admin = msg.sender;
        treasury = initialTreasury;
        feeCollector = initialTreasury;
    }

    /// @notice Point the payout destination at `newTreasury`.
    function setTreasury(address newTreasury) external {
        require(msg.sender == admin, "admin only");
        treasury = newTreasury;
    }

    /// @notice Point the fee-collector destination at `newCollector`.
    function setFeeCollector(address newCollector) external {
        require(msg.sender == admin, "admin only");
        feeCollector = newCollector;
    }

    /// @notice Send `amount` of the held balance to the current
    ///         treasury destination.
    function payout(uint256 amount) external {
        require(amount <= address(this).balance, "insufficient balance");
        (bool ok, ) = treasury.call{value: amount}("");
        require(ok, "payout failed");
    }

    receive() external payable {}
}
