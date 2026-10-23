// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title LabTreasury
/// @notice Synthetic treasury/payout contract for a security-review
///         exercise. All balances, addresses, and amounts are fictional:
///         this contract is never deployed to any chain and holds
///         nothing of value. It exists so a reviewer has an honest
///         surface to read.
contract Treasury {
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
