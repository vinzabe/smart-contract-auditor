// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Intentionally vulnerable savings vault — for auditor demos only.
/// Bugs:
///   1. Reentrancy in withdraw() (external call before state update)
///   2. tx.origin auth in setOwner()
///   3. Block timestamp dependence in claimBonus()
///   4. Unchecked low-level call in adminCall()
contract Vault {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastClaim;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @dev Reentrancy: send Ether before zeroing the balance.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] -= amount;
    }

    /// @dev tx.origin authentication is wrong.
    function setOwner(address newOwner) external {
        require(tx.origin == owner, "not owner");
        owner = newOwner;
    }

    /// @dev block.timestamp can be biased by miners.
    function claimBonus() external {
        require(block.timestamp - lastClaim[msg.sender] > 1 days, "too soon");
        lastClaim[msg.sender] = block.timestamp;
        balances[msg.sender] += 1 ether;
    }

    /// @dev Unchecked low-level call.
    function adminCall(address target, bytes calldata data) external {
        require(msg.sender == owner, "not owner");
        target.call(data);  // ignored returncode
    }
}
