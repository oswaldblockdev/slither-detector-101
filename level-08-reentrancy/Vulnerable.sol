// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyVault {
    mapping(address => uint256) public balances;

    // 🚩 VULNERABLE: Interaction (call) happens BEFORE Effect (balance = 0)
    function withdrawAll() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0);

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);

        balances[msg.sender] = 0; // State write after call!
    }

    // ✅ SAFE: Effect (balance = 0) happens BEFORE Interaction (call)
    function safeWithdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0);

        balances[msg.sender] = 0; // Effect first

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}