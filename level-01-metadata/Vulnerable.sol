// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Bank {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // THIS SHOULD BE FLAGGED
    function debug_resetBalance(address user) public {
        balances[user] = 0;
    }

    // THIS SHOULD BE FLAGGED
    function test_addFunds() public {
        balances[msg.sender] += 100 ether;
    }
}