// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ✅ Standard ERC20-like
contract GoodToken {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    function transfer(address _to, uint256 _amount) public returns (bool) {
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        return true;
    }
}

// 🚩 VULNERABLE: Missing the 'bool' return value (Common in older tokens like USDT)
contract BadToken {
    uint256 public totalSupply;
    mapping(address => uint256) public balances;

    function transfer(address _to, uint256 _amount) public {
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
        // No return statement!
    }
}

// 🚩 VULNERABLE: Wrong parameter types
contract WrongParams {
    uint256 public totalSupply;

    function transfer(uint256 _amount, address _to) public returns (bool) {
        return true;
    }
}