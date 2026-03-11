// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Bank {
    mapping(address => uint256) public balances;

    // ✅ SAFE: Has a require guard
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success);
    }

    // 🚩 VULNERABLE: Performs a call without any preceding require/assert
    function unprotectedCall(address _target, bytes memory _data) public {
        (bool success, ) = _target.call(_data);
        require(success);
    }
}