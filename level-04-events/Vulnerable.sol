// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    mapping(address => uint256) public balances;
    event Transfer(address indexed from, address indexed to, uint256 value);

    // ✅ SAFE: Updates balance and emits Transfer event
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Transfer(address(0), msg.sender, msg.value);
    }

    // 🚩 VULNERABLE: Updates balance but forgets to emit event
    function adminAirdrop(address _to, uint256 _amount) public {
        balances[_to] += _amount;
        // Missing: emit Transfer(address(0), _to, _amount);
    }

    // ✅ SAFE: Does not change state, so no event needed
    function getBalance(address _user) public view returns (uint256) {
        return balances[_user];
    }
}