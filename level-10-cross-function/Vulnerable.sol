// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LogicContract {
    address public owner;
    bool public initialized;

    // 🚩 VULNERABLE: Sensitive setup but forgets to check 'initialized'
    function setup(address _owner) public {
        owner = _owner;
        initialized = true;
    }
}

contract SecureLogic {
    address public owner;
    bool public initialized;

    // ✅ SAFE: Properly guarded
    function initialize(address _owner) public {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }
}