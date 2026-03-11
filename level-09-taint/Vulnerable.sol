// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Proxy {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    // 🚩 VULNERABLE: The destination '_target' comes from the user
    function execute(address _target, bytes memory _data) public {
        require(msg.sender == admin);
        (bool success, ) = _target.call(_data);
        require(success);
    }

    // ✅ SAFE: The destination is a hardcoded/state variable (not tainted by input)
    function callAdmin() public {
        (bool success, ) = admin.call("");
        require(success);
    }
}