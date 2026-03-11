// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Destroyer {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // 🚩 VULNERABLE: Direct selfdestruct usage
    function kill() public {
        require(msg.sender == owner);
        selfdestruct(payable(owner));
    }

    // 🚩 VULNERABLE: Aliased or hidden usage
    // Even if we use an old name or unusual syntax, SlithIR sees it.
    function hiddenKill(address payable _target) public {
        require(msg.sender == owner);
        address payable addr = _target;
        selfdestruct(addr);
    }
}

contract Safe {
    // ✅ SAFE: No destructive opcodes here
    function withdraw() public pure returns (string memory) {
        return "Nothing to see here";
    }
}