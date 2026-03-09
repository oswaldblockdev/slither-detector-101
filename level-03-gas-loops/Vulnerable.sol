// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GasSuck {
    address[] public investors;

    function addInvestor(address _inv) public {
        investors.push(_inv);
    }

    // 🚩 VULNERABLE: Will break once 'investors' is too large
    function payout() public {
        for (uint i = 0; i < investors.length; i++) {
            // transfer logic...
        }
    }

    // ✅ SAFE: Fixed length
    function constantLoop() public pure {
        uint[10] memory fixedArr;
        for (uint i = 0; i < 10; i++) {
            fixedArr[i] = i;
        }
    }
}