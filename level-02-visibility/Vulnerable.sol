// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    address public owner;
    uint256 public rewardRate;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // ✅ SAFE: Has modifier
    function setOwner(address _newOwner) public onlyOwner {
        owner = _newOwner;
    }

    // 🚩 VULNERABLE: Public, changes state, NO modifier
    function updateRewardRate(uint256 _newRate) external {
        rewardRate = _newRate;
    }

    // ✅ SAFE: No state change (View function)
    function getRate() public view returns (uint256) {
        return rewardRate;
    }
}