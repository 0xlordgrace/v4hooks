// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {BaseHook} from "@openzeppelin/uniswap-hooks/base/BaseHook.sol";

/// @notice Modeled on the Bunni v2 incident (Sept 2025): share accounting that rounds
/// in the user's favour on withdraw, so repeated small withdrawals drain idle balance.
/// Caller checks, pool validation and permission bits are all correct, so none of the
/// three V4H detectors should fire. This is a deliberate, labelled out-of-scope miss.
/// EXPECT: (none) -- out_of_scope: rounding
contract BunniStyleRoundingHook is BaseHook {
    using PoolIdLibrary for PoolKey;

    PoolId public immutable pool;
    uint256 public idleBalance;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(IPoolManager _poolManager, PoolKey memory key) BaseHook(_poolManager) {
        pool = key.toId();
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
    }

    function _beforeInitialize(address, PoolKey calldata key, uint160) internal view override returns (bytes4) {
        require(PoolId.unwrap(key.toId()) == PoolId.unwrap(pool), "wrong pool");
        return this.beforeInitialize.selector;
    }

    function withdraw(uint256 shareAmount) external returns (uint256 amount) {
        // BUG: rounds up in the withdrawer's favour.
        amount = (shareAmount * idleBalance + totalShares - 1) / totalShares;
        shares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        idleBalance -= amount;
    }
}
