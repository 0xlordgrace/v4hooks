// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BaseHook} from "@openzeppelin/uniswap-hooks/base/BaseHook.sol";

/// @notice Fixed version of AnyPoolPointsHook: binds itself to one pool in
/// beforeInitialize (flag enabled) and re-checks the pool id in afterSwap.
/// EXPECT: (none)
contract SinglePoolGuardedHook is BaseHook {
    using PoolIdLibrary for PoolKey;

    PoolId public servedPool;
    bool public initialized;
    mapping(address => uint256) public points;
    uint256 public totalPoints;

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: true,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    function _beforeInitialize(address, PoolKey calldata key, uint160) internal override returns (bytes4) {
        require(!initialized, "already bound");
        initialized = true;
        servedPool = key.toId();
        return this.beforeInitialize.selector;
    }

    function _afterSwap(address sender, PoolKey calldata key, SwapParams calldata, BalanceDelta delta, bytes calldata)
        internal
        override
        returns (bytes4, int128)
    {
        if (PoolId.unwrap(key.toId()) != PoolId.unwrap(servedPool)) revert("wrong pool");
        int128 a0 = delta.amount0();
        uint256 amt = uint256(uint128(a0 < 0 ? -a0 : a0));
        points[sender] += amt;
        totalPoints += amt;
        return (this.afterSwap.selector, 0);
    }
}
