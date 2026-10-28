// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BaseHook} from "@openzeppelin/uniswap-hooks/base/BaseHook.sol";

/// @notice Correctly gated by PoolManager (via BaseHook), but it keeps one global
/// points ledger and never checks which pool is calling. Anyone can initialize a
/// pool of two worthless tokens with this hook and farm points by wash-trading it.
/// EXPECT: V4H-02 (afterSwap)
contract AnyPoolPointsHook is BaseHook {
    mapping(address => uint256) public points;
    uint256 public totalPoints;

    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
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

    function _afterSwap(address sender, PoolKey calldata, SwapParams calldata, BalanceDelta delta, bytes calldata)
        internal
        override
        returns (bytes4, int128)
    {
        _award(sender, delta);
        return (this.afterSwap.selector, 0);
    }

    function _award(address user, BalanceDelta delta) internal {
        int128 a0 = delta.amount0();
        uint256 amt = uint256(uint128(a0 < 0 ? -a0 : a0));
        points[user] += amt;
        totalPoints += amt;
    }
}
