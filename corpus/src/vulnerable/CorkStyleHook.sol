// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {TrivialHooks} from "../common/TrivialHooks.sol";

/// @notice Modeled on the access-control failure class behind the Cork Protocol
/// incident (May 2025): a hand-rolled hook whose swap callback moves hook-held
/// value based on caller-supplied PoolKey/hookData, with no PoolManager gate and
/// no restriction on which pools may attach to it.
/// EXPECT: V4H-01 (beforeSwap), V4H-02 (beforeSwap)
contract CorkStyleHook is TrivialHooks {
    IPoolManager public immutable poolManager;
    uint256 public reserveBalance;

    constructor(IPoolManager _poolManager) {
        poolManager = _poolManager;
        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // BUG: no onlyPoolManager -- anyone can call this directly with a forged key.
    function beforeSwap(address, PoolKey calldata key, SwapParams calldata params, bytes calldata hookData)
        external
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        address recipient = abi.decode(hookData, (address));
        uint256 amount = params.amountSpecified < 0 ? uint256(-params.amountSpecified) : uint256(params.amountSpecified);
        // Global (not per-pool) accounting written for any pool that uses this hook.
        reserveBalance -= amount;
        Currency.unwrap(key.currency1) == address(0)
            ? payable(recipient).transfer(amount)
            : key.currency1.transfer(recipient, amount);
        return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }
}
