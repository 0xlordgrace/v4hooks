// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {Currency} from "@uniswap/v4-core/src/types/Currency.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BaseHook} from "@openzeppelin/uniswap-hooks/base/BaseHook.sol";

/// @notice The author wrote a pool allowlist in _beforeInitialize but left the
/// beforeInitialize permission bit false, so the PoolManager never calls it. The
/// guard is dead code and any pool can attach to the hook's shared deposit ledger.
/// EXPECT: V4H-03 (beforeInitialize), V4H-02 (afterAddLiquidity)
contract DeadInitGuardHook is BaseHook {
    Currency public immutable allowedToken;
    uint256 public totalDeposits;

    constructor(IPoolManager _poolManager, Currency _allowedToken) BaseHook(_poolManager) {
        allowedToken = _allowedToken;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false, // BUG: should be true
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: true,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    function _beforeInitialize(address, PoolKey calldata key, uint160) internal view override returns (bytes4) {
        require(key.currency0 == allowedToken || key.currency1 == allowedToken, "pool not allowed");
        return this.beforeInitialize.selector;
    }

    function _afterAddLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata params,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) internal override returns (bytes4, BalanceDelta) {
        if (params.liquidityDelta > 0) totalDeposits += uint256(params.liquidityDelta);
        return (this.afterAddLiquidity.selector, BalanceDelta.wrap(0));
    }
}
