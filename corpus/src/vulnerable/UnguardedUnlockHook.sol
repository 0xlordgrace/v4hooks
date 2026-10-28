// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {IUnlockCallback} from "@uniswap/v4-core/src/interfaces/callback/IUnlockCallback.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {ModifyLiquidityParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {BaseHook} from "@openzeppelin/uniswap-hooks/base/BaseHook.sol";

/// @notice Bunni-style rebalancer: the hook unlocks the PoolManager to move its own
/// liquidity. unlockCallback trusts its `data` and never checks msg.sender, so anyone
/// can make the hook modify liquidity with attacker-chosen parameters.
/// EXPECT: V4H-01 (unlockCallback)
contract UnguardedUnlockHook is BaseHook, IUnlockCallback {
    using PoolIdLibrary for PoolKey;

    mapping(PoolId => bool) public managed;

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
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    function _beforeInitialize(address sender, PoolKey calldata key, uint160) internal override returns (bytes4) {
        require(sender == address(this), "only self-initialized pools");
        managed[key.toId()] = true;
        return this.beforeInitialize.selector;
    }

    function rebalance(PoolKey calldata key, ModifyLiquidityParams calldata params) external {
        require(managed[key.toId()], "unmanaged");
        poolManager.unlock(abi.encode(key, params));
    }

    // BUG: no msg.sender == poolManager check.
    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        (PoolKey memory key, ModifyLiquidityParams memory params) = abi.decode(data, (PoolKey, ModifyLiquidityParams));
        (bytes32 delta,) = _modify(key, params);
        return abi.encode(delta);
    }

    function _modify(PoolKey memory key, ModifyLiquidityParams memory params) internal returns (bytes32, bytes32) {
        (int256 a, int256 b) = (0, 0);
        poolManager.modifyLiquidity(key, params, "");
        return (bytes32(uint256(a)), bytes32(uint256(b)));
    }
}
