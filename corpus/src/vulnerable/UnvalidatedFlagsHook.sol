// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {IHooks} from "@uniswap/v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {TrivialHooks} from "../common/TrivialHooks.sol";

/// @notice Hand-rolled hook that declares permissions but never checks them against
/// its own address (no Hooks.validateHookPermissions). If it is deployed to an
/// address whose low bits don't match, afterSwap is silently never called.
/// EXPECT: V4H-03 (getHookPermissions)
contract UnvalidatedFlagsHook is TrivialHooks {
    using PoolIdLibrary for PoolKey;

    IPoolManager public immutable poolManager;
    mapping(PoolId => uint256) public volume;

    constructor(IPoolManager _poolManager) {
        poolManager = _poolManager;
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function afterSwap(address, PoolKey calldata key, SwapParams calldata, BalanceDelta delta, bytes calldata)
        external
        override
        returns (bytes4, int128)
    {
        require(msg.sender == address(poolManager), "not pool manager");
        int128 a0 = delta.amount0();
        volume[key.toId()] += uint256(uint128(a0 < 0 ? -a0 : a0));
        return (IHooks.afterSwap.selector, 0);
    }
}
