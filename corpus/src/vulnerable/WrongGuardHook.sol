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

/// @notice The callback *has* a sender check, but against the wrong principal: it
/// checks the router/owner instead of the PoolManager, so the owner (or anyone the
/// owner forwards for) can fabricate swap events.
/// EXPECT: V4H-01 (afterSwap)
contract WrongGuardHook is TrivialHooks {
    using PoolIdLibrary for PoolKey;

    IPoolManager public immutable poolManager;
    address public owner;
    PoolId public immutable servedPool;
    mapping(address => uint256) public points;

    constructor(IPoolManager _poolManager, PoolKey memory key) {
        poolManager = _poolManager;
        owner = msg.sender;
        servedPool = key.toId();
        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    // BUG: gated by owner, not PoolManager.
    function afterSwap(address sender, PoolKey calldata key, SwapParams calldata, BalanceDelta delta, bytes calldata)
        external
        override
        onlyOwner
        returns (bytes4, int128)
    {
        require(PoolId.unwrap(key.toId()) == PoolId.unwrap(servedPool), "wrong pool");
        points[sender] += uint256(uint128(delta.amount0() < 0 ? -delta.amount0() : delta.amount0()));
        return (IHooks.afterSwap.selector, 0);
    }
}
