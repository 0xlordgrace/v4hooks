// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./V4Stubs.sol";

// Shapes of the 2023 / early-2024 pre-release v4 API: Hooks.Calls flags returned by
// getHooksCalls(), modifyPosition instead of add/removeLiquidity, lockAcquired instead
// of unlockCallback.
struct ModifyPositionParams {
    int24 tickLower;
    int24 tickUpper;
    int256 liquidityDelta;
}

library Hooks2023 {
    struct Calls {
        bool beforeInitialize;
        bool afterInitialize;
        bool beforeModifyPosition;
        bool afterModifyPosition;
        bool beforeSwap;
        bool afterSwap;
        bool beforeDonate;
        bool afterDonate;
    }

    function validateHookAddress(address, Calls memory) internal pure {}
}

abstract contract BaseHook2023 {
    IPoolManager public immutable poolManager;

    error HookNotImplemented();

    constructor(IPoolManager m) {
        poolManager = m;
        Hooks2023.validateHookAddress(address(this), getHooksCalls());
    }

    function getHooksCalls() public pure virtual returns (Hooks2023.Calls memory);

    function beforeInitialize(address, PoolKey calldata, uint160) external virtual returns (bytes4) {
        revert HookNotImplemented();
    }

    function beforeModifyPosition(address, PoolKey calldata, ModifyPositionParams calldata)
        external
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function afterModifyPosition(address, PoolKey calldata, ModifyPositionParams calldata, int256)
        external
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function beforeSwap(address, PoolKey calldata, SwapParams calldata) external virtual returns (bytes4) {
        revert HookNotImplemented();
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, int256) external virtual returns (bytes4) {
        revert HookNotImplemented();
    }
}
