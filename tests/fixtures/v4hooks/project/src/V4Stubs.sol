// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// Minimal stand-ins for v4-core / OZ BaseHook with the same names, shapes and
// control flow the detectors rely on.
type PoolId is bytes32;
type Currency is address;

struct PoolKey {
    Currency currency0;
    Currency currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

struct ModifyLiquidityParams {
    int24 tickLower;
    int24 tickUpper;
    int256 liquidityDelta;
    bytes32 salt;
}

struct SwapParams {
    bool zeroForOne;
    int256 amountSpecified;
    uint160 sqrtPriceLimitX96;
}

library PoolIdLibrary {
    function toId(PoolKey memory key) internal pure returns (PoolId) {
        return PoolId.wrap(keccak256(abi.encode(key)));
    }
}

library CurrencyLib {
    function transfer(Currency, address, uint256) internal {}
}

interface IPoolManager {
    function unlock(bytes calldata) external returns (bytes memory);
    function initialize(PoolKey memory key, uint160 sqrtPriceX96) external returns (int24);
    function take(Currency currency, address to, uint256 amount) external;
    function sync(Currency currency) external;
    function settle() external payable returns (uint256);
    function swap(PoolKey memory key, SwapParams memory params, bytes calldata hookData) external returns (int256);
}

/// Shape of v4-core's test-utils CurrencySettler: the payer's tokens go to the PoolManager.
library CurrencySettler {
    function settle(Currency currency, IPoolManager manager, address payer, uint256 amount) internal {
        manager.sync(currency);
        if (payer == address(this)) CurrencyLib.transfer(currency, address(manager), amount);
        manager.settle();
    }
}

interface IHooks {
    function beforeInitialize(address, PoolKey calldata, uint160) external returns (bytes4);
    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata) external returns (bytes4);
    function afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        external
        returns (bytes4);
}

library Hooks {
    struct Permissions {
        bool beforeInitialize;
        bool afterInitialize;
        bool beforeAddLiquidity;
        bool afterAddLiquidity;
        bool beforeRemoveLiquidity;
        bool afterRemoveLiquidity;
        bool beforeSwap;
        bool afterSwap;
        bool beforeDonate;
        bool afterDonate;
        bool beforeSwapReturnDelta;
        bool afterSwapReturnDelta;
        bool afterAddLiquidityReturnDelta;
        bool afterRemoveLiquidityReturnDelta;
    }

    function validateHookPermissions(IHooks, Permissions memory) internal pure {}
}

abstract contract BaseHook is IHooks {
    IPoolManager public immutable poolManager;

    error HookNotImplemented();
    error NotPoolManager();

    constructor(IPoolManager m) {
        poolManager = m;
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    modifier onlyPoolManager() {
        if (msg.sender != address(poolManager)) revert NotPoolManager();
        _;
    }

    function getHookPermissions() public pure virtual returns (Hooks.Permissions memory);

    function beforeInitialize(address s, PoolKey calldata k, uint160 p) external onlyPoolManager returns (bytes4) {
        return _beforeInitialize(s, k, p);
    }

    function _beforeInitialize(address, PoolKey calldata, uint160) internal virtual returns (bytes4) {
        revert HookNotImplemented();
    }

    function afterInitialize(address s, PoolKey calldata k, uint160 p, int24 t)
        external
        onlyPoolManager
        returns (bytes4)
    {
        return _afterInitialize(s, k, p, t);
    }

    function _afterInitialize(address, PoolKey calldata, uint160, int24) internal virtual returns (bytes4) {
        revert HookNotImplemented();
    }

    function beforeAddLiquidity(address s, PoolKey calldata k, ModifyLiquidityParams calldata p, bytes calldata d)
        external
        onlyPoolManager
        returns (bytes4)
    {
        return _beforeAddLiquidity(s, k, p, d);
    }

    function _beforeAddLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        internal
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function beforeRemoveLiquidity(address s, PoolKey calldata k, ModifyLiquidityParams calldata p, bytes calldata d)
        external
        onlyPoolManager
        returns (bytes4)
    {
        return _beforeRemoveLiquidity(s, k, p, d);
    }

    function _beforeRemoveLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        internal
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function beforeDonate(address s, PoolKey calldata k, uint256 a0, uint256 a1, bytes calldata d)
        external
        onlyPoolManager
        returns (bytes4)
    {
        return _beforeDonate(s, k, a0, a1, d);
    }

    function _beforeDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        internal
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function beforeSwap(address s, PoolKey calldata k, SwapParams calldata p, bytes calldata d)
        external
        onlyPoolManager
        returns (bytes4)
    {
        return _beforeSwap(s, k, p, d);
    }

    function _beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        internal
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }

    function afterSwap(address s, PoolKey calldata k, SwapParams calldata p, int256 d, bytes calldata h)
        external
        onlyPoolManager
        returns (bytes4)
    {
        return _afterSwap(s, k, p, d, h);
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        virtual
        returns (bytes4)
    {
        revert HookNotImplemented();
    }
}
