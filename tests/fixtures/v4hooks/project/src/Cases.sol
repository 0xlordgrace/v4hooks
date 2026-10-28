// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./V4Stubs.sol";
import "./V4Stubs2023.sol";

// Pos_NN_* must be flagged by detector V4H-NN; Neg_NN_* must not be flagged by
// V4H-NN (other detectors may legitimately fire on them).

/// Hand-rolled hook (no BaseHook): helpers shared by the raw cases below.
abstract contract RawHook is IHooks {
    IPoolManager public poolManager;
    address public owner;
    uint256 public total;

    function beforeInitialize(address, PoolKey calldata, uint160) external virtual returns (bytes4) {
        return IHooks.beforeInitialize.selector;
    }

    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        virtual
        returns (bytes4)
    {
        return IHooks.beforeSwap.selector;
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        external
        virtual
        returns (bytes4)
    {
        return IHooks.afterSwap.selector;
    }

    function _perms(bool swapFlag) internal pure returns (Hooks.Permissions memory p) {
        p.beforeSwap = swapFlag;
    }
}

// ── V4H-01 ──────────────────────────────────────────────────────────────────

contract Pos_01_NoCheck is RawHook {
    constructor() {
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        override
        returns (bytes4)
    {
        total += 1;
        return IHooks.beforeSwap.selector;
    }
}

contract Pos_01_OwnerCheck is RawHook {
    constructor() {
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        override
        returns (bytes4)
    {
        require(msg.sender == owner, "owner");
        total += 1;
        return IHooks.beforeSwap.selector;
    }
}

contract Pos_01_UnlockCallback is RawHook {
    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        total += data.length;
        return data;
    }
}

contract Neg_01_InlineRequire is RawHook {
    constructor() {
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        override
        returns (bytes4)
    {
        require(msg.sender == address(poolManager), "pm");
        total += 1;
        return IHooks.beforeSwap.selector;
    }
}

contract Neg_01_GuardInHelper is RawHook {
    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        _onlyPM();
        total += data.length;
        return data;
    }

    function _onlyPM() internal view {
        if (msg.sender != address(poolManager)) revert("pm");
    }
}

contract Neg_01_UnusedNoop is RawHook {
    // beforeInitialize/beforeSwap/afterSwap are inherited no-ops returning their
    // selector, with no flags set: nothing to protect, not flagged.
    constructor() {
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {}
}

// ── V4H-02 ──────────────────────────────────────────────────────────────────

contract Pos_02_GlobalLedger is BaseHook {
    using PoolIdLibrary for PoolKey;

    mapping(address => uint256) public points;

    constructor(IPoolManager m) BaseHook(m) {}

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

    function _afterSwap(address sender, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        points[sender] += 1;
        return this.afterSwap.selector;
    }
}

contract Pos_02_KeyCurrencyTransfer is BaseHook {
    using CurrencyLib for Currency;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata, bytes calldata d)
        internal
        override
        returns (bytes4)
    {
        key.currency0.transfer(abi.decode(d, (address)), 1 ether);
        return this.beforeSwap.selector;
    }
}

contract Neg_02_PerPoolState is BaseHook {
    using PoolIdLibrary for PoolKey;

    mapping(PoolId => uint256) public swaps;
    mapping(bytes32 => uint256) public orders;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        swaps[key.toId()] += 1;
        orders[keccak256(abi.encode(key, 1))] += 1;
        return this.afterSwap.selector;
    }
}

contract Neg_02_InitGate is BaseHook {
    PoolId public pool;
    bool public bound;
    uint256 public total;

    using PoolIdLibrary for PoolKey;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
        p.afterSwap = true;
    }

    function _beforeInitialize(address, PoolKey calldata key, uint160) internal override returns (bytes4) {
        require(!bound, "bound");
        bound = true;
        pool = key.toId();
        return this.beforeInitialize.selector;
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        total += 1;
        return this.afterSwap.selector;
    }
}

contract Neg_02_CallbackChecksKey is BaseHook {
    uint256 public total;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        require(key.hooks == address(this) && Currency.unwrap(key.currency0) == address(0), "pool");
        total += 1;
        return this.afterSwap.selector;
    }
}

// ── V4H-03 ──────────────────────────────────────────────────────────────────

contract Pos_03_FlagNoImpl is BaseHook {
    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }
}

contract Pos_03_ImplNoFlag is BaseHook {
    PoolId public allowed;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {}

    function _beforeInitialize(address, PoolKey calldata key, uint160) internal view override returns (bytes4) {
        require(key.hooks == address(this), "x");
        return this.beforeInitialize.selector;
    }
}

contract Pos_03_DeltaWithoutBase is BaseHook {
    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        // positional form
        return Hooks.Permissions(false, false, false, false, false, false, false, false, false, false, true, false, false, false);
    }
}

contract Pos_03_NeverValidated is RawHook {
    function getHookPermissions() public pure returns (Hooks.Permissions memory) {
        return _perms(false);
    }
}

contract Neg_03_DeliberateRevert is BaseHook {
    error SwapsDisabled();

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    // Intentional: block swaps. Not the BaseHook placeholder.
    function _beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        internal
        pure
        override
        returns (bytes4)
    {
        revert SwapsDisabled();
    }
}

// ── Regressions from the held-out set (benchmarks/v4hooks-heldout) ───────────

/// v4-core DynamicReturnFeeTestHook: unguarded, but `view`, so a caller can change nothing.
contract Neg_01_ViewCallback is RawHook {
    uint24 public fee;

    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        view
        override
        returns (bytes4)
    {
        return fee > 0 ? IHooks.beforeSwap.selector : bytes4(0);
    }
}

/// Clanker: beforeInitialize always reverts, so only the hook itself can create a pool
/// (PoolManager skips hook calls when the hook is the caller).
contract Neg_02_RevertingInitGate is BaseHook {
    error UnsupportedInitializePath();

    uint256 public total;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
        p.afterSwap = true;
    }

    function initializePool(PoolKey calldata key) external {
        poolManager.initialize(key, 1 << 96);
    }

    function _beforeInitialize(address, PoolKey calldata, uint160) internal pure override returns (bytes4) {
        revert UnsupportedInitializePath();
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        total += 1;
        return this.afterSwap.selector;
    }
}

library InitGateLib {
    error Unauthorized();

    function checkCaller(address caller, address hub) external pure {
        if (caller != hub) revert Unauthorized();
    }
}

/// Bunni: the pool gate lives in afterInitialize, inside an external library.
contract Neg_02_AfterInitGate is BaseHook {
    address public immutable hub;
    uint256 public total;

    constructor(IPoolManager m, address h) BaseHook(m) {
        hub = h;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterInitialize = true;
        p.afterSwap = true;
    }

    function _afterInitialize(address caller, PoolKey calldata, uint160, int24) internal view override returns (bytes4) {
        InitGateLib.checkCaller(caller, hub);
        return this.afterInitialize.selector;
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        total += 1;
        return this.afterSwap.selector;
    }
}

/// v4-core CustomCurveHook / DeltaReturningHook: pays the swapper out of the hook's own
/// inventory, in a currency picked from the key and passed through a local and a helper.
contract Pos_02_InventoryPayout is BaseHook {
    using CurrencySettler for Currency;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
        p.beforeSwapReturnDelta = true;
    }

    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        (Currency input, Currency output) = params.zeroForOne ? (key.currency0, key.currency1) : (key.currency1, key.currency0);
        uint256 amount = uint256(-params.amountSpecified);
        poolManager.take(input, address(this), amount);
        _pay(output, amount);
        return this.beforeSwap.selector;
    }

    function _pay(Currency c, uint256 amount) internal {
        c.settle(poolManager, address(this), amount);
    }
}

/// v4-core FeeTakingHook: only ever takes INTO the hook; no pool can drain it.
contract Neg_02_FeeTakeOnly is BaseHook {
    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, int256 delta, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        poolManager.take(key.currency1, address(this), uint256(delta > 0 ? delta : -delta) / 100);
        return this.afterSwap.selector;
    }
}

/// v4-core MockHooks: afterInitialize records into storage shared by every pool.
contract Pos_02_InitGlobalWrite is BaseHook {
    uint160 public lastPrice;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterInitialize = true;
    }

    function _afterInitialize(address, PoolKey calldata, uint160 price, int24) internal override returns (bytes4) {
        lastPrice = price;
        return this.afterInitialize.selector;
    }
}

/// Uniswap StablePairHook: afterInitialize is the placeholder, but beforeInitialize
/// rejects everyone and the hook creates its own pool, so it can never run.
contract Neg_03_UnreachableAfterInit is BaseHook {
    error InvalidInitializer(address);

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
        p.afterInitialize = true;
    }

    function initializePool(PoolKey calldata key) external {
        poolManager.initialize(key, 1 << 96);
    }

    function _beforeInitialize(address sender, PoolKey calldata, uint160) internal pure override returns (bytes4) {
        revert InvalidInitializer(sender);
    }
}

/// EulerSwap: a custom curve that keeps BaseHook's reverts on beforeInitialize (it
/// initializes its own pool), before{Add,Remove}Liquidity and beforeDonate on purpose.
contract Neg_03_CustomCurveBlocks is BaseHook {
    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
        p.beforeAddLiquidity = true;
        p.beforeRemoveLiquidity = true;
        p.beforeDonate = true;
        p.beforeSwap = true;
        p.beforeSwapReturnDelta = true;
    }

    function activate(PoolKey calldata key) external {
        poolManager.initialize(key, 1 << 96);
    }

    function _beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        internal
        pure
        override
        returns (bytes4)
    {
        return this.beforeSwap.selector;
    }
}

/// beforeInitialize placeholder with no self-initialization path: no pool can ever exist.
contract Pos_03_InitPlaceholderNoSelfInit is BaseHook {
    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
    }
}

/// afterInitialize placeholder while anyone may initialize: every pool creation reverts.
contract Pos_03_AfterInitPlaceholder is BaseHook {
    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterInitialize = true;
    }
}

/// Not a custom curve (no beforeSwapReturnDelta): a beforeAddLiquidity placeholder bricks LPs.
contract Pos_03_AddLiquidityPlaceholder is BaseHook {
    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeAddLiquidity = true;
    }
}

// ── Regressions from held-out set 2 (benchmarks/v4hooks-heldout2) ─────────────

/// Licredity: the PoolManager check is written in inline assembly.
contract Neg_01_AssemblyGuard is RawHook {
    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        IPoolManager _poolManager = poolManager;
        assembly ("memory-safe") {
            if iszero(eq(caller(), _poolManager)) {
                mstore(0x00, 0xae18210a)
                revert(0x1c, 0x04)
            }
        }
        total += data.length;
        return data;
    }
}

/// An assembly sender check against the wrong principal is still a finding.
contract Pos_01_AssemblyOwnerGuard is RawHook {
    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        address _owner = owner;
        assembly {
            if iszero(eq(caller(), _owner)) { revert(0, 0) }
        }
        total += data.length;
        return data;
    }
}

/// CorkHook: a flagged callback whose only statement is a revert cannot be abused.
contract Neg_01_RevertOnlyCallback is RawHook {
    constructor() {
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        revert("native swaps disabled");
    }
}

/// Licredity: the one-pool init gate (sender == this) is in inline assembly.
contract Neg_02_AssemblyInitGate is BaseHook {
    uint256 public total;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
        p.afterSwap = true;
    }

    function _beforeInitialize(address sender, PoolKey calldata, uint160) internal view override returns (bytes4) {
        assembly ("memory-safe") {
            if iszero(eq(sender, address())) { revert(0, 0) }
        }
        return this.beforeInitialize.selector;
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        total += 1;
        return this.afterSwap.selector;
    }
}

/// Flayer: pre-release v4 API. beforeInitialize takes hookData and always reverts;
/// afterAddLiquidity has no feesAccrued delta (5 parameters).
contract Neg_02_LegacyApiHook {
    IPoolManager public immutable poolManager;
    uint256 public total;

    constructor(IPoolManager m) {
        poolManager = m;
        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
        p.afterAddLiquidity = true;
        p.afterSwap = true;
    }

    function beforeInitialize(address, PoolKey calldata, uint160, bytes calldata) external view returns (bytes4) {
        require(msg.sender == address(poolManager), "pm");
        revert("use initializeCollection");
    }

    function afterAddLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, int256, bytes calldata)
        external
        returns (bytes4)
    {
        require(msg.sender == address(poolManager), "pm");
        total += 1;
        return this.afterAddLiquidity.selector;
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        external
        returns (bytes4)
    {
        require(msg.sender == address(poolManager), "pm");
        total += 1;
        return this.afterSwap.selector;
    }
}

/// Same legacy hook seen by V4H-03: the 5-parameter afterAddLiquidity IS the implementation.
contract Neg_03_LegacyApiArity {
    IPoolManager public immutable poolManager;
    uint256 public total;

    constructor(IPoolManager m) {
        poolManager = m;
        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.afterAddLiquidity = true;
    }

    function afterAddLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, int256, bytes calldata)
        external
        returns (bytes4)
    {
        require(msg.sender == address(poolManager), "pm");
        total += 1;
        return this.afterAddLiquidity.selector;
    }
}

function requiredHookPermissions() pure returns (Hooks.Permissions memory p) {
    p.beforeSwapReturnDelta = true; // without beforeSwap: no valid address exists
}

/// Angstrom L2: permissions come from a free function, not getHookPermissions().
contract Pos_03_PermsInFreeFunction is RawHook {
    constructor() {
        Hooks.validateHookPermissions(this, requiredHookPermissions());
    }
}

/// Angstrom L2 (Cyfrin Medium): afterSwap returns a fee delta but afterSwapReturnDelta
/// is off, so PoolManager ignores it and the swap fails to settle.
contract Pos_03_DeltaWithoutFlag {
    IPoolManager public immutable poolManager;
    uint24 public feeE6;

    constructor(IPoolManager m) {
        poolManager = m;
        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, int256 delta, bytes calldata)
        external
        returns (bytes4, int128 hookDelta)
    {
        require(msg.sender == address(poolManager), "pm");
        hookDelta = int128(delta) * int128(uint128(feeE6)) / 1e6;
        return (this.afterSwap.selector, hookDelta);
    }
}

/// Same shape with the flag set: fine.
contract Neg_03_DeltaWithFlag {
    IPoolManager public immutable poolManager;
    uint24 public feeE6;

    constructor(IPoolManager m) {
        poolManager = m;
        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
        p.afterSwapReturnDelta = true;
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, int256 delta, bytes calldata)
        external
        returns (bytes4, int128 hookDelta)
    {
        require(msg.sender == address(poolManager), "pm");
        hookDelta = int128(delta) * int128(uint128(feeE6)) / 1e6;
        return (this.afterSwap.selector, hookDelta);
    }
}

/// Flag off and the delta is always zero: fine.
contract Neg_03_ZeroDeltaNoFlag {
    IPoolManager public immutable poolManager;
    uint256 public total;

    constructor(IPoolManager m) {
        poolManager = m;
        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        external
        returns (bytes4, int128)
    {
        require(msg.sender == address(poolManager), "pm");
        total += 1;
        return (this.afterSwap.selector, 0);
    }
}

// ── Set-3 root causes (each written to fail first) ─────────────────────────

/// PaperHook shape: positional permissions assigned to the named return.
contract Neg_03_AssignedPermissions is BaseHook {
    uint256 public total;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p = Hooks.Permissions(false, false, false, false, false, false, false, true, false, false, false, false, false, false);
    }

    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        require(key.hooks == address(this), "pool");
        total += 1;
        return this.afterSwap.selector;
    }
}

/// Named permissions in a local variable, then returned.
contract Neg_03_LocalPermissions is BaseHook {
    uint256 public total;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        Hooks.Permissions memory perms = Hooks.Permissions({
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
        return perms;
    }

    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        require(key.hooks == address(this), "pool");
        total += 1;
        return this.afterSwap.selector;
    }
}

/// SentinelFeeHook shape: flagged, unguarded, not `view`, but it only checks and returns.
contract Neg_01_ChecksOnlyNoWrites is RawHook {
    constructor() {
        Hooks.validateHookPermissions(this, getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
    }

    function beforeInitialize(address, PoolKey calldata key, uint160) external override returns (bytes4) {
        require(key.fee == 0x800000, "dynamic fee only");
        return IHooks.beforeInitialize.selector;
    }
}

/// StopLoss shape: the 2023 Hooks.Calls API, afterSwap without hookData (4 params).
contract Pos_01_Api2023 {
    mapping(address => uint256) public fills;

    function afterSwap(address sender, PoolKey calldata, SwapParams calldata, int256)
        external
        returns (bytes4)
    {
        fills[sender] += 1;
        return this.afterSwap.selector;
    }
}

/// SentinelFeeHook shape: beforeInitialize only checks a pool *property*, which doesn't
/// restrict who can attach. Global state in afterSwap is still exposed.
contract Pos_02_PropertyOnlyInitCheck is BaseHook {
    uint256 public total;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
        p.afterSwap = true;
    }

    function _beforeInitialize(address, PoolKey calldata key, uint160) internal pure override returns (bytes4) {
        require(key.fee == 0x800000 && key.tickSpacing == 60, "dynamic fee only");
        return this.beforeInitialize.selector;
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        total += 1;
        return this.afterSwap.selector;
    }
}

interface IRewardLedger {
    function accrue(address user, uint256 amount) external;
    function price() external view returns (uint256);
}

/// SuperDCA / Gamma shape: the shared state lives in another contract.
contract Pos_02_ExternalLedger is BaseHook {
    IRewardLedger public ledger;

    constructor(IPoolManager m, IRewardLedger l) BaseHook(m) {
        ledger = l;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function _afterSwap(address sender, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        ledger.accrue(sender, 1);
        return this.afterSwap.selector;
    }
}

/// Reading another contract (view) is not a shared effect.
contract Neg_02_ExternalViewOnly is BaseHook {
    IRewardLedger public ledger;

    constructor(IPoolManager m, IRewardLedger l) BaseHook(m) {
        ledger = l;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        view
        override
        returns (bytes4)
    {
        require(ledger.price() > 0, "no price");
        return this.afterSwap.selector;
    }
}

// ── Regressions from the set-3 fixes ──

/// FullRange shape: writes through a local storage pointer.
contract Pos_01_StoragePointerWrite is RawHook {
    struct Info {
        bool accrued;
    }

    mapping(PoolId => Info) public info;

    using PoolIdLibrary for PoolKey;

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function beforeSwap(address, PoolKey calldata key, SwapParams calldata, bytes calldata)
        external
        override
        returns (bytes4)
    {
        Info storage i = info[key.toId()];
        i.accrued = true;
        return IHooks.beforeSwap.selector;
    }
}

/// Gamma LimitOrderHook shape: writes transient storage in assembly.
contract Pos_01_TransientWrite is RawHook {
    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        override
        returns (bytes4)
    {
        assembly {
            tstore(0, 1)
        }
        return IHooks.beforeSwap.selector;
    }
}

interface IWETH9 {
    function withdraw(uint256) external;
    function transfer(address, uint256) external returns (bool);
}

/// WETH/Livo shape: plain token calls are value moves, not shared foreign state.
contract Neg_02_TokenCallsOnly is BaseHook {
    IWETH9 public immutable weth;

    constructor(IPoolManager m, IWETH9 w) BaseHook(m) {
        weth = w;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function _afterSwap(address sender, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        weth.withdraw(1);
        weth.transfer(sender, 1);
        return this.afterSwap.selector;
    }
}

/// WETHHook shape: the pool-identity check is computed into a local first.
contract Neg_02_GateViaLocal is BaseHook {
    Currency public immutable wrapped;
    uint256 public total;

    constructor(IPoolManager m, Currency w) BaseHook(m) {
        wrapped = w;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeInitialize = true;
        p.afterSwap = true;
    }

    function _beforeInitialize(address, PoolKey calldata key, uint160) internal view override returns (bytes4) {
        bool ok = Currency.unwrap(key.currency0) == address(0) && Currency.unwrap(key.currency1) == Currency.unwrap(wrapped);
        if (!ok) revert("pair");
        return this.beforeInitialize.selector;
    }

    function _afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        total += 1;
        return this.afterSwap.selector;
    }
}

// ── Set-4 root causes ──

/// PredicateHook shape: the delta is a local initialised to zero and never changed.
contract Neg_03_DeltaLocalZero {
    IPoolManager public immutable poolManager;
    uint256 public total;

    constructor(IPoolManager m) {
        poolManager = m;
        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        external
        returns (bytes4, int128)
    {
        require(msg.sender == address(poolManager), "pm");
        int128 hookDelta = int128(0);
        total += 1;
        return (this.afterSwap.selector, hookDelta);
    }
}

/// Same shape, but the local is reassigned to a non-zero value: still flagged.
contract Pos_03_DeltaLocalReassigned {
    IPoolManager public immutable poolManager;
    uint24 public feeE6;

    constructor(IPoolManager m) {
        poolManager = m;
        Hooks.validateHookPermissions(IHooks(address(this)), getHookPermissions());
    }

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, int256 delta, bytes calldata)
        external
        returns (bytes4, int128)
    {
        require(msg.sender == address(poolManager), "pm");
        int128 hookDelta = int128(0);
        if (feeE6 > 0) hookDelta = int128(delta) * int128(uint128(feeE6)) / 1e6;
        return (this.afterSwap.selector, hookDelta);
    }
}

/// TaxStrategy shape: the hook swaps through the PoolManager itself, then settles the
/// delta that swap returned. It pays for its own action, not out of inventory.
contract Neg_02_SettleOwnSwap is BaseHook {
    using CurrencySettler for Currency;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        _convert(key, 1e18);
        return this.afterSwap.selector;
    }

    function _convert(PoolKey memory key, uint256 amount) internal {
        int256 delta = poolManager.swap(key, SwapParams(true, -int256(amount), 0), "");
        key.currency0.settle(poolManager, address(this), uint256(-delta));
    }
}


// ── Pre-release API (set-5 root causes) ──

/// PoolCallsHook / AttestationHook shape: getHooksCalls() enables beforeSwap, which is
/// only the reverting placeholder. Positional Hooks.Calls.
contract Pos_03_CallsFlagNoImpl is BaseHook2023 {
    uint256 public total;

    constructor(IPoolManager m) BaseHook2023(m) {}

    function getHooksCalls() public pure override returns (Hooks2023.Calls memory) {
        return Hooks2023.Calls(false, false, false, false, true, true, false, false);
    }

    function afterSwap(address, PoolKey calldata key, SwapParams calldata, int256) external override returns (bytes4) {
        require(msg.sender == address(poolManager) && key.hooks == address(this), "pm");
        total += 1;
        return this.afterSwap.selector;
    }
}

/// Same API, flags and implementations agree: clean.
contract Neg_03_CallsMatch is BaseHook2023 {
    uint256 public total;

    constructor(IPoolManager m) BaseHook2023(m) {}

    function getHooksCalls() public pure override returns (Hooks2023.Calls memory) {
        return Hooks2023.Calls({
            beforeInitialize: false,
            afterInitialize: false,
            beforeModifyPosition: false,
            afterModifyPosition: false,
            beforeSwap: false,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false
        });
    }

    function afterSwap(address, PoolKey calldata key, SwapParams calldata, int256) external override returns (bytes4) {
        require(msg.sender == address(poolManager) && key.hooks == address(this), "pm");
        total += 1;
        return this.afterSwap.selector;
    }
}

/// HyperlaneLPHook shape: afterModifyPosition is unguarded and calls out.
contract Pos_01_ModifyPositionUnguarded is BaseHook2023 {
    IRewardLedger public ledger;

    constructor(IPoolManager m, IRewardLedger l) BaseHook2023(m) {
        ledger = l;
    }

    function getHooksCalls() public pure override returns (Hooks2023.Calls memory c) {
        c.afterModifyPosition = true;
    }

    function afterModifyPosition(address sender, PoolKey calldata, ModifyPositionParams calldata, int256)
        external
        override
        returns (bytes4)
    {
        ledger.accrue(sender, 1);
        return this.afterModifyPosition.selector;
    }
}

/// lockAcquired (pre-unlockCallback) without a PoolManager check.
contract Pos_01_LockAcquiredUnguarded is RawHook {
    function lockAcquired(bytes calldata data) external returns (bytes memory) {
        total += data.length;
        return data;
    }
}

/// lockAcquired guarded in a helper (PoolCallsHook shape): clean.
contract Neg_01_LockAcquiredGuarded is RawHook {
    function lockAcquired(bytes calldata data) external returns (bytes memory) {
        _onlyPM();
        total += data.length;
        return data;
    }

    function _onlyPM() internal view {
        require(msg.sender == address(poolManager), "pm");
    }
}

// ── Public-scan root cause: template counters ──

/// v4-template Counter shape: unguarded callbacks that only bump counters nobody reads
/// (only the auto-generated getters). Reported, but as info.
contract Pos_01_CounterOnly is RawHook {
    using PoolIdLibrary for PoolKey;

    mapping(PoolId => uint256) public beforeSwapCount;

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function beforeSwap(address, PoolKey calldata key, SwapParams calldata, bytes calldata)
        external
        override
        returns (bytes4)
    {
        beforeSwapCount[key.toId()]++;
        return IHooks.beforeSwap.selector;
    }
}

/// RoyaltyHook shape: the unguarded write feeds a payout in another function.
contract Pos_01_WriteFeedsPayout is RawHook {
    mapping(address => uint256) public volume;

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function afterSwap(address sender, PoolKey calldata, SwapParams calldata, int256 d, bytes calldata)
        external
        override
        returns (bytes4)
    {
        volume[sender] += uint256(d < 0 ? -d : d);
        return IHooks.afterSwap.selector;
    }

    function claimRebate() external returns (uint256 amount) {
        amount = volume[msg.sender] / 100;
        volume[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}

/// Points ledger read only off-chain (public getter): crediting arbitrary addresses is
/// still a consequence, unlike a per-pool counter.
contract Pos_01_PointsLedger is RawHook {
    mapping(address => uint256) public points;

    function getHookPermissions() public pure returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function afterSwap(address sender, PoolKey calldata, SwapParams calldata, int256, bytes calldata)
        external
        override
        returns (bytes4)
    {
        points[sender] += 1;
        return IHooks.afterSwap.selector;
    }
}

// ── Public-scan V4H-02 root causes (RevertHook) ──

/// RevertHook _afterSwap shape: the callback exits early unless the pool has a record
/// in hook storage (`if (!cursor.hasTriggers) return`). Unknown pools do nothing.
contract Neg_02_RegisteredPoolsOnly is BaseHook {
    using PoolIdLibrary for PoolKey;

    struct Cursor {
        bool hasTriggers;
        int24 last;
    }

    mapping(PoolId => Cursor) internal cursors;
    uint256 public executed;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        PoolId id = key.toId();
        Cursor storage c = cursors[id];
        if (!c.hasTriggers) return this.afterSwap.selector;
        executed += 1;
        return this.afterSwap.selector;
    }
}

// Hedge-style: the early exit reads storage keyed by key.currency0. A currency is not a pool:
// an attacker's pool with the same currency0 passes the exit and reaches the shared counter.
contract Pos_02_CurrencyKeyedExit is BaseHook {
    mapping(Currency => uint256[]) internal pricesByCurrency;
    uint256 public executed;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function _afterSwap(address, PoolKey calldata key, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        uint256[] memory prices = pricesByCurrency[key.currency0];
        if (prices.length == 0) return this.afterSwap.selector;
        executed += 1;
        return this.afterSwap.selector;
    }
}

interface IPoolController {
    function onSwap(PoolKey calldata key, address sender) external returns (uint24);
}

/// RevertHook auction-controller shape: the controller returns early for pools it has
/// no config for, so the hook's call is per-pool even though the controller is shared.
contract ControllerWithPoolGate is IPoolController {
    using PoolIdLibrary for PoolKey;

    mapping(PoolId => uint256) internal epochLength;
    uint256 public totalSwaps;

    function onSwap(PoolKey calldata key, address) external returns (uint24) {
        PoolId id = key.toId();
        if (epochLength[id] == 0) return 0;
        totalSwaps += 1;
        return 3000;
    }
}

contract Neg_02_ControllerIgnoresUnknownPools is BaseHook {
    ControllerWithPoolGate public controller;

    constructor(IPoolManager m, ControllerWithPoolGate c) BaseHook(m) {
        controller = c;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function _beforeSwap(address sender, PoolKey calldata key, SwapParams calldata, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        controller.onSwap(key, sender);
        return this.beforeSwap.selector;
    }
}

/// Gamma LimitOrderManager shape: the shared controller processes any pool. Still flagged.
contract ControllerAnyPool is IPoolController {
    uint256 public totalSwaps;

    function onSwap(PoolKey calldata, address) external returns (uint24) {
        totalSwaps += 1;
        return 0;
    }
}

contract Pos_02_ControllerProcessesAnyPool is BaseHook {
    ControllerAnyPool public controller;

    constructor(IPoolManager m, ControllerAnyPool c) BaseHook(m) {
        controller = c;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function _beforeSwap(address sender, PoolKey calldata key, SwapParams calldata, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        controller.onSwap(key, sender);
        return this.beforeSwap.selector;
    }
}

/// Gamma LimitOrderManager shape: a *helper* returns early for an empty pool list, but
/// the entry point still runs shared effects for any pool. Must stay flagged.
contract ControllerHelperLookup is IPoolController {
    using PoolIdLibrary for PoolKey;

    mapping(PoolId => uint256[]) internal orders;
    uint256 public totalSwaps;

    function onSwap(PoolKey calldata key, address) external returns (uint24) {
        uint256 n = _count(key.toId());
        totalSwaps += 1 + n;
        return 0;
    }

    function _count(PoolId id) internal view returns (uint256) {
        if (orders[id].length == 0) return 0;
        return orders[id].length;
    }
}

contract Pos_02_ControllerHelperOnlyGate is BaseHook {
    ControllerHelperLookup public controller;

    constructor(IPoolManager m, ControllerHelperLookup c) BaseHook(m) {
        controller = c;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.afterSwap = true;
    }

    function _afterSwap(address sender, PoolKey calldata key, SwapParams calldata, int256, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        controller.onSwap(key, sender);
        return this.afterSwap.selector;
    }
}

// ── Stranger-test root causes (FablesFi/fables shapes; each written to fail first) ──

/// Permissions built by an internal virtual helper that a derived hook extends via super.
abstract contract SuperPermsBase is BaseHook {
    uint256 public swaps;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return _hookPerms();
    }

    function _hookPerms() internal pure virtual returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        require(key.hooks == address(this), "pool");
        swaps += 1;
        return this.beforeSwap.selector;
    }
}

contract Neg_03_SuperPermissions is SuperPermsBase {
    uint256 public adds;

    constructor(IPoolManager m) SuperPermsBase(m) {}

    function _hookPerms() internal pure override returns (Hooks.Permissions memory p) {
        p = super._hookPerms();
        p.beforeAddLiquidity = true;
    }

    function _beforeAddLiquidity(address, PoolKey calldata key, ModifyLiquidityParams calldata, bytes calldata)
        internal
        override
        returns (bytes4)
    {
        require(key.hooks == address(this), "pool");
        adds += 1;
        return this.beforeAddLiquidity.selector;
    }
}

/// The super chain still counts: a flag added in the override with no callback is flagged.
contract Pos_03_SuperPermissionsNoImpl is SuperPermsBase {
    constructor(IPoolManager m) SuperPermsBase(m) {}

    function _hookPerms() internal pure override returns (Hooks.Permissions memory p) {
        p = super._hookPerms();
        p.afterSwap = true;
    }
}

/// A callback served by an assembly fallback that dispatches on the selector.
contract Neg_03_FallbackDispatch is BaseHook {
    bytes4 constant BEFORE_SWAP = 0x575e24b4;

    constructor(IPoolManager m) BaseHook(m) {}

    function getHookPermissions() public pure override returns (Hooks.Permissions memory p) {
        p.beforeSwap = true;
    }

    fallback() external {
        require(msg.sender == address(poolManager) && msg.sig == BEFORE_SWAP, "pm");
        assembly {
            mstore(0x00, shl(224, 0x575e24b4))
            return(0x00, 0x60)
        }
    }
}
