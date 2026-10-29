"""V4H-02: hook keeps shared state but never checks which pool is calling.

A v4 hook can be attached to any pool by whoever initializes it. A hook whose
callbacks write state that is shared across pools (a global ledger, user points,
reserves) or move hook-held tokens chosen by ``key.currencyN`` must either refuse
foreign pools in beforeInitialize or check the PoolKey/PoolId in the callback.
State keyed by PoolId is per-pool and is not flagged.
"""

from __future__ import annotations

from ..model import HookFinding
from ..solast import Node, is_msg_sender, of_type, type_string
from .base import (
    CALLBACKS,
    Hook,
    always_reverts,
    is_state_changing_external_call,
    lvalues,
    mutable_state_var_ids,
    reverts_or_requires,
    state_vars_read_in_checks,
    storage_target,
)
from .permissions import parse_permissions

# Moving the hook's *own* balance of a key-chosen token. take() pays INTO the hook
# and is not counted; settle(manager, address(this), ...) pays the PoolManager out
# of the hook's inventory (v4-core CurrencySettler) and is.
VALUE_MOVES = {"transfer", "transferFrom", "safeTransfer", "safeTransferFrom"}
INIT_CALLBACKS = ("beforeInitialize", "afterInitialize")


class UnvalidatedPoolKey:
    id = "V4H-02"
    title = "Hook does not validate which pool is calling"

    def run(self, hook: Hook) -> list[HookFinding]:
        flags = parse_permissions(hook)

        def enabled(name: str) -> bool:
            if flags is not None and flags.get(name) is not None:
                return bool(flags[name])
            return hook.is_implemented(name)

        # A revert in either initialize callback stops the pool from being created.
        if any(enabled(n) and self._has_any_gate(hook, n) for n in INIT_CALLBACKS):
            return []
        findings = []
        for name in CALLBACKS:
            if not enabled(name) or not hook.is_implemented(name):
                continue
            entry = hook.callback(name)
            impl = hook.implementation(name)
            assert entry and impl
            body = hook.contract.reachable(impl[0])
            per_position = _trusted_salt(hook, name, enabled, body)
            shared_writes = sorted({w for f in body for w in shared_state_writes(hook, f, per_position)})
            moves = sorted({m for f in body for m in key_currency_moves(f, hook)})
            external = sorted({e for f in body for e in external_state_calls(f, hook)})
            if not shared_writes and not moves and not external:
                continue
            reach = hook.contract.reachable(entry[0])
            gate_fns = [entry[0], impl[0]]
            if self._validates_pool(hook, reach) or pool_keyed_exit(gate_fns, reach, _all_state_ids(hook.contract)):
                continue
            what = []
            if shared_writes:
                what.append(f"writes pool-agnostic state ({', '.join(shared_writes)})")
            if moves:
                what.append(f"moves tokens chosen by the PoolKey ({', '.join(moves)})")
            if external:
                what.append(f"changes state in another contract ({', '.join(external)})")
            init_note = (
                "beforeInitialize is not enabled"
                if not enabled("beforeInitialize")
                else "beforeInitialize does not restrict which pools can initialize"
            )
            gated = sorted(set(shared_writes) & state_vars_read_in_checks(hook))
            findings.append(
                hook.finding(
                    self.id,
                    self.title,
                    "high" if moves else "medium",
                    impl[0],
                    f"{hook.name}.{name} {' and '.join(what)}, but {init_note} and the callback never "
                    "compares the PoolKey/PoolId against an allowed pool. Any pool can attach to this hook.",
                    confidence="confirmed" if (moves or external or gated) else "pattern",
                    gated_shared_writes=gated,
                    callback=name,
                    shared_state_writes=shared_writes,
                    key_currency_moves=moves,
                    external_state_calls=external,
                    before_initialize_enabled=enabled("beforeInitialize"),
                )
            )
        return findings

    def _has_any_gate(self, hook: Hook, name: str) -> bool:
        """An initialize callback that restricts *who or what* can attach: an
        unconditional revert (only the hook itself can initialize, since PoolManager
        skips self-calls), or a check on the caller, the currencies, the pool id or
        hook storage (a bound flag, an allowlist). A check on fee or tickSpacing alone
        restricts the pool's shape, not who attaches, and does not count."""
        impl = hook.implementation(name)
        if impl is None:
            return False
        if always_reverts(impl[0]):
            return True
        fns = hook.contract.reachable(impl[0])
        return any(self._restricts_attach(hook, c, fns) for c in reverts_or_requires(fns))

    def _restricts_attach(self, hook: Hook, cond: Node, fns: list[Node]) -> bool:
        if cond.get("nodeType", "").startswith("Yul"):
            return True  # assembly gates are almost always caller()/address checks
        state = mutable_state_var_ids(hook)
        for n in of_type(_with_local_inits(cond, fns), "Identifier", "MemberAccess", "FunctionCall"):
            if is_msg_sender(n) or n.get("memberName") == "origin":
                return True
            if n.get("memberName") in POOL_IDENTITY or type_string(n) == "PoolId":
                return True
            if n.get("nodeType") == "Identifier":
                if n.get("referencedDeclaration") in state:
                    return True
                if type_string(n) == "address" and n.get("name") != "this":
                    return True  # the `sender` / caller parameter
        return False

    def _validates_pool(self, hook: Hook, fns: list[Node]) -> bool:
        """The callback checks the pool's identity, not just its fee/tickSpacing."""
        for cond in reverts_or_requires(fns):
            if cond.get("nodeType", "").startswith("Yul"):
                continue
            shape_bases = {id(m.get("expression")) for m in of_type(cond, "MemberAccess")
                           if m.get("memberName") in POOL_SHAPE}
            for n in of_type(cond, "Identifier", "MemberAccess", "FunctionCall"):
                ts = type_string(n)
                if ts == "PoolId" or n.get("memberName") in POOL_IDENTITY:
                    return True
                if "struct PoolKey" in ts and id(n) not in shape_bases:
                    return True
        return False


def _with_local_inits(cond: Node, fns: list[Node]) -> list[Node]:
    """The condition plus the initializers of the locals it reads, so
    `bool ok = key.currency0 == X; if (!ok) revert();` is seen as a currency check."""
    ids = {n.get("referencedDeclaration") for n in of_type(cond, "Identifier")}
    inits = [
        d["initialValue"]
        for f in fns
        for d in of_type(f.get("body"), "VariableDeclarationStatement")
        if d.get("initialValue") and any(decl and decl.get("id") in ids for decl in d.get("declarations", []))
    ]
    return [cond, *inits]


POOL_IDENTITY = ("hooks", "currency0", "currency1")
POOL_SHAPE = ("fee", "tickSpacing")
# ERC-20 / WETH calls move value; they're judged by key_currency_moves, not as shared state.
TOKEN_CALLS = {"transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "approve", "deposit", "withdraw"}


def _all_state_ids(contract) -> set[int]:
    return {v["id"] for v in contract.state_vars()}


def pool_keyed_exit(gate_fns: list[Node], scope_fns: list[Node], state_ids: set[int]) -> bool:
    """One of ``gate_fns`` exits early, in its own top-level statements, depending on
    storage keyed by the pool (`if (!cursors[poolId].hasTriggers) return;`,
    `require(configs[id].enabled)`): pools the contract has no record of never reach the
    effects. A lookup inside a helper doesn't count; it doesn't guard the caller's
    effects. Locals are followed to their initializers (via ``scope_fns``), so storage
    pointers (`Cursor storage c = cursors[id]`) count."""
    conds = []
    for f in gate_fns:
        for st in (f.get("body") or {}).get("statements", []):
            if st.get("nodeType") == "IfStatement":
                body = st.get("trueBody") or {}
                if body.get("nodeType") == "Return" or any(True for _ in of_type(body, "Return")) or \
                        any(True for _ in of_type(body, "RevertStatement")):
                    conds.append(st["condition"])
            elif st.get("nodeType") == "ExpressionStatement":
                e = st.get("expression") or {}
                if e.get("nodeType") == "FunctionCall" and e.get("expression", {}).get("name") == "require" and e.get("arguments"):
                    conds.append(e["arguments"][0])
    for cond in conds:
        for part in _with_local_inits(cond, scope_fns):
            for ia in of_type(part, "IndexAccess"):
                base = ia.get("baseExpression") or {}
                while base.get("nodeType") in ("IndexAccess", "MemberAccess"):
                    base = base.get("baseExpression") or base.get("expression") or {}
                if base.get("referencedDeclaration") in state_ids and _identifies_pool(ia.get("indexExpression") or {}):
                    return True
    return False


def _callee_ignores_unknown_pools(hook: Hook, call: Node) -> bool:
    """The external call's implementation is in the build and exits early for pools
    it has no record of (a shared controller that keys everything by PoolId)."""
    ref = hook.unit.by_id.get(call["expression"].get("referencedDeclaration", -1))
    if not ref or ref.get("nodeType") != "FunctionDefinition":
        return False
    name, n = ref.get("name"), len(ref["parameters"]["parameters"])
    scope = ref.get("scope")
    for c in hook.unit.contracts():
        if c.kind != "contract" or (scope not in c.node.get("linearizedBaseContracts", []) and c.id != scope):
            continue
        found = c.resolve(name, n)
        if found and pool_keyed_exit([found[0]], c.reachable(found[0]), _all_state_ids(c)):
            return True
    return False


def external_state_calls(fn: Node, hook: Hook) -> list[str]:
    """State-changing calls on another contract held in hook storage (a staking or
    reward contract, an order manager): shared state the hook's own storage hides.
    The PoolManager is excluded; calls to it are per-pool by construction."""
    state = {v["id"]: v for v in hook.contract.state_vars()}
    out = []
    for call in of_type(fn.get("body"), "FunctionCall"):
        if not is_state_changing_external_call(call) or call["expression"].get("memberName") in TOKEN_CALLS:
            continue
        recv = call["expression"].get("expression", {})
        while recv.get("nodeType") == "FunctionCall" and recv.get("arguments"):  # IFoo(address(x))
            recv = recv["arguments"][0]
        var = state.get(recv.get("referencedDeclaration", -1))
        if var is None or "PoolManager" in type_string(var):
            continue
        if _callee_ignores_unknown_pools(hook, call):
            continue
        out.append(f"{var['name']}.{call['expression']['memberName']}")
    return out


def _derived_from_pool(expr: Node) -> bool:
    """Index is a PoolId, or computed from the PoolKey (e.g. keccak256(abi.encode(key, ...)))."""
    return any(type_string(n) == "PoolId" or "struct PoolKey" in type_string(n) for n in of_type(expr, *_EXPR))


_EXPR = ("Identifier", "MemberAccess", "FunctionCall", "IndexAccess")


def _identifies_pool(expr: Node) -> bool:
    """Index names one pool: a PoolId, or the whole PoolKey (hashed). `key.currency0` or
    `key.fee` is shared with other pools (any pool can reuse a currency), so storage keyed
    by it is no pool gate."""
    fields = {
        id(m["expression"])
        for m in of_type(expr, "MemberAccess")
        if "struct PoolKey" in type_string(m.get("expression") or {}) and m.get("memberName") in POOL_IDENTITY + POOL_SHAPE
    }
    return any(
        (type_string(n) == "PoolId" or "struct PoolKey" in type_string(n)) and id(n) not in fields
        for n in of_type(expr, *_EXPR)
    )


def shared_state_writes(hook: Hook, fn: Node, also_keyed=None) -> list[str]:
    def keyed(e: Node) -> bool:
        return _derived_from_pool(e) or (also_keyed is not None and also_keyed(e))

    out = []
    for lv in lvalues(fn):
        t = storage_target(lv, hook, keyed_by=keyed)
        if t and not t[1]:
            out.append(t[0])
    return out


# The before-callback that runs, with the same sender, ahead of each liquidity callback.
LIQUIDITY_GATE = {
    "beforeAddLiquidity": "beforeAddLiquidity",
    "afterAddLiquidity": "beforeAddLiquidity",
    "beforeRemoveLiquidity": "beforeRemoveLiquidity",
    "afterRemoveLiquidity": "beforeRemoveLiquidity",
}


def _trusted_salt(hook: Hook, name: str, enabled, body: list[Node]):
    """Storage keyed by ``params.salt`` is per-position (RevertHook's
    ``_positionStates[uint256(params.salt)]``) when the matching beforeXLiquidity reverts
    unless ``sender`` equals an address the hook stores (a trusted PositionManager): then
    every salt is a token id that manager minted. Without that check any caller of
    modifyLiquidity picks the salt from any pool, so salt-keyed state stays shared.
    Returns an index predicate for ``storage_target``, or None."""
    gate = LIQUIDITY_GATE.get(name)
    if gate is None or not enabled(gate) or not hook.is_implemented(gate):
        return None
    impl = hook.implementation(gate)
    params = impl[0]["parameters"]["parameters"]
    if not params:
        return None
    gate_fns = hook.contract.reachable(impl[0])
    # The check may sit in a helper (`_checkLiquiditySender(sender)`): follow the sender.
    senders = _derived_ids(hook, gate_fns, {params[0].get("id")}, lambda n: False)
    state = _all_state_ids(hook.contract)
    trusted = False
    for cond in reverts_or_requires(gate_fns):
        refs = {n.get("referencedDeclaration") for n in of_type(cond, "Identifier")}
        if refs & senders and refs & state:
            trusted = True
            break
    if not trusted:
        return None
    tainted = _derived_ids(hook, body, set(), _is_salt)
    return lambda e: any(_is_salt(n) or n.get("referencedDeclaration") in tainted
                         for n in of_type(e, "Identifier", "MemberAccess"))


def _is_salt(n: Node) -> bool:
    return n.get("memberName") == "salt" and "ModifyLiquidityParams" in type_string(n.get("expression") or {})


def _derived_ids(hook: Hook, fns: list[Node], seeds: set[int], is_source) -> set[int]:
    """``seeds`` plus the locals and internal-helper parameters whose value comes from a
    seed or from a node matching ``is_source``
    (`uint256 tokenId = uint256(params.salt); _deactivate(tokenId);`)."""
    tainted = set(seeds)

    def derived(e: Node | None) -> bool:
        return bool(e) and any(is_source(n) or n.get("referencedDeclaration") in tainted
                               for n in of_type(e, "Identifier", "MemberAccess"))

    changed = True
    while changed:
        before = len(tainted)
        for f in fns:
            body = f.get("body")
            for d in of_type(body, "VariableDeclarationStatement"):
                if derived(d.get("initialValue")):
                    tainted |= {x["id"] for x in d.get("declarations", []) if x}
            for a in of_type(body, "Assignment"):
                lhs = a.get("leftHandSide") or {}
                if lhs.get("nodeType") == "Identifier" and derived(a.get("rightHandSide")):
                    tainted.add(lhs.get("referencedDeclaration"))
            for call in of_type(body, "FunctionCall"):
                ref = hook.unit.by_id.get((call.get("expression") or {}).get("referencedDeclaration", -1)) or {}
                if ref.get("nodeType") != "FunctionDefinition":
                    continue
                for arg, prm in zip(call.get("arguments", []), ref["parameters"]["parameters"]):
                    if derived(arg):
                        tainted.add(prm["id"])
        changed = len(tainted) != before
    return tainted


def key_currency_moves(fn: Node, hook: Hook | None = None) -> list[str]:
    """Calls that move the hook's own tokens in a currency the PoolKey can choose.

    ``key.currencyN.transfer(...)`` always counts. In the hook's own code (not inside a
    library such as CurrencySettler, whose body would double count) a ``transfer`` or a
    ``settle(manager, address(this), ...)`` on any Currency value that is not a hook
    state variable counts too: that Currency came from the key, through a local or a
    helper parameter.
    """
    out = []
    in_library = hook is not None and fn.get("id") in hook.unit.library_functions
    state_ids = _state_ids_all(hook) if hook is not None else set()
    for call in of_type(fn.get("body"), "FunctionCall"):
        expr = call.get("expression", {})
        member = expr.get("memberName")
        if expr.get("nodeType") != "MemberAccess" or member not in VALUE_MOVES | {"settle"}:
            continue
        recv = expr.get("expression", {})
        if recv.get("nodeType") == "MemberAccess" and recv.get("memberName") in ("currency0", "currency1"):
            if member in VALUE_MOVES:
                out.append(f"key.{recv['memberName']}.{member}")
            elif _pays_from_self(call) and not _settles_own_action(call, fn):
                out.append(f"key.{recv['memberName']}.settle")
            continue
        if hook is None or in_library or type_string(recv) != "Currency":
            continue
        if recv.get("nodeType") == "Identifier" and recv.get("referencedDeclaration") in state_ids:
            continue  # a currency fixed by the hook, not by the key
        if member in VALUE_MOVES or (_pays_from_self(call) and not _settles_own_action(call, fn)):
            out.append(f"{recv.get('name', 'currency')}.{member}")
    return out


def _pays_from_self(call: Node) -> bool:
    """settle(manager, address(this), amount[, burn]): the payer is the hook.

    ``burn = true`` pays with ERC-6909 claims instead; hooks do that to hand back fees
    they took as claims earlier in the same swap (OpenZeppelin's fee hooks), so it is
    not counted. Known blind spot: claims pooled across pools and paid out this way.
    """
    args = call.get("arguments", [])
    if args and args[-1].get("nodeType") == "Literal" and args[-1].get("value") == "true":
        return False
    for arg in args:
        if (
            arg.get("nodeType") == "FunctionCall"
            and arg.get("kind") == "typeConversion"
            and any(a.get("name") == "this" for a in arg.get("arguments", []))
        ):
            return True
    return False


# PoolManager calls whose returned delta the hook then owes for its own action.
OWN_ACTIONS = {"swap", "modifyLiquidity", "donate"}


def _settles_own_action(call: Node, fn: Node) -> bool:
    """The settled amount is computed from a delta returned by the hook's own
    poolManager.swap/modifyLiquidity in the same function: the hook is paying for an
    action it initiated, not paying out inventory to whoever brought the pool."""
    own: set[int] = set()
    for d in of_type(fn.get("body"), "VariableDeclarationStatement"):
        init = d.get("initialValue") or {}
        if init.get("nodeType") == "FunctionCall" and init.get("expression", {}).get("memberName") in OWN_ACTIONS:
            own |= {x["id"] for x in d.get("declarations", []) if x}
    for asg in of_type(fn.get("body"), "Assignment"):
        rhs = asg.get("rightHandSide") or {}
        lhs = asg.get("leftHandSide") or {}
        if rhs.get("nodeType") == "FunctionCall" and rhs.get("expression", {}).get("memberName") in OWN_ACTIONS:
            own |= {n.get("referencedDeclaration") for n in of_type(lhs, "Identifier")}
    if not own:
        return False
    return any(n.get("referencedDeclaration") in own for a in call.get("arguments", []) for n in of_type(a, "Identifier"))


def _state_ids_all(hook: Hook) -> set[int]:
    return {v["id"] for v in hook.contract.state_vars()}
