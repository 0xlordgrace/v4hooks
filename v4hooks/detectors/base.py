"""Detector interface and the shared view of "a hook contract"."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..model import HookFinding
from ..solast import Contract, Node, Unit, of_type, type_string

# IHooks callbacks: name -> number of parameters.
CALLBACKS: dict[str, int] = {
    "beforeInitialize": 3,
    "afterInitialize": 4,
    "beforeAddLiquidity": 4,
    "afterAddLiquidity": 6,
    "beforeRemoveLiquidity": 4,
    "afterRemoveLiquidity": 6,
    "beforeSwap": 4,
    "afterSwap": 5,
    "beforeDonate": 5,
    "afterDonate": 5,
    # Pre-release API (2023 / early 2024): one modifyPosition pair instead of
    # add/removeLiquidity. Later pre-release versions added hookData (see LEGACY_ARITY).
    "beforeModifyPosition": 3,
    "afterModifyPosition": 4,
}
# Pre-release v4 (2024) signatures that audited hooks still ship with: initialize
# callbacks took hookData, and after{Add,Remove}Liquidity had no feesAccrued delta.
# Older v4 APIs: the pre-release IHooks (hookData on initialize, 5-arg after*Liquidity)
# and the 2023 Hooks.Calls API (no hookData on swap/donate).
LEGACY_ARITY: dict[str, tuple[int, ...]] = {
    "beforeInitialize": (4,),
    "afterInitialize": (5,),
    "afterAddLiquidity": (5,),
    "afterRemoveLiquidity": (5,),
    "beforeSwap": (3,),
    "afterSwap": (4,),
    "beforeDonate": (4,),
    "afterDonate": (4,),
    "beforeModifyPosition": (4,),
    "afterModifyPosition": (5,),
}
# Callbacks that run on every pool operation (as opposed to once at init).
OPERATION_CALLBACKS = [c for c in CALLBACKS if "Initialize" not in c]
UNLOCK_CALLBACK = "unlockCallback"
# PoolManager callbacks into a locker: unlockCallback(bytes), and the pre-release
# lockAcquired(bytes) / lockAcquired(uint256 id, bytes).
UNLOCK_CALLBACKS: dict[str, tuple[int, ...]] = {"unlockCallback": (1,), "lockAcquired": (1, 2)}


class Detector(Protocol):
    id: str
    title: str

    def run(self, hook: Hook) -> list[HookFinding]: ...


@dataclass
class Hook:
    """A leaf contract that implements IHooks (or IHooks-shaped callbacks)."""

    contract: Contract

    @property
    def unit(self) -> Unit:
        return self.contract.unit

    @property
    def name(self) -> str:
        return self.contract.name

    def callback(self, name: str) -> tuple[Node, Contract] | None:
        """The external entry point PoolManager would call (release or pre-release arity)."""
        return resolve_callback(self.contract, name)

    def implementation(self, name: str) -> tuple[Node, Contract] | None:
        """Where the callback's logic actually lives.

        BaseHook-style contracts route ``beforeSwap`` -> ``_beforeSwap``; if the
        external entry point just forwards to ``_name``, follow it.
        """
        entry = self.callback(name)
        if entry is None:
            return None
        fn, _ = entry
        if forwards_to(fn, "_" + name):
            inner = resolve_callback(self.contract, name, prefix="_")
            if inner:
                return inner
        return entry

    def is_implemented(self, name: str) -> bool:
        impl = self.implementation(name)
        return impl is not None and not is_trivial(impl[0])

    def finding(self, detector: str, title: str, severity: str, fn: Node, message: str,
                confidence: str = "pattern", **evidence) -> HookFinding:
        path, a, b = self.unit.location(fn)
        return HookFinding(
            detector=detector,
            title=title,
            severity=severity,
            contract=self.name,
            function=fn.get("name") or fn.get("kind", ""),
            file=path,
            line_start=a,
            line_end=b,
            message=message,
            evidence=evidence,
            snippet=self.unit.snippet(fn),
            confidence=confidence,
        )


def find_hooks(units: list[Unit], scope: list[str] | None = None) -> list[Hook]:
    """Leaf, deployable hook contracts whose source is in ``scope`` (path prefixes).

    A contract is a hook if it inherits IHooks or declares a function with an
    IHooks callback name taking a PoolKey. "Leaf" = not inherited by another hook
    in the same unit, so an abstract base is analysed through its concrete child.
    """
    hooks: list[Hook] = []
    for unit in units:
        candidates = []
        for c in unit.contracts():
            if c.kind != "contract" or c.abstract:
                continue
            if scope and not any(c.path.startswith(s) for s in scope):
                continue
            if c.inherits("IHooks") or _declares_callback(c):
                candidates.append(c)
        bases = {cid for c in candidates for cid in c.node.get("linearizedBaseContracts", [])[1:]}
        hooks.extend(Hook(c) for c in candidates if c.id not in bases)
    return hooks


def _declares_callback(c: Contract) -> bool:
    for base in c.linearized():
        for f in base.own_functions():
            if f.get("name") in CALLBACKS and any(
                "struct PoolKey" in (p.get("typeDescriptions") or {}).get("typeString", "")
                for p in f["parameters"]["parameters"]
            ):
                return True
    return False


def forwards_to(fn: Node, name: str) -> bool:
    """True if ``fn``'s body is essentially ``return name(...)``."""
    stmts = (fn.get("body") or {}).get("statements", [])
    if len(stmts) != 1 or stmts[0].get("nodeType") != "Return":
        return False
    expr = stmts[0].get("expression") or {}
    return expr.get("nodeType") == "FunctionCall" and expr.get("expression", {}).get("name") == name


def is_trivial(fn: Node) -> bool:
    """A body that does nothing a caller could care about: empty, a bare revert,
    or returning only selectors / zero deltas / literals."""
    body = fn.get("body")
    if not body:
        return True
    stmts = body.get("statements", [])
    if not stmts:
        return True
    if len(stmts) != 1:
        return False
    s = stmts[0]
    if s.get("nodeType") == "RevertStatement":
        return True
    if s.get("nodeType") == "ExpressionStatement":
        e = s.get("expression", {})
        return e.get("nodeType") == "FunctionCall" and e.get("expression", {}).get("name") in ("revert",)
    if s.get("nodeType") != "Return":
        return False
    expr = s.get("expression")
    if expr is None:
        return True
    parts = expr.get("components", [expr]) if expr.get("nodeType") == "TupleExpression" else [expr]
    return all(_is_constant_ret(p) for p in parts if p)


def _is_constant_ret(e: Node) -> bool:
    nt = e.get("nodeType")
    if nt == "Literal":
        return True
    if nt == "MemberAccess" and e.get("memberName") in ("selector", "ZERO_DELTA"):
        return True
    if nt == "FunctionCall":
        # BalanceDelta.wrap(0), toBeforeSwapDelta(0, 0), uint24(0)
        return all(_is_constant_ret(a) for a in e.get("arguments", []))
    return False


def resolve_callback(contract: Contract, name: str, prefix: str = "") -> tuple[Node, Contract] | None:
    for n in (CALLBACKS.get(name), *LEGACY_ARITY.get(name, ())):
        if n is not None:
            found = contract.resolve(prefix + name, n)
            if found:
                return found
    return None


def always_reverts(fn: Node) -> bool:
    """The whole body is one unconditional revert."""
    stmts = (fn.get("body") or {}).get("statements", [])
    if len(stmts) != 1:
        return False
    s = stmts[0]
    if s.get("nodeType") == "RevertStatement":
        return True
    e = s.get("expression", {}) if s.get("nodeType") == "ExpressionStatement" else {}
    return e.get("nodeType") == "FunctionCall" and e.get("expression", {}).get("name") == "revert"


def initializes_own_pool(hook: Hook) -> bool:
    """The hook calls PoolManager.initialize itself. PoolManager skips a hook's
    callbacks when the hook is the caller, so such a hook can create its pools
    while its initialize callbacks reject everyone else."""
    for c in hook.contract.linearized():
        for f in c.own_functions():
            for call in of_type(f.get("body"), "FunctionCall"):
                expr = call.get("expression", {})
                if (
                    expr.get("nodeType") == "MemberAccess"
                    and expr.get("memberName") == "initialize"
                    and "PoolManager" in type_string(expr.get("expression", {}))
                ):
                    return True
    return False


def reverts_or_requires(nodes: list[Node]) -> list[Node]:
    """Every condition that gates execution: require(cond), if (cond) revert."""
    conds: list[Node] = []
    for root in nodes:
        for call in of_type(root.get("body"), "FunctionCall"):
            if call.get("expression", {}).get("name") in ("require", "assert") and call.get("arguments"):
                conds.append(call["arguments"][0])
        # Inline assembly: `if iszero(eq(caller(), pm)) { revert(...) }`. The YulIf
        # condition is returned as-is; consumers read Yul calls and identifiers.
        for asm in of_type(root.get("body"), "InlineAssembly"):
            for yif in of_type(asm.get("AST"), "YulIf"):
                if any(c.get("functionName", {}).get("name") == "revert" for c in of_type(yif.get("body"), "YulFunctionCall")):
                    conds.append(yif["condition"])
        for if_ in of_type(root.get("body"), "IfStatement"):
            branch = if_.get("trueBody", {})
            if any(True for _ in of_type(branch, "RevertStatement")) or any(
                c.get("expression", {}).get("name") == "revert" for c in of_type(branch, "FunctionCall")
            ):
                conds.append(if_["condition"])
    return conds


# ── state effects ──


def mutable_state_var_ids(hook: Hook) -> set[int]:
    return {v["id"] for v in hook.contract.state_vars() if not v.get("constant") and v.get("mutability") != "immutable"}


def storage_target(expr: Node, hook: Hook, keyed_by=None) -> tuple[str, bool] | None:
    """(state var name, keyed) for an lvalue, or None if it isn't storage. ``keyed``
    is True if any index on the way down satisfies ``keyed_by``."""
    keyed = False
    ids = mutable_state_var_ids(hook)
    while True:
        nt = expr.get("nodeType")
        if nt == "IndexAccess":
            if keyed_by and keyed_by(expr.get("indexExpression") or {}):
                keyed = True
            expr = expr.get("baseExpression", {})
        elif nt == "MemberAccess":
            expr = expr.get("expression", {})
        elif nt == "Identifier":
            if expr.get("referencedDeclaration") in ids:
                return expr["name"], keyed
            decl = hook.unit.by_id.get(expr.get("referencedDeclaration", -1)) or {}
            if decl.get("nodeType") == "VariableDeclaration" and decl.get("storageLocation") == "storage" \
                    and not decl.get("stateVariable"):
                # A local storage pointer (`Info storage i = info[id]; i.x = ...`). Where it
                # points isn't tracked, so callers that care about keying treat it as keyed.
                return expr["name"], keyed_by is not None
            return None
        else:
            return None


def lvalues(fn: Node) -> list[Node]:
    out = [a["leftHandSide"] for a in of_type(fn.get("body"), "Assignment")]
    out += [u["subExpression"] for u in of_type(fn.get("body"), "UnaryOperation")
            if u.get("operator") in ("++", "--", "delete")]
    return out


def is_state_changing_external_call(call: Node) -> bool:
    """A call through an external function type that isn't view/pure."""
    expr = call.get("expression", {})
    if expr.get("nodeType") != "MemberAccess":
        return False
    ts = type_string(expr)
    if not ts.startswith("function") or " external" not in ts:
        return expr.get("memberName") in ("transfer", "send", "call") and "address" in type_string(
            expr.get("expression", {}))
    return " view" not in ts and " pure" not in ts


YUL_EFFECTS = {"sstore", "tstore", "call", "callcode", "delegatecall", "create", "create2", "selfdestruct"}


def has_effects(hook: Hook, fns: list[Node]) -> bool:
    """Writes storage or makes a state-changing external call on any reachable path."""
    for f in fns:
        if any(storage_target(lv, hook) for lv in lvalues(f)):
            return True
        for y in of_type(f.get("body"), "YulFunctionCall"):
            if (y.get("functionName") or {}).get("name") in YUL_EFFECTS:
                return True
        if any(is_state_changing_external_call(c) for c in of_type(f.get("body"), "FunctionCall")):
            return True
    return False


# ── confidence ──


def state_vars_read_in_checks(hook: Hook) -> set[str]:
    """Names of hook state variables that some require/if-revert anywhere in the
    contract reads: state that gates behaviour, as opposed to a cosmetic record."""
    ids = mutable_state_var_ids(hook)
    names: set[str] = set()
    for c in hook.contract.linearized():
        bodies = [n for n in c.node.get("nodes", []) if n.get("nodeType") in ("FunctionDefinition", "ModifierDefinition")]
        for cond in reverts_or_requires(bodies):
            for n in of_type(cond, "Identifier"):
                if n.get("referencedDeclaration") in ids:
                    names.add(n["name"])
    return names


def _address_index(expr: Node) -> bool:
    """An index computed from an address (a per-user ledger), as opposed to a pool id."""
    return any(type_string(n) in ("address", "address payable") for n in of_type(expr, "Identifier", "MemberAccess", "FunctionCall"))


def state_var_readers(hook: Hook, exclude: set[int]) -> dict[str, set[str]]:
    """State variable name -> names of the other functions that read it. Compiler-made
    getters don't count, so a counter only ever read from outside isn't a consequence."""
    ids = mutable_state_var_ids(hook)
    out: dict[str, set[str]] = {}
    for c in hook.contract.linearized():
        for f in c.own_functions():
            if f["id"] in exclude or not f.get("body"):
                continue
            written = {id(lv) for lv in lvalues(f)}
            for n in of_type(f.get("body"), "Identifier"):
                if n.get("referencedDeclaration") in ids and id(n) not in written:
                    out.setdefault(n["name"], set()).add(f.get("name") or f.get("kind", "?"))
    return out


def consequences(hook: Hook, fns: list[Node]) -> list[str]:
    """What a direct call to this code can visibly do beyond writing a record:
    call out (incl. token transfers and PoolManager actions), move ETH, or write
    state that another check reads."""
    reasons: set[str] = set()
    gated = state_vars_read_in_checks(hook)
    readers = state_var_readers(hook, exclude={f["id"] for f in fns})
    for f in fns:
        for call in of_type(f.get("body"), "FunctionCall"):
            if is_state_changing_external_call(call):
                reasons.add(f"calls {call['expression'].get('memberName')}")
        for y in of_type(f.get("body"), "YulFunctionCall"):
            if (y.get("functionName") or {}).get("name") in ("call", "delegatecall", "callcode"):
                reasons.add("low-level call")
            elif (y.get("functionName") or {}).get("name") in ("sstore", "tstore"):
                reasons.add(f"assembly {y['functionName']['name']}")  # readers can't be traced
        for lv in lvalues(f):
            t = storage_target(lv, hook)
            if t and t[0] in gated:
                reasons.add(f"writes {t[0]} (read by a check)")
            elif t and t[0] in readers:
                reasons.add(f"writes {t[0]} (read by {', '.join(sorted(readers[t[0]]))})")
            elif t and storage_target(lv, hook, keyed_by=_address_index)[1]:
                reasons.add(f"credits {t[0]}[address]")
    return sorted(reasons)
