"""V4H-03: permission flags disagree with the callbacks the hook implements.

In v4 the PoolManager decides which callbacks to call from the low bits of the
hook's address, which must match getHookPermissions(). Mismatches fail silently:
  * flag on, callback not implemented -> BaseHook's default reverts, pool bricked
  * callback implemented, flag off    -> logic (often a guard) never runs
  * *ReturnDelta on without its base  -> address can never be valid
  * permissions never validated       -> a mis-mined address goes unnoticed
"""

from __future__ import annotations

from ..model import HookFinding
from ..solast import Node, callee_name, of_type
from .base import CALLBACKS, Hook, always_reverts, initializes_own_pool, is_trivial
from .permissions import RETURN_DELTA_BASE, parse_permissions, permissions_function


class PermissionBitMismatch:
    id = "V4H-03"
    title = "Hook permission flags do not match implemented callbacks"

    def run(self, hook: Hook) -> list[HookFinding]:
        flags = parse_permissions(hook)
        perm_fn = permissions_function(hook)
        if flags is None or perm_fn is None:
            return []
        findings = []
        for name in CALLBACKS:
            flag = flags.get(name)
            impl = hook.implementation(name)
            if flag is True and (impl is None or _is_unimplemented_default(impl)) \
                    and not _deliberate_block(hook, flags, name) and not _serving_fallback(hook):
                findings.append(
                    hook.finding(
                        self.id, self.title, "high", perm_fn,
                        f"{hook.name} enables `{name}` in getHookPermissions but never implements it "
                        "(the inherited default reverts). Every pool operation that triggers it will revert.",
                        confidence="confirmed", callback=name, flag=True, implemented=False,
                    )
                )
            elif flag is False and impl is not None and not is_trivial(impl[0]):
                findings.append(
                    hook.finding(
                        self.id, self.title, "medium", impl[0],
                        f"{hook.name} implements `{name}` but its permission flag is false, so the "
                        "PoolManager never calls it. Any checks or accounting in it are dead code.",
                        callback=name, flag=False, implemented=True,
                    )
                )
        for delta_flag, base in RETURN_DELTA_BASE.items():
            impl = hook.implementation(base)
            if flags.get(delta_flag) is False and flags.get(base) and impl and _returns_nonzero_delta(impl[0]):
                findings.append(
                    hook.finding(
                        self.id, self.title, "high", impl[0],
                        f"{hook.name}.{base} returns a non-zero delta but `{delta_flag}` is off, so the "
                        "PoolManager ignores it: the hook's side of the delta is never accounted and the "
                        "operation fails to settle.",
                        confidence="confirmed", callback=base, flag=delta_flag, returns_delta=True,
                    )
                )
            if flags.get(delta_flag) is True and flags.get(base) is False:
                findings.append(
                    hook.finding(
                        self.id, self.title, "medium", perm_fn,
                        f"{hook.name} sets `{delta_flag}` without `{base}`; no hook address can satisfy "
                        "these flags.",
                        confidence="confirmed", callback=base, flag=delta_flag,
                    )
                )
        if not _validates_address(hook):
            findings.append(
                hook.finding(
                    self.id, self.title, "info", perm_fn,
                    f"{hook.name} declares permissions but never calls Hooks.validateHookPermissions, so a "
                    "deployment whose address bits differ from getHookPermissions() is not caught.",
                    callback=None, validated=False,
                )
            )
        return findings


def _is_unimplemented_default(impl: tuple[Node, object]) -> bool:
    """The inherited BaseHook placeholder. A hook that deliberately overrides a
    callback to revert (e.g. to force liquidity through the hook) is not flagged."""
    fn, declaring = impl
    if not always_reverts(fn):
        return False
    if getattr(declaring, "name", "") == "BaseHook":
        return True
    return any(
        n.get("name") == "HookNotImplemented" or n.get("memberName") == "HookNotImplemented"
        for n in of_type(fn.get("body"), "Identifier", "MemberAccess")
    )


def _serving_fallback(hook: Hook) -> bool:
    """A fallback() that does not always revert may serve any callback by selector
    (seen in assembly-dispatching hooks), so "never implements" can't be confirmed."""
    for c in hook.contract.linearized():
        for f in c.own_functions():
            if f.get("kind") == "fallback" and f.get("implemented") and not always_reverts(f):
                return True
    return False


def _deliberate_block(hook: Hook, flags: dict, name: str) -> bool:
    """A reverting placeholder that cannot brick anything, or that blocks an action on purpose.

    * beforeInitialize: the hook creates its own pools (PoolManager skips self-calls),
      so the revert only stops foreign pools.
    * afterInitialize: unreachable when beforeInitialize rejects every caller and the
      hook creates its own pools.
    * before{Add,Remove}Liquidity / beforeDonate on a custom curve (beforeSwapReturnDelta): the
      pool's v4 liquidity is unused, and blocking it keeps users from stranding funds.
    """
    if name == "beforeInitialize":
        return initializes_own_pool(hook)
    if name == "afterInitialize":
        before = hook.implementation("beforeInitialize")
        return bool(flags.get("beforeInitialize")) and before is not None and always_reverts(before[0]) \
            and initializes_own_pool(hook)
    if name in ("beforeAddLiquidity", "beforeRemoveLiquidity", "beforeDonate"):
        return bool(flags.get("beforeSwapReturnDelta"))
    return False


def _returns_nonzero_delta(fn: Node) -> bool:
    """Some return path yields a delta (2nd return value) that is not a constant zero."""
    returns = (fn.get("returnParameters") or {}).get("parameters", [])
    if len(returns) < 2:
        return False
    for ret in of_type(fn.get("body"), "Return"):
        expr = ret.get("expression") or {}
        parts = expr.get("components", []) if expr.get("nodeType") == "TupleExpression" else []
        if len(parts) >= 2 and parts[1] and not _is_zero(parts[1], fn):
            return True
    return False


def _is_zero(e: Node, fn: Node | None = None) -> bool:
    if e.get("nodeType") == "Identifier" and fn is not None:
        return _local_always_zero(e.get("referencedDeclaration"), fn)
    if e.get("nodeType") == "Literal":
        return e.get("value") in ("0", "0x0", "false")
    if e.get("nodeType") == "MemberAccess" and e.get("memberName") == "ZERO_DELTA":
        return True
    if e.get("nodeType") == "FunctionCall":  # int128(0), toBeforeSwapDelta(0, 0), BalanceDelta.wrap(0)
        return bool(e.get("arguments")) and all(_is_zero(a) for a in e["arguments"])
    return False


def _local_always_zero(decl_id: int | None, fn: Node, seen: frozenset = frozenset()) -> bool:
    """A local or named return whose every value in ``fn`` is a constant zero
    (`BeforeSwapDelta d = BeforeSwapDelta.wrap(0); return (.., d, ..)`).
    Parameters and state variables are unknown, so they are not zero."""
    if decl_id in seen:
        return False
    seen = seen | {decl_id}
    declared = [d for d in of_type(fn.get("body"), "VariableDeclarationStatement")
                if any(x and x.get("id") == decl_id for x in d.get("declarations", []))]
    is_return = any(p.get("id") == decl_id for p in (fn.get("returnParameters") or {}).get("parameters", []))
    if not declared and not is_return:
        return False
    values = [d.get("initialValue") for d in declared]  # None = uninitialised = zero
    for asg in of_type(fn.get("body"), "Assignment"):
        lhs = asg.get("leftHandSide", {})
        if lhs.get("nodeType") == "Identifier" and lhs.get("referencedDeclaration") == decl_id:
            if asg.get("operator") != "=":
                return False  # `d += x`
            values.append(asg.get("rightHandSide"))
    return all(v is None or _is_zero_seen(v, fn, seen) for v in values)


def _is_zero_seen(e: Node, fn: Node, seen: frozenset) -> bool:
    if e.get("nodeType") == "Identifier":
        return _local_always_zero(e.get("referencedDeclaration"), fn, seen)
    return _is_zero(e, fn)


def _validates_address(hook: Hook) -> bool:
    for c in hook.contract.linearized():
        for f in c.own_functions():
            if any(callee_name(call) in ("validateHookPermissions", "_validateHookAddress", "validateHookAddress")  # last: pre-release API
                   for call in of_type(f.get("body"), "FunctionCall")):
                return True
    return False
