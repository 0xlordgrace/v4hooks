"""V4H-01: hook callbacks reachable by anyone, not just the PoolManager.

Trail of Bits, "Building secure Uniswap v4 hooks": every IHooks callback and
unlockCallback must revert unless msg.sender is the PoolManager. Otherwise anyone
can call the hook directly with a forged PoolKey, params and hookData.
"""

from __future__ import annotations

from ..model import HookFinding
from ..solast import Node, is_msg_sender, of_type, type_string
from .base import (
    CALLBACKS,
    UNLOCK_CALLBACKS,
    Hook,
    always_reverts,
    consequences,
    has_effects,
    is_trivial,
    reverts_or_requires,
)
from .permissions import parse_permissions


class MissingCallerCheck:
    id = "V4H-01"
    title = "Hook callback not restricted to PoolManager"

    def run(self, hook: Hook) -> list[HookFinding]:
        flags = parse_permissions(hook) or {}
        findings = []
        for name in [*CALLBACKS, *UNLOCK_CALLBACKS]:
            entry = hook.callback(name) if name not in UNLOCK_CALLBACKS else _resolve_unlock(hook, name)
            if entry is None:
                continue
            fn, _ = entry
            if fn.get("visibility") not in ("external", "public"):
                continue
            # A view/pure callback cannot change state or move funds, whoever calls it.
            if fn.get("stateMutability") in ("view", "pure"):
                continue
            # An unused no-op callback is harmless; only check ones that do something
            # or that PoolManager is configured to call.
            impl = hook.implementation(name) if name not in UNLOCK_CALLBACKS else entry
            # A callback that can only revert does nothing for a direct caller to abuse.
            if always_reverts(fn) or (impl is not None and always_reverts(impl[0])):
                continue
            if not flags.get(name) and (impl is None or is_trivial(impl[0])):
                continue
            # Nothing to abuse if no path writes storage or calls out (e.g. check-and-return).
            if not has_effects(hook, hook.contract.reachable(fn)):
                continue
            pm_checks, other_checks = classify_sender_checks(hook, fn)
            if pm_checks:
                continue
            if other_checks:
                msg = (
                    f"{hook.name}.{name} checks msg.sender, but against "
                    f"{', '.join(sorted(other_checks))} rather than the PoolManager."
                )
            else:
                msg = f"{hook.name}.{name} has no msg.sender check on any path (function, modifiers, internal calls)."
            why = consequences(hook, hook.contract.reachable(fn))
            if not why:
                msg += (" No visible consequence: it only writes state that no other function reads"
                        " (e.g. a template counter), so this is reported as informational.")
            findings.append(
                hook.finding(
                    self.id,
                    self.title,
                    "high" if why else "info",
                    fn,
                    msg + " Anyone can invoke it directly with arbitrary arguments.",
                    confidence="confirmed" if why else "pattern",
                    consequences=why,
                    callback=name,
                    sender_checked_against=sorted(other_checks),
                    permission_enabled=flags.get(name),
                )
            )
        return findings


def _resolve_unlock(hook: Hook, name: str):
    for n in UNLOCK_CALLBACKS[name]:
        found = hook.contract.resolve(name, n)
        if found:
            return found
    return None


def classify_sender_checks(hook: Hook, fn: Node) -> tuple[list[str], set[str]]:
    """Split msg.sender guards reachable from ``fn`` into PoolManager / other."""
    pm, other = [], set()
    for cond in reverts_or_requires(hook.contract.reachable(fn)):
        if cond.get("nodeType", "").startswith("Yul"):
            _classify_yul(hook, cond, pm, other)
            continue
        for cmp in of_type(cond, "BinaryOperation"):
            if cmp.get("operator") not in ("==", "!="):
                continue
            left, right = cmp["leftExpression"], cmp["rightExpression"]
            if is_msg_sender(left):
                peer = right
            elif is_msg_sender(right):
                peer = left
            else:
                continue
            if _mentions_pool_manager(peer):
                pm.append(hook.unit.snippet(cond, 1))
            else:
                other.add(_describe(peer))
    return pm, other


def _classify_yul(hook: Hook, cond: Node, pm: list[str], other: set[str]) -> None:
    """eq(caller(), x) inside an assembly guard. ``x`` is a Solidity variable the
    assembly reads, identified by name (and, when it is a local, by its type)."""
    for call in of_type(cond, "YulFunctionCall"):
        if call.get("functionName", {}).get("name") != "eq":
            continue
        args = call.get("arguments", [])
        callers = [a for a in args if a.get("nodeType") == "YulFunctionCall" and a["functionName"]["name"] == "caller"]
        if not callers:
            continue
        for peer in (a for a in args if a not in callers):
            name = peer.get("name", "") if peer.get("nodeType") == "YulIdentifier" else "?"
            if "poolmanager" in name.lower():
                pm.append(f"assembly: eq(caller(), {name})")
            else:
                other.add(name)


def _mentions_pool_manager(expr: Node) -> bool:
    for n in of_type(expr, "Identifier", "MemberAccess", "FunctionCall"):
        if "IPoolManager" in type_string(n) or "PoolManager" in type_string(n):
            return True
        name = (n.get("name") or n.get("memberName") or "").lower()
        if "poolmanager" in name:
            return True
    return False


def _describe(expr: Node) -> str:
    for n in of_type(expr, "Identifier", "MemberAccess"):
        return n.get("name") or n.get("memberName") or "?"
    return "?"
