"""Read the flags a hook's getHookPermissions() returns, straight from the AST."""

from __future__ import annotations

from ..solast import Node, of_type
from .base import Hook

FLAGS = [
    "beforeInitialize",
    "afterInitialize",
    "beforeAddLiquidity",
    "afterAddLiquidity",
    "beforeRemoveLiquidity",
    "afterRemoveLiquidity",
    "beforeSwap",
    "afterSwap",
    "beforeDonate",
    "afterDonate",
    "beforeSwapReturnDelta",
    "afterSwapReturnDelta",
    "afterAddLiquidityReturnDelta",
    "afterRemoveLiquidityReturnDelta",
    # Pre-release Hooks.Calls (getHooksCalls)
    "beforeModifyPosition",
    "afterModifyPosition",
]
# A *ReturnDelta flag is only legal alongside its base callback flag.
RETURN_DELTA_BASE = {
    "beforeSwapReturnDelta": "beforeSwap",
    "afterSwapReturnDelta": "afterSwap",
    "afterAddLiquidityReturnDelta": "afterAddLiquidity",
    "afterRemoveLiquidityReturnDelta": "afterRemoveLiquidity",
}

Flags = dict[str, "bool | None"]


def permissions_function(hook: Hook) -> Node | None:
    """getHookPermissions(), or else the zero-argument function returning
    Hooks.Permissions that the hook calls (e.g. Angstrom's free function
    getRequiredHookPermissions(), passed to validateHookPermissions)."""
    found = hook.contract.resolve("getHookPermissions", 0) or hook.contract.resolve("getHooksCalls", 0)
    if found:
        return found[0]
    for c in hook.contract.linearized():
        for f in c.own_functions():
            for call in of_type(f.get("body"), "FunctionCall"):
                ref = hook.unit.by_id.get(call.get("expression", {}).get("referencedDeclaration", -1))
                if (
                    ref
                    and ref.get("nodeType") == "FunctionDefinition"
                    and ref.get("implemented")
                    and not ref["parameters"]["parameters"]
                    and _returns_permissions(ref)
                ):
                    return ref
    return None


def _returns_permissions(fn: Node) -> bool:
    rets = (fn.get("returnParameters") or {}).get("parameters", [])
    ts = (rets[0].get("typeDescriptions") or {}).get("typeString", "") if len(rets) == 1 else ""
    return ts.startswith("struct ") and ts.endswith((".Permissions", ".Calls"))


def parse_permissions(hook: Hook) -> Flags | None:
    """{flag: True/False/None(unknown)}, or None if there is no getHookPermissions.

    Handles the shapes seen in practice:
      return Hooks.Permissions({beforeSwap: true, ...});   (named)
      return Hooks.Permissions(true, false, ...);           (positional)
      p = Hooks.Permissions(...);  /  Permissions memory p = Hooks.Permissions(...);
      Permissions memory p; p.beforeSwap = true; return p;  (field writes)
    """
    fn = permissions_function(hook)
    if fn is None:
        return None
    body = fn.get("body") or {}
    ctors = [(r.get("expression") or {}) for r in of_type(body, "Return")]
    ctors += [a.get("rightHandSide") or {} for a in of_type(body, "Assignment")]  # p = Hooks.Permissions(...)
    ctors += [d.get("initialValue") or {} for d in of_type(body, "VariableDeclarationStatement")]
    for expr in ctors:
        if expr.get("nodeType") == "FunctionCall" and expr.get("kind") == "structConstructorCall":
            names = expr.get("names") or _struct_fields(hook, expr) or FLAGS
            return {f: None for f in FLAGS} | {
                n: _literal_bool(a) for n, a in zip(names, expr.get("arguments", [])) if n in FLAGS
            }
    # Field-write form: memory structs start zeroed, so unspecified flags are false.
    flags: Flags = {f: False for f in FLAGS}
    for asg in of_type(body, "Assignment"):
        lhs = asg.get("leftHandSide", {})
        if lhs.get("nodeType") == "MemberAccess" and lhs.get("memberName") in FLAGS:
            flags[lhs["memberName"]] = _literal_bool(asg.get("rightHandSide", {}))
    return flags


def _struct_fields(hook: Hook, ctor: Node) -> list[str]:
    """Field names of the struct a positional constructor builds, in declaration
    order (Hooks.Permissions and the pre-release Hooks.Calls differ)."""
    ref = (ctor.get("expression") or {}).get("referencedDeclaration")
    struct = hook.unit.by_id.get(ref) if ref is not None else None
    if not struct or struct.get("nodeType") != "StructDefinition":
        return []
    return [m.get("name") for m in struct.get("members", [])]


def _literal_bool(node: Node) -> bool | None:
    if node.get("nodeType") == "Literal" and node.get("kind") == "bool":
        return node.get("value") == "true"
    return None
