"""Load solc compact-JSON ASTs from Foundry build-info and query them.

Everything the detectors know about the code comes from here. We read the AST
solc itself produced (via ``forge build --build-info``), so there is no parser of
our own to get wrong, and the same compiler version always yields the same tree.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

Node = dict[str, Any]


class BuildError(RuntimeError):
    pass


# ── loading ──────────────────────────────────────────────────────────────────


def forge_build(project: Path, out_dir: Path | None = None) -> Path:
    """Run ``forge build`` with build-info into a fresh directory and return it.

    ``--force`` plus a fresh directory means every source is in the output: a
    cached build would leave unchanged files out of the new build-info.
    """
    forge = shutil.which("forge")
    if not forge:
        raise BuildError("forge not found on PATH (install Foundry: https://getfoundry.sh)")
    out_dir = Path(out_dir or tempfile.mkdtemp(prefix="v4hooks-bi-"))
    proc = _run_forge(forge, project, out_dir, via_ir=False)
    if proc.returncode != 0 and "stack too deep" in (proc.stdout + proc.stderr).lower():
        # Many production hooks only compile through the IR pipeline.
        proc = _run_forge(forge, project, out_dir, via_ir=True)
    if proc.returncode != 0:
        raise BuildError(f"forge build failed in {project}:\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    return out_dir


def _run_forge(forge: str, project: Path, out_dir: Path, via_ir: bool) -> subprocess.CompletedProcess:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    cmd = [forge, "build", "--build-info", "--build-info-path", str(out_dir), "--force", "--skip", "test", "script"]
    if via_ir:
        cmd.append("--via-ir")
    return subprocess.run(cmd, cwd=project, capture_output=True, text=True)


def load_build_info(build_info_dir: Path) -> list[Unit]:
    """One Unit per build-info file (one per solc version/compilation)."""
    units = []
    for path in sorted(Path(build_info_dir).glob("*.json")):
        data = json.loads(path.read_text())
        sources = {p: s["ast"] for p, s in data["output"]["sources"].items() if "ast" in s}
        contents = {p: s.get("content", "") for p, s in data["input"]["sources"].items()}
        units.append(Unit(sources=sources, contents=contents, solc=data.get("solcLongVersion", "")))
    return units


def load_ast_json(path: Path) -> Unit:
    """Load a unit from a minimal fixture: {"sources": {path: {"ast":..., "content":...}}}.

    Used by unit tests so they run without forge.
    """
    data = json.loads(Path(path).read_text())
    return Unit(
        sources={p: s["ast"] for p, s in data["sources"].items()},
        contents={p: s.get("content", "") for p, s in data["sources"].items()},
        solc=data.get("solc", ""),
    )


# ── tree helpers ─────────────────────────────────────────────────────────────


def walk(node: Any) -> Iterator[Node]:
    """Yield every AST node under ``node`` (inclusive), depth-first, in source order."""
    if isinstance(node, dict):
        if "nodeType" in node:
            yield node
        for key, value in node.items():
            if key in ("typeDescriptions", "documentation"):
                continue
            if isinstance(value, dict | list):
                yield from walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk(item)


def of_type(node: Any, *types: str) -> Iterator[Node]:
    return (n for n in walk(node) if n["nodeType"] in types)


def type_string(node: Node) -> str:
    return (node.get("typeDescriptions") or {}).get("typeString") or ""


def is_msg_sender(node: Node) -> bool:
    return (
        node.get("nodeType") == "MemberAccess"
        and node.get("memberName") == "sender"
        and node.get("expression", {}).get("name") == "msg"
    )


def callee_name(call: Node) -> str:
    expr = call.get("expression", {})
    if expr.get("nodeType") == "Identifier":
        return expr.get("name", "")
    if expr.get("nodeType") == "MemberAccess":
        return expr.get("memberName", "")
    return ""


# ── model ────────────────────────────────────────────────────────────────────


@dataclass
class Unit:
    sources: dict[str, Node]
    contents: dict[str, str]
    solc: str = ""
    by_id: dict[int, Node] = field(default_factory=dict, repr=False)
    _file_of: dict[int, str] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for path, ast in self.sources.items():
            for n in walk(ast):
                if "id" in n:  # Yul nodes inside inline assembly have no id
                    self.by_id[n["id"]] = n
            self._file_of[ast.get("id", -1)] = path
        # solc's src is "start:length:sourceIndex"; map index -> path via SourceUnit ids
        self._index_to_path: dict[int, str] = {}
        self.library_functions: set[int] = {
            f["id"]
            for n in self.by_id.values()
            if n.get("nodeType") == "ContractDefinition" and n.get("contractKind") == "library"
            for f in n.get("nodes", [])
            if f.get("nodeType") == "FunctionDefinition" and f.get("implemented")
        }
        for path, ast in self.sources.items():
            if "src" not in ast:  # forge's dynamic-test-linking stubs (foundry-pp/) have no AST location
                continue
            idx = int(ast["src"].split(":")[2])
            self._index_to_path[idx] = path

    def contracts(self) -> Iterator[Contract]:
        for path in sorted(self.sources):
            for n in self.sources[path].get("nodes", []):
                if n.get("nodeType") == "ContractDefinition":
                    yield Contract(self, n, path)

    def contract(self, cid: int) -> Contract | None:
        n = self.by_id.get(cid)
        if not n or n.get("nodeType") != "ContractDefinition":
            return None
        return Contract(self, n, self.path_of(n))

    def path_of(self, node: Node) -> str:
        return self._index_to_path.get(int(node["src"].split(":")[2]), "")

    def location(self, node: Node) -> tuple[str, int, int]:
        """(file, start_line, end_line), 1-based."""
        start, length, idx = (int(x) for x in node["src"].split(":"))
        path = self._index_to_path.get(idx, "")
        text = self.contents.get(path, "")
        if not text:
            return path, 0, 0
        raw = text.encode()
        line_start = raw[:start].count(b"\n") + 1
        line_end = raw[: start + length].count(b"\n") + 1
        return path, line_start, line_end

    def snippet(self, node: Node, max_lines: int = 40) -> str:
        path, a, b = self.location(node)
        lines = self.contents.get(path, "").splitlines()
        return "\n".join(lines[a - 1 : min(b, a - 1 + max_lines)])


@dataclass
class Contract:
    unit: Unit
    node: Node
    path: str

    @property
    def id(self) -> int:
        return self.node["id"]

    @property
    def name(self) -> str:
        return self.node["name"]

    @property
    def kind(self) -> str:
        return self.node.get("contractKind", "contract")

    @property
    def abstract(self) -> bool:
        return bool(self.node.get("abstract"))

    def linearized(self) -> list[Contract]:
        """Most-derived first (solc's C3 order)."""
        out = []
        for cid in self.node.get("linearizedBaseContracts", [self.id]):
            c = self.unit.contract(cid)
            if c:
                out.append(c)
        return out

    def inherits(self, name: str) -> bool:
        return any(c.name == name for c in self.linearized())

    def own_functions(self) -> list[Node]:
        return [n for n in self.node.get("nodes", []) if n.get("nodeType") == "FunctionDefinition"]

    def own_state_vars(self) -> list[Node]:
        return [
            n
            for n in self.node.get("nodes", [])
            if n.get("nodeType") == "VariableDeclaration" and n.get("stateVariable")
        ]

    def state_vars(self) -> list[Node]:
        return [v for c in self.linearized() for v in c.own_state_vars()]

    def resolve(self, name: str, n_params: int | None = None, with_body: bool = True) -> tuple[Node, Contract] | None:
        """Most-derived definition of function ``name`` visible in this contract."""
        for c in self.linearized():
            for f in c.own_functions():
                if f.get("name") != name:
                    continue
                if n_params is not None and len(f["parameters"]["parameters"]) != n_params:
                    continue
                if with_body and not f.get("implemented"):
                    continue
                return f, c
        return None

    def resolve_modifier(self, name: str) -> Node | None:
        for c in self.linearized():
            for n in c.node.get("nodes", []):
                if n.get("nodeType") == "ModifierDefinition" and n.get("name") == name:
                    return n
        return None

    def reachable(self, fn: Node, max_depth: int = 6) -> list[Node]:
        """``fn`` plus every function/modifier body it reaches through internal
        calls and modifiers, with virtual calls resolved against this contract."""
        seen: set[int] = set()
        out: list[Node] = []

        def visit(f: Node, depth: int) -> None:
            if f["id"] in seen or depth > max_depth:
                return
            seen.add(f["id"])
            out.append(f)
            for inv in f.get("modifiers", []) or []:
                mname = inv.get("modifierName", {}).get("name")
                m = self.resolve_modifier(mname) if mname else None
                if m:
                    visit(m, depth + 1)
            for call in of_type(f.get("body"), "FunctionCall"):
                target = self._internal_target(call)
                if target is not None:
                    visit(target, depth + 1)

        visit(fn, 0)
        return out

    def _internal_target(self, call: Node) -> Node | None:
        expr = call.get("expression", {})
        if expr.get("nodeType") != "Identifier":
            # `this.f()` is an external self-call (not followed); super.f() and library
            # calls (`Lib.f(x)`, `x.f()` via `using for`) are MemberAccess too.
            if expr.get("nodeType") != "MemberAccess":
                return None
            ref_id = expr.get("referencedDeclaration", -1)
            ref = self.unit.by_id.get(ref_id)
            if expr.get("expression", {}).get("name") == "super":
                return ref if ref and ref.get("implemented") else None
            return ref if ref_id in self.unit.library_functions else None
        ref = self.unit.by_id.get(expr.get("referencedDeclaration", -1))
        if not ref or ref.get("nodeType") != "FunctionDefinition":
            return None
        if ref.get("virtual") or ref.get("overrides") or not ref.get("implemented"):
            found = self.resolve(ref["name"], len(ref["parameters"]["parameters"]))
            return found[0] if found else None
        return ref
