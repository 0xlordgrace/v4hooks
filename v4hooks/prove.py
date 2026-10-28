"""Proof step: turn V4H-01 findings into Foundry tests and run them.

For each finding a test deploys the hook (at an address carrying its permission bits,
with a stand-in PoolManager) or, with ``--fork-url``, uses the deployed address. It
then calls the flagged callback from an address that is not the PoolManager, with
plausible arguments built from the ABI. The finding is ``proven`` when that call
succeeds and writes hook storage. Anything else is reported with the reason, and the
finding stays a pattern match. Nothing here decides findings; it only checks them.

No forge-std: the test declares the few cheatcodes it needs, so it compiles against
any project that compiles at all.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import HookFinding

ATTACKER = 0xA77AC4E500000000000000000000000000000001
FAKE_PM = 0x9000000000000000000000000000000000000001
TEST_CONTRACT = 0x7FA9385BE102AC3EAC297483DD6233D62B3E1496  # forge's default test address
NO_WRITE = "V4H-PROOF: call succeeded but wrote no hook storage"
PROOF_DIR = "v4hooks_proof"

# v4-core release: permission flags are the low 14 bits of the hook address.
RELEASE_BITS = {
    "beforeInitialize": 13, "afterInitialize": 12,
    "beforeAddLiquidity": 11, "afterAddLiquidity": 10,
    "beforeRemoveLiquidity": 9, "afterRemoveLiquidity": 8,
    "beforeSwap": 7, "afterSwap": 6, "beforeDonate": 5, "afterDonate": 4,
    "beforeSwapReturnDelta": 3, "afterSwapReturnDelta": 2,
    "afterAddLiquidityReturnDelta": 1, "afterRemoveLiquidityReturnDelta": 0,
}  # fmt: skip
# Mid-2023 pre-release (Hooks.Calls): flags are the top bits.
CALLS_BITS = {
    "beforeInitialize": 159, "afterInitialize": 158,
    "beforeModifyPosition": 157, "afterModifyPosition": 156,
    "beforeSwap": 155, "afterSwap": 154, "beforeDonate": 153, "afterDonate": 152,
}  # fmt: skip
ADDRESS_BASE = 0x4444 << 64  # clear of both flag layouts (low 14 bits, top byte)


@dataclass
class Proof:
    fingerprint: str
    contract: str
    callback: str
    status: str  # proven | reaches-pm | reverted | no-effect | unsupported
    reason: str = ""
    test: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class ProofRun:
    proofs: list[Proof] = field(default_factory=list)
    forge_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"proofs": [p.to_dict() for p in self.proofs]}


# ── ABI encoding (standard head/tail layout) ──────────────────────────────────


def _split_array(t: str) -> tuple[str, int | None] | None:
    m = re.fullmatch(r"(.*)\[(\d*)\]", t)
    if not m:
        return None
    return m.group(1), int(m.group(2)) if m.group(2) else None


def _is_dynamic(inp: dict) -> bool:
    t = inp["type"]
    if t in ("bytes", "string"):
        return True
    arr = _split_array(t)
    if arr:
        inner, n = arr
        return n is None or _is_dynamic({**inp, "type": inner})
    if t == "tuple":
        return any(_is_dynamic(c) for c in inp["components"])
    return False


def _word(n: int) -> bytes:
    return (n % (1 << 256)).to_bytes(32, "big")


def _encode_seq(inputs: list[dict], values: list[Any]) -> bytes:
    heads, tails = [], b""
    head_len = sum(32 if _is_dynamic(i) else _static_size(i) for i in inputs)
    for inp, v in zip(inputs, values):
        enc = _encode(inp, v)
        if _is_dynamic(inp):
            heads.append(_word(head_len + len(tails)))
            tails += enc
        else:
            heads.append(enc)
    return b"".join(heads) + tails


def _static_size(inp: dict) -> int:
    arr = _split_array(inp["type"])
    if arr:
        return arr[1] * _static_size({**inp, "type": arr[0]})
    if inp["type"] == "tuple":
        return sum(_static_size(c) for c in inp["components"])
    return 32


def _encode(inp: dict, v: Any) -> bytes:
    t = inp["type"]
    arr = _split_array(t)
    if arr:
        inner = {**inp, "type": arr[0]}
        body = _encode_seq([inner] * len(v), list(v))
        return body if arr[1] is not None else _word(len(v)) + body
    if t == "tuple":
        return _encode_seq(inp["components"], list(v))
    if t in ("bytes", "string"):
        data = v.encode() if isinstance(v, str) else bytes(v)
        return _word(len(data)) + data + b"\0" * (-len(data) % 32)
    if t.startswith("bytes"):
        return bytes(v).ljust(32, b"\0")
    if t == "bool":
        return _word(1 if v else 0)
    return _word(int(v))  # address, uintN, intN (two's complement via _word)


def abi_encode(inputs: list[dict], values: list[Any]) -> bytes:
    return _encode_seq(inputs, values)


def selector_sig(entry: dict) -> str:
    def canon(i: dict) -> str:
        if i["type"].startswith("tuple"):
            return "(" + ",".join(canon(c) for c in i["components"]) + ")" + i["type"][5:]
        return i["type"]

    return f"{entry['name']}({','.join(canon(i) for i in entry['inputs'])})"


# ── plausible arguments ───────────────────────────────────────────────────────

_NAMED = {
    "fee": 3000, "tickspacing": 60, "sqrtpricex96": 1 << 96, "zeroforone": True,
    "amountspecified": -(10**18), "sqrtpricelimitx96": 4295128740,
    "ticklower": -120, "tickupper": 120, "liquiditydelta": 10**18,
}  # fmt: skip


def default_value(inp: dict, hook: int, pm: int) -> Any:
    """A value a real call might carry: the key names this hook, swaps and positions
    are small but non-zero, managers point at the PoolManager, other addresses are 0."""
    t, name = inp["type"], inp.get("name", "").lower()
    arr = _split_array(t)
    if arr:
        return [default_value({**inp, "type": arr[0]}, hook, pm) for _ in range(arr[1] or 0)]
    if t == "tuple":
        return [default_value(c, hook, pm) for c in inp["components"]]
    if t in ("bytes", "string"):
        return b""
    if t.startswith("bytes"):
        return b""
    if t == "address":
        if name == "hooks":
            return hook
        if "manager" in name or "PoolManager" in inp.get("internalType", ""):
            return pm
        return 0
    if name in _NAMED and t != "bool":
        return _NAMED[name]
    if t == "bool":
        return bool(_NAMED.get(name, False))
    return 0


_AMOUNTS = ("amountspecified", "liquiditydelta")


def variants(inputs: list[dict], hook: int, pm: int) -> list[bytes]:
    """Encoded argument sets to try: defaults first, then each combination of the
    bytes arguments (empty, the attacker's address, 512 zero bytes, which decode as any
    static struct) and zeroed amounts."""
    base = [default_value(i, hook, pm) for i in inputs]
    blobs = [b"", _word(ATTACKER), b"\0" * 512]
    out: list[bytes] = []
    for zero_amounts in (False, True):
        for blob in blobs:
            vals = [_override(i, v, blob, zero_amounts) for i, v in zip(inputs, base)]
            enc = abi_encode(inputs, vals)
            if enc not in out:
                out.append(enc)
    return out


def _override(inp: dict, v: Any, blob: bytes, zero_amounts: bool) -> Any:
    t = inp["type"]
    if t == "bytes":
        return blob
    if t == "tuple":
        return [_override(c, x, blob, zero_amounts) for c, x in zip(inp["components"], v)]
    if zero_amounts and inp.get("name", "").lower() in _AMOUNTS:
        return 0
    return v


def ctor_value(inp: dict, hook: int, pm: int) -> Any:
    """Constructor arguments: managers get the PoolManager, other addresses the test
    contract (so an `owner` argument is someone the test controls)."""
    if inp["type"] == "address" and not ("manager" in inp.get("name", "").lower()
                                         or "PoolManager" in inp.get("internalType", "")):
        return TEST_CONTRACT
    return default_value(inp, hook, pm)


# ── addresses ─────────────────────────────────────────────────────────────────


def hook_address(flags: dict[str, bool | None], abi: list[dict]) -> int | None:
    """Address whose bits encode ``flags``, or None for an API we can't encode."""
    names = {e.get("name") for e in abi if e.get("type") == "function"}
    bits = CALLS_BITS if "getHooksCalls" in names else RELEASE_BITS
    if any(v and k not in bits for k, v in flags.items()):
        return None
    addr = ADDRESS_BASE
    for k, v in flags.items():
        if v:
            addr |= 1 << bits[k]
    return addr


def _addr(n: int) -> str:
    return f"address(uint160(uint256(0x00{n:040x})))"  # 00 prefix: not an address literal


# ── test generation ───────────────────────────────────────────────────────────

VM_INTERFACE = """interface V4HVm {
    function prank(address) external;
    function record() external;
    function accesses(address) external returns (bytes32[] memory reads, bytes32[] memory writes);
    function etch(address, bytes calldata) external;
}"""


# Fake PoolManager runtime: SLOAD slot 0 (so a call shows up in vm.accesses, even a
# staticcall) and return 256 zero bytes, which decodes as zero for any static return.
FAKE_PM_CODE = "60005450" + "6101006000f3"
SILENT_REVERT = "V4H-PROOF: every attempt reverted without a reason"
REACHED_PM = "V4H-PROOF: no hook storage written, but the call reached the PoolManager"


@dataclass
class Case:
    finding: HookFinding
    artifact: str  # "path/File.sol:Name"
    variants: list[bytes]  # ABI-encoded arguments; the selector is computed in Solidity
    hook: int
    ctor_args: bytes | None  # None: fork mode, the hook is already deployed
    sig: str
    pm: int = FAKE_PM
    creation: str = ""  # creation bytecode (hex) from the build-info


def render(cases: list[Case]) -> str:
    out = [
        "// SPDX-License-Identifier: UNLICENSED",
        "// Generated by `v4hooks prove`. Safe to delete.",
        "pragma solidity >=0.8.0;",
        "",
        VM_INTERFACE,
        "",
    ]
    for i, c in enumerate(cases):
        deploy = ""
        if c.ctor_args is not None:
            deploy = f"""
        vm.etch(pm, hex"{FAKE_PM_CODE}");
        bytes memory init = abi.encodePacked(hex"{c.creation}", hex"{c.ctor_args.hex()}");
        vm.etch(hook, init);
        (bool built, bytes memory runtime) = hook.call("");
        require(built, "V4H-PROOF: constructor reverted");
        vm.etch(hook, runtime);"""
        args = "".join(f'\n        args[{k}] = hex"{v.hex()}";' for k, v in enumerate(c.variants))
        out.append(f"""// {c.finding.detector} {c.finding.contract}.{c.sig}  ({c.finding.file}:{c.finding.line_start})
contract {_cname(i, c)} {{
    V4HVm constant vm = V4HVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function test_proof() public {{
        address hook = {_addr(c.hook)};
        address pm = {_addr(c.pm)};{deploy}
        bytes[] memory args = new bytes[]({len(c.variants)});{args}
        bytes memory firstRevert;
        bool reachedPm;
        bool anySucceeded;
        // Arguments are the attacker's to choose: try each variant, proven if any one
        // succeeds from a non-PoolManager address and writes hook storage.
        for (uint256 k = 0; k < args.length; k++) {{
            vm.record();
            vm.prank({_addr(ATTACKER)});
            (bool ok, bytes memory ret) = hook.call(abi.encodePacked(bytes4(keccak256("{c.sig}")), args[k]));
            if (!ok) {{
                if (k == 0) firstRevert = ret;
                continue;
            }}
            anySucceeded = true;
            (, bytes32[] memory writes) = vm.accesses(hook);
            if (writes.length > 0) return;
            (bytes32[] memory pmReads,) = vm.accesses(pm);
            if (pmReads.length > 0) reachedPm = true;
        }}
        if (reachedPm) revert("{REACHED_PM}");
        if (anySucceeded) revert("{NO_WRITE}");
        if (firstRevert.length == 0) revert("{SILENT_REVERT}");
        assembly {{ revert(add(firstRevert, 32), mload(firstRevert)) }}
    }}
}}
""")
    return "\n".join(out)


# ── driver ────────────────────────────────────────────────────────────────────


def load_abis(build_info_dir: Path) -> tuple[dict[tuple[str, str], list[dict]], dict[tuple[str, str], str]]:
    """ABIs and creation bytecode per (file, contract). The bytecode is embedded in the
    test, so it needs no artifact lookup (which a project's fs_permissions can block)."""
    abis: dict[tuple[str, str], list[dict]] = {}
    code: dict[tuple[str, str], str] = {}
    for path in sorted(Path(build_info_dir).glob("*.json")):
        data = json.loads(path.read_text())
        for file, contracts in (data.get("output", {}).get("contracts") or {}).items():
            for name, c in contracts.items():
                abis.setdefault((file, name), c.get("abi") or [])
                obj = ((c.get("evm") or {}).get("bytecode") or {}).get("object") or ""
                code.setdefault((file, name), obj.removeprefix("0x"))
    return abis, code


def _defining_file(abis: dict[tuple[str, str], list[dict]], f: HookFinding) -> str | None:
    """The source that defines ``f.contract``. The finding's own file is where the
    callback is written, which may be a base contract in another file."""
    if (f.file, f.contract) in abis:
        return f.file
    files = sorted(file for file, name in abis if name == f.contract)
    return files[0] if len(files) == 1 else None


def _cname(i: int, c: Case) -> str:
    return f"V4HProof_{i}_" + re.sub(r"\W", "_", c.finding.contract)


def flags_by_contract(units: list, scope: list[str] | None = None) -> dict[str, dict[str, bool | None]]:
    from .detectors.base import find_hooks
    from .detectors.permissions import parse_permissions

    return {h.name: parse_permissions(h) or {} for h in find_hooks(units, scope)}


def build_cases(
    findings: list[HookFinding],
    build_info_dir: Path,
    flags_by_contract: dict[str, dict[str, bool | None]],
    deployed: dict[str, int] | None = None,
) -> tuple[list[Case], list[Proof]]:
    """Cases to run, plus findings we can't build a test for (status ``unsupported``)."""
    abis, code = load_abis(build_info_dir)
    cases, skipped = [], []
    for f in findings:
        if f.detector != "V4H-01":
            continue
        cb = f.evidence.get("callback") or f.function.lstrip("_")
        src = _defining_file(abis, f)
        abi = abis.get((src, f.contract), [])

        def skip(reason: str, cb: str = cb, f: HookFinding = f) -> None:
            skipped.append(Proof(f.fingerprint, f.contract, cb, "unsupported", reason))

        entry = next((e for e in abi if e.get("type") == "function" and e.get("name") == cb), None)
        if entry is None:
            skip(f"no ABI entry for {cb} in {src or '?'}:{f.contract}")
            continue
        sig = selector_sig(entry)
        if deployed is not None:
            if f.contract not in deployed:
                skip(f"no deployed address given for {f.contract}")
                continue
            hook, ctor = deployed[f.contract], None
        else:
            creation = code.get((src, f.contract), "")
            if not creation or "__" in creation:
                skip("no creation bytecode in the build (abstract, or needs linked libraries)")
                continue
            hook = hook_address(flags_by_contract.get(f.contract) or {}, abi)
            if hook is None:
                skip("permission flags use an API this step can't encode in an address")
                continue
            ctor_entry = next((e for e in abi if e.get("type") == "constructor"), {"inputs": []})
            ctor = abi_encode(ctor_entry["inputs"], [ctor_value(i, hook, FAKE_PM) for i in ctor_entry["inputs"]])
        case = Case(f, f"{src}:{f.contract}", variants(entry["inputs"], hook, FAKE_PM), hook, ctor, sig)
        if ctor is not None:
            case.creation = creation
        cases.append(case)
    return cases, skipped


def _classify(result: dict) -> tuple[str, str]:
    if result.get("status") == "Success":
        return "proven", ""
    reason = result.get("reason") or ""
    if REACHED_PM in reason:
        return "reaches-pm", "succeeded and called into the PoolManager, but wrote no hook storage"
    if NO_WRITE in reason:
        return "no-effect", reason
    if "constructor reverted" in reason:
        return "unsupported", "deploy failed: constructor reverted with the default arguments"
    return "reverted", reason


def run_proofs(
    project: Path,
    cases: list[Case],
    fork_url: str | None = None,
    keep: bool = False,
    forge: str | None = None,
) -> ProofRun:
    run = ProofRun()
    if not cases:
        return run
    forge = forge or shutil.which("forge") or "forge"
    test_dir = Path(project) / "test" / PROOF_DIR
    test_dir.mkdir(parents=True, exist_ok=True)
    path = test_dir / "V4HProof.t.sol"
    path.write_text(render(cases))
    cmd = [forge, "test", "--json", "--match-path", f"test/{PROOF_DIR}/*"]
    if fork_url:
        cmd += ["--fork-url", fork_url]
    env = {"FOUNDRY_TEST": f"test/{PROOF_DIR}"}  # compile only our tests, not the project's
    try:
        proc = subprocess.run(cmd, cwd=project, capture_output=True, text=True, env={**_environ(), **env})
    finally:
        if not keep:
            shutil.rmtree(test_dir, ignore_errors=True)
    run.forge_output = proc.stdout[-4000:] + proc.stderr[-4000:]
    results = _parse_forge_json(proc.stdout)
    for i, c in enumerate(cases):
        cname = _cname(i, c)
        res = results.get(cname)
        cb = c.sig.split("(")[0]
        if res is None:
            reason = "forge produced no result (compile error?)"
            run.proofs.append(Proof(c.finding.fingerprint, c.finding.contract, cb, "unsupported", reason, cname))
            continue
        status, reason = _classify(res)
        run.proofs.append(Proof(c.finding.fingerprint, c.finding.contract, cb, status, reason, cname))
    return run


def _environ() -> dict[str, str]:
    import os

    return dict(os.environ)


def _parse_forge_json(stdout: str) -> dict[str, dict]:
    """{contract name: test_proof() result} from ``forge test --json``."""
    start = stdout.find("{")
    if start < 0:
        return {}
    try:
        data = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return {}
    out = {}
    for key, suite in data.items():
        res = (suite.get("test_results") or {}).get("test_proof()")
        if res is not None:
            out[key.rsplit(":", 1)[-1]] = res
    return out


def prove_project(
    project: Path,
    scope: list[str] | None = None,
    build_info: Path | None = None,
    fork_url: str | None = None,
    deployed: dict[str, int] | None = None,
    pool_manager: int | None = None,
    keep: bool = False,
) -> ProofRun:
    """Scan ``project`` and try to prove each V4H-01 finding (see module docstring)."""
    from .scanner import scan_units
    from .solast import forge_build, load_build_info

    bi = Path(build_info) if build_info else forge_build(Path(project))
    units = load_build_info(bi)
    findings = scan_units(units, scope).findings
    cases, skipped = build_cases(findings, bi, flags_by_contract(units, scope), deployed if fork_url else None)
    if pool_manager is not None:
        for c in cases:
            c.pm = pool_manager
    run = run_proofs(Path(project), cases, fork_url=fork_url, keep=keep)
    run.proofs = skipped + run.proofs
    return run
