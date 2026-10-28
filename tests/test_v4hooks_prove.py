"""Proof step: ABI encoding, argument variants, hook addresses, and a real run on the corpus."""

import shutil
from pathlib import Path

import pytest

from v4hooks import prove
from v4hooks.model import HookFinding

CORPUS = Path(__file__).parent.parent / "corpus"


def w(n: int) -> bytes:
    return (n % (1 << 256)).to_bytes(32, "big")


U256 = {"type": "uint256", "name": "a"}
BYTES = {"type": "bytes", "name": "hookData"}


def test_encode_static_and_dynamic():
    assert prove.abi_encode([U256, BYTES], [1, b"ab"]) == w(1) + w(0x40) + w(2) + b"ab" + b"\0" * 30


def test_encode_negative_int_is_twos_complement():
    assert prove.abi_encode([{"type": "int256", "name": "x"}], [-1]) == b"\xff" * 32


def test_encode_static_tuple_inline_dynamic_tuple_by_offset():
    static = {"type": "tuple", "components": [{"type": "address", "name": "a"}, {"type": "uint24", "name": "fee"}]}
    assert prove.abi_encode([static], [[5, 3000]]) == w(5) + w(3000)
    dyn = {"type": "tuple", "components": [U256, BYTES]}
    assert prove.abi_encode([dyn], [[1, b""]]) == w(0x20) + w(1) + w(0x40) + w(0)


def test_encode_arrays():
    assert prove.abi_encode([{"type": "uint8[]", "name": "x"}], [[7, 8]]) == w(0x20) + w(2) + w(7) + w(8)
    assert prove.abi_encode([{"type": "uint8[2]", "name": "x"}], [[7, 8]]) == w(7) + w(8)


POOL_KEY = {
    "type": "tuple",
    "name": "key",
    "components": [
        {"type": "address", "name": "currency0"},
        {"type": "address", "name": "currency1"},
        {"type": "uint24", "name": "fee"},
        {"type": "int24", "name": "tickSpacing"},
        {"type": "address", "name": "hooks"},
    ],
}


def test_canonical_signature():
    entry = {"name": "afterSwap", "inputs": [{"type": "address", "name": ""}, POOL_KEY, BYTES]}
    assert prove.selector_sig(entry) == "afterSwap(address,(address,address,uint24,int24,address),bytes)"


def test_defaults_name_the_hook_in_the_key():
    assert prove.default_value(POOL_KEY, hook=0xABC, pm=0x1) == [0, 0, 3000, 60, 0xABC]


def test_variants_cover_hookdata_and_zero_amounts():
    params = {"type": "tuple", "name": "params", "components": [{"type": "int256", "name": "amountSpecified"}]}
    vs = prove.variants([params, BYTES], hook=1, pm=2)
    assert len(vs) == 6 and len(set(vs)) == 6
    assert vs[0] == prove.abi_encode([params, BYTES], [[-(10**18)], b""])
    assert prove.abi_encode([params, BYTES], [[0], b"\0" * 512]) in vs


def test_hook_address_encodes_release_and_2023_flags():
    addr = prove.hook_address({"beforeSwap": True, "afterSwap": False}, abi=[])
    assert addr & 0x3FFF == 1 << 7
    old = prove.hook_address({"afterSwap": True}, abi=[{"type": "function", "name": "getHooksCalls"}])
    assert old >> 152 & 0xFF == 1 << 2 and old & 0x3FFF == 0
    # A flag outside the layout can't be encoded: report it, don't guess.
    assert prove.hook_address({"beforeModifyPosition": True}, abi=[]) is None


def test_findings_without_abi_are_unsupported(tmp_path):
    f = HookFinding("V4H-01", "t", "high", "Nope", "beforeSwap", "src/X.sol", 1, 2, "m")
    cases, skipped = prove.build_cases([f], tmp_path, {})
    assert cases == [] and skipped[0].status == "unsupported"


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("forge") is None, reason="forge not installed")
@pytest.mark.skipif(not (CORPUS / "lib/uniswap-hooks/src").exists(), reason="run corpus/setup.sh first")
def test_corpus_proofs():
    from v4hooks.scanner import scan_units
    from v4hooks.solast import forge_build, load_build_info

    bi = forge_build(CORPUS)
    units = load_build_info(bi)
    res = scan_units(units, ["src/"])
    cases, skipped = prove.build_cases(res.findings, bi, prove.flags_by_contract(units, ["src/"]))
    run = prove.run_proofs(CORPUS, cases)
    got = {(p.contract, p.callback): p.status for p in skipped + run.proofs}
    assert got[("CorkStyleHook", "beforeSwap")] == "proven"
    assert got[("UnguardedUnlockHook", "unlockCallback")] == "reaches-pm"
    # Owner-gated, not PoolManager-gated: a stranger can't call it, and the proof says so.
    assert got[("WrongGuardHook", "afterSwap")] == "reverted"
    assert not (CORPUS / "test" / prove.PROOF_DIR).exists()


def test_silent_reverts_are_not_reported_as_no_effect():
    # Regression: every attempt reverting with empty data used to fall through to the
    # "succeeded but wrote nothing" message.
    f = HookFinding("V4H-01", "t", "high", "H", "beforeSwap", "src/H.sol", 1, 2, "m")
    src = prove.render([prove.Case(f, "src/H.sol:H", [b""], 1, None, "beforeSwap()")])
    assert "anySucceeded = true;" in src
    assert src.index("if (anySucceeded)") < src.index(prove.SILENT_REVERT)
    assert prove._classify({"status": "Failure", "reason": prove.SILENT_REVERT})[0] == "reverted"
