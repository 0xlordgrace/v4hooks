"""Unit tests for the V4H detectors against a checked-in AST snapshot (no forge).

Fixture source: tests/fixtures/v4hooks/project/src/Cases.sol
Convention: Pos_NN_* must be flagged by V4H-NN, Neg_NN_* must not be.
"""

from pathlib import Path

import pytest

from v4hooks import scan_units
from v4hooks.detectors import DETECTORS_BY_ID, find_hooks
from v4hooks.detectors.permissions import parse_permissions
from v4hooks.solast import load_ast_json

FIXTURE = Path(__file__).parent / "fixtures" / "v4hooks" / "ast.json"


@pytest.fixture(scope="module")
def unit():
    return load_ast_json(FIXTURE)


@pytest.fixture(scope="module")
def hooks(unit):
    return {h.name: h for h in find_hooks([unit], ["src/Cases"])}


def _ids(hooks, name, det):
    return [(f.function, f.evidence) for f in DETECTORS_BY_ID[det].run(hooks[name])]


def _cases(prefix):
    import re

    text = (FIXTURE.parent / "project" / "src" / "Cases.sol").read_text()
    return sorted(re.findall(rf"^contract ({prefix}\w+)", text, re.M))


def test_finds_only_leaf_concrete_hooks(hooks):
    assert "RawHook" not in hooks  # abstract base
    assert "BaseHook" not in hooks
    assert len(hooks) == len(_cases("Pos_")) + len(_cases("Neg_"))


@pytest.mark.parametrize("det", ["01", "02", "03"])
def test_positives_flagged(hooks, det):
    for name in _cases(f"Pos_{det}_"):
        assert _ids(hooks, name, f"V4H-{det}"), f"{name} should be flagged by V4H-{det}"


@pytest.mark.parametrize("det", ["01", "02", "03"])
def test_negatives_not_flagged(hooks, det):
    cases = _cases(f"Neg_{det}_")
    assert cases
    for name in cases:
        assert not _ids(hooks, name, f"V4H-{det}"), f"{name} must not be flagged by V4H-{det}"


# ── V4H-01 specifics ──


def test_caller_check_reports_wrong_principal(hooks):
    [(fn, ev)] = _ids(hooks, "Pos_01_OwnerCheck", "V4H-01")
    assert fn == "beforeSwap"
    assert ev["sender_checked_against"] == ["owner"]


def test_caller_check_covers_unlock_callback(hooks):
    [(fn, _)] = _ids(hooks, "Pos_01_UnlockCallback", "V4H-01")
    assert fn == "unlockCallback"


def test_caller_check_follows_basehook_modifier(hooks):
    # Every BaseHook-derived positive for other detectors is PoolManager-gated.
    for name in ("Pos_02_GlobalLedger", "Pos_03_FlagNoImpl", "Neg_02_InitGate"):
        assert not _ids(hooks, name, "V4H-01")


# ── V4H-02 specifics ──


def test_poolkey_reports_shared_writes(hooks):
    [(fn, ev)] = _ids(hooks, "Pos_02_GlobalLedger", "V4H-02")
    assert fn == "_afterSwap"
    assert ev["shared_state_writes"] == ["points"]
    assert ev["before_initialize_enabled"] is False


def test_poolkey_reports_key_currency_transfer(hooks):
    [(_, ev)] = _ids(hooks, "Pos_02_KeyCurrencyTransfer", "V4H-02")
    assert ev["key_currency_moves"] == ["key.currency0.transfer"]


def test_poolkey_state_keyed_by_pool_is_fine(hooks):
    # mapping(PoolId => ..) and keccak256(abi.encode(key, ..)) keys are per-pool
    assert not _ids(hooks, "Neg_02_PerPoolState", "V4H-02")


# ── V4H-03 specifics ──


def test_permissions_parser_shapes(hooks):
    named = parse_permissions(hooks["Pos_02_GlobalLedger"])
    assert named["afterSwap"] is True and named["beforeSwap"] is False
    positional = parse_permissions(hooks["Pos_03_DeltaWithoutBase"])
    assert positional["beforeSwapReturnDelta"] is True and positional["beforeSwap"] is False
    fields = parse_permissions(hooks["Neg_02_InitGate"])
    assert fields["beforeInitialize"] and fields["afterSwap"] and not fields["beforeSwap"]


def test_permission_bits_each_rule(hooks):
    assert _ids(hooks, "Pos_03_FlagNoImpl", "V4H-03")[0][1] == {
        "callback": "beforeSwap", "flag": True, "implemented": False}
    assert _ids(hooks, "Pos_03_ImplNoFlag", "V4H-03")[0][0] == "_beforeInitialize"
    assert _ids(hooks, "Pos_03_DeltaWithoutBase", "V4H-03")[0][1]["flag"] == "beforeSwapReturnDelta"
    assert _ids(hooks, "Pos_03_NeverValidated", "V4H-03")[0][1] == {"callback": None, "validated": False}


def test_deliberate_revert_override_not_flagged(hooks):
    assert not _ids(hooks, "Neg_03_DeliberateRevert", "V4H-03")


# ── scanner ──


def test_scan_is_deterministic(unit):
    a = scan_units([unit], ["src/Cases"]).to_json()
    b = scan_units([load_ast_json(FIXTURE)], ["src/Cases"]).to_json()
    assert a == b
    assert "timings" not in a  # wall-clock data never enters the findings JSON


def test_findings_have_locations_and_snippets(unit):
    for f in scan_units([unit], ["src/Cases"]).findings:
        assert f.file == "src/Cases.sol" and 0 < f.line_start <= f.line_end
        assert f.snippet.strip()
        assert len(f.fingerprint) == 16


def test_loader_skips_sources_without_location():
    """forge's dynamic test linking adds foundry-pp/ sources whose AST has no `src`."""
    from v4hooks.solast import Unit

    good = {"nodeType": "SourceUnit", "id": 1, "src": "0:0:0", "nodes": []}
    stub = {"nodeType": "SourceUnit", "id": 2, "nodes": []}
    unit = Unit(sources={"src/A.sol": good, "foundry-pp/DeployHelper1.sol": stub}, contents={})
    assert list(unit.contracts()) == []


def test_never_validated_is_informational(hooks):
    [f] = DETECTORS_BY_ID["V4H-03"].run(hooks["Pos_03_NeverValidated"])
    assert f.severity == "info"


def test_external_ledger_named_in_evidence(hooks):
    [(_, ev)] = _ids(hooks, "Pos_02_ExternalLedger", "V4H-02")
    assert ev["external_state_calls"] == ["ledger.accrue"]


# ── confidence tiers ──


def _conf(hooks, name, det):
    return [f.confidence for f in DETECTORS_BY_ID[det].run(hooks[name])]


def test_value_move_or_external_call_is_confirmed(hooks):
    assert _conf(hooks, "Pos_02_KeyCurrencyTransfer", "V4H-02") == ["confirmed"]
    assert _conf(hooks, "Pos_02_ExternalLedger", "V4H-02") == ["confirmed"]


def test_record_only_write_is_pattern(hooks):
    # A counter nobody checks: the shape is there, the consequence isn't visible.
    assert _conf(hooks, "Pos_01_NoCheck", "V4H-01") == ["pattern"]
    assert _conf(hooks, "Pos_02_GlobalLedger", "V4H-02") == ["pattern"]


def test_bricking_and_ignored_delta_are_confirmed_dead_code_is_pattern(hooks):
    assert _conf(hooks, "Pos_03_FlagNoImpl", "V4H-03") == ["confirmed"]
    assert _conf(hooks, "Pos_03_DeltaWithoutFlag", "V4H-03") == ["confirmed"]
    assert _conf(hooks, "Pos_03_ImplNoFlag", "V4H-03") == ["pattern"]


def test_findings_about_different_callbacks_are_not_deduplicated():
    # Several "flag on, not implemented" findings share the permissions function's
    # location; the callback must be part of the identity or the scanner merges them.
    from v4hooks.model import HookFinding

    base = dict(detector="V4H-03", title="t", severity="high", contract="H", function="getHooksCalls",
                file="a.sol", line_start=10, line_end=20, message="m")
    a = HookFinding(**base, evidence={"callback": "beforeSwap"})
    b = HookFinding(**base, evidence={"callback": "beforeInitialize"})
    assert a.fingerprint != b.fingerprint


def test_consequence_free_unguarded_callback_is_info(hooks):
    [f] = DETECTORS_BY_ID["V4H-01"].run(hooks["Pos_01_CounterOnly"])
    assert f.severity == "info" and f.confidence == "pattern"


def test_unguarded_write_read_elsewhere_stays_high(hooks):
    [f] = DETECTORS_BY_ID["V4H-01"].run(hooks["Pos_01_WriteFeedsPayout"])
    assert f.severity == "high" and f.confidence == "confirmed"
    assert any("read by claimRebate" in r for r in f.evidence["consequences"])


def test_address_keyed_ledger_write_is_a_consequence(hooks):
    [f] = DETECTORS_BY_ID["V4H-01"].run(hooks["Pos_01_PointsLedger"])
    assert f.severity == "high"


def test_assembly_storage_write_counts_as_consequence(hooks):
    # Yul writes can't be traced to their readers, so they stay reportable (Gamma LimitOrderHook).
    [f] = DETECTORS_BY_ID["V4H-01"].run(hooks["Pos_01_TransientWrite"])
    assert f.severity == "high"


def test_super_permissions_chain_is_followed(hooks):
    # Base sets beforeSwap, override adds afterSwap via `p = super._hookPerms()`.
    got = _ids(hooks, "Pos_03_SuperPermissionsNoImpl", "V4H-03")
    assert [ev["callback"] for _, ev in got] == ["afterSwap"]
