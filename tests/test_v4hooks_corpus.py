"""End-to-end on the Foundry corpus (needs forge + the uniswap-hooks submodule)."""

import shutil

import pytest

from v4hooks.benchmark import DEFAULT_LABELS, run_benchmark
from v4hooks.scanner import scan_project
from v4hooks.solast import forge_build

CORPUS = DEFAULT_LABELS.parent
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("forge") is None, reason="forge not installed"),
    pytest.mark.skipif(not (CORPUS / "lib/uniswap-hooks/src").exists(),
                       reason="run corpus/setup.sh first"),
]


@pytest.fixture(scope="module")
def build_info(tmp_path_factory):
    return forge_build(CORPUS, tmp_path_factory.mktemp("bi") / "out")


def test_benchmark_scores(build_info):
    res = run_benchmark(build_info=build_info)
    for det, s in res.scores.items():
        assert s.fp == 0, f"{det} false positives: {s.false_positives}"
        assert s.fn == 0, f"{det} false negatives: {s.false_negatives}"
        assert s.tp >= 2
    assert not res.unlabelled
    assert [o["contract"] for o in res.out_of_scope] == ["BunniStyleRoundingHook"]


def test_scan_json_is_byte_identical_across_builds(build_info, tmp_path):
    a = scan_project(CORPUS, build_info=build_info).to_json()
    b = scan_project(CORPUS, build_info=forge_build(CORPUS, tmp_path / "bi2")).to_json()
    assert a == b


def test_openzeppelin_hooks_are_clean(build_info):
    res = scan_project(CORPUS, scope=["lib/uniswap-hooks/src/mocks/"], build_info=build_info)
    assert len(res.hooks) == 12
    assert res.findings == []
