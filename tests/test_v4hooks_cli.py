"""Standalone v4hooks: CLI, SARIF output, and installability without Ghost Orchid."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from v4hooks import scan_units
from v4hooks.sarif import to_sarif
from v4hooks.solast import load_ast_json

REPO = Path(__file__).resolve().parents[1]
PKG = REPO
FIXTURE = Path(__file__).parent / "fixtures" / "v4hooks" / "ast.json"


@pytest.fixture(scope="module")
def result():
    return scan_units([load_ast_json(FIXTURE)], ["src/Cases"])


@pytest.fixture()
def build_info(tmp_path):
    """The AST fixture rewritten in forge build-info layout, as the CLI reads it."""
    fx = json.loads(FIXTURE.read_text())
    bi = {
        "solcLongVersion": fx.get("solc", ""),
        "output": {"sources": {p: {"ast": s["ast"]} for p, s in fx["sources"].items()}},
        "input": {"sources": {p: {"content": s["content"]} for p, s in fx["sources"].items()}},
    }
    d = tmp_path / "bi"
    d.mkdir()
    (d / "fixture.json").write_text(json.dumps(bi))
    return d


def _standalone_env(tmp_path):
    """A sys.path where the package is importable only as top-level `v4hooks`."""
    site = tmp_path / "site"
    site.mkdir(exist_ok=True)
    link = site / "v4hooks"
    if not link.exists():
        link.symlink_to(PKG / "v4hooks", target_is_directory=True)
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH",)}
    env["PYTHONPATH"] = str(site)
    return env


# ── SARIF ──


def test_sarif_shape(result):
    sarif = to_sarif(result)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"V4H-01", "V4H-02", "V4H-03"}
    assert len(run["results"]) == len(result.findings)
    first = run["results"][0]
    loc = first["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/Cases.sol"
    assert loc["region"]["startLine"] >= 1
    assert first["partialFingerprints"]["v4hooks/v1"]


def test_sarif_levels_and_prefix(result):
    sarif = to_sarif(result, uri_prefix="contracts/")
    levels = {r["level"] for r in sarif["runs"][0]["results"]}
    assert levels <= {"error", "warning", "note"}
    by_sev = {f.severity for f in result.findings}
    assert "info" in by_sev and "note" in levels
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in sarif["runs"][0]["results"]}
    assert uris == {"contracts/src/Cases.sol"}


def test_sarif_is_deterministic(result):
    assert json.dumps(to_sarif(result), sort_keys=True) == json.dumps(to_sarif(result), sort_keys=True)


# ── CLI ──


def _cli(args, env=None, cwd=REPO):
    return subprocess.run([sys.executable, "-m", "v4hooks.cli", *args], capture_output=True, text=True,
                          env=env, cwd=cwd)


def test_cli_scan_writes_json_and_sarif(tmp_path, build_info):
    env = _standalone_env(tmp_path)
    out_json, out_sarif = tmp_path / "scan.json", tmp_path / "scan.sarif"
    p = _cli(["scan", ".", "--build-info", str(build_info), "--scope", "src/Cases",
              "--json", str(out_json), "--sarif", str(out_sarif)], env=env)
    assert p.returncode == 1, p.stderr  # findings at or above the default --fail-on
    assert json.loads(out_json.read_text())["findings"]
    assert json.loads(out_sarif.read_text())["runs"][0]["results"]


def test_cli_fail_on_threshold(tmp_path, build_info):
    env = _standalone_env(tmp_path)
    p = _cli(["scan", ".", "--build-info", str(build_info), "--scope", "src/Cases", "--fail-on", "none"], env=env)
    assert p.returncode == 0, p.stderr
    p = _cli(["scan", ".", "--build-info", str(build_info), "--scope", "src/NoSuchDir"], env=env)
    assert p.returncode == 0 and "0 finding" in p.stdout


def test_cli_explain_template(tmp_path, build_info):
    env = _standalone_env(tmp_path)
    scan = tmp_path / "scan.json"
    _cli(["scan", ".", "--build-info", str(build_info), "--scope", "src/Cases", "--json", str(scan)], env=env)
    p = _cli(["explain", str(scan), "--no-model"], env=env)
    assert p.returncode == 0, p.stderr
    assert "# Uniswap v4 hook scan report" in p.stdout


# ── standalone install ──


def test_imports_without_ghost_orchid(tmp_path):
    env = _standalone_env(tmp_path)
    code = (
        "import sys, v4hooks, v4hooks.cli, v4hooks.explain, v4hooks.sarif, v4hooks.scanner\n"
        "bad = [m for m in sys.modules if m.split('.')[0] in ('harness', 'extensions', 'llm', 'httpx', 'yaml')]\n"
        "assert not bad, bad\n"
        "print('ok')\n"
    )
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env=env, cwd=tmp_path)
    assert p.returncode == 0 and "ok" in p.stdout, p.stderr


def test_package_metadata():
    text = (PKG / "pyproject.toml").read_text()
    assert 'name = "v4hooks"' in text
    assert 'v4hooks = "v4hooks.cli:main"' in text
    assert "dependencies = []" in text


# ── GitHub Action ──


def test_action_yml_parses_and_matches_cli():
    yaml = pytest.importorskip("yaml")
    from v4hooks.cli import FAIL_ON, build_parser

    action = yaml.safe_load((PKG / "action.yml").read_text())
    assert action["runs"]["using"] == "composite"
    assert set(action["inputs"]) >= {"project", "scope", "fail-on", "sarif-file", "upload-sarif"}
    scan = next(s for s in action["runs"]["steps"] if s.get("id") == "scan")["run"]
    # Every flag the action passes must exist on the CLI.
    scan_parser = build_parser()._subparsers._group_actions[0].choices["scan"]
    known = {o for a in scan_parser._actions for o in a.option_strings}
    for flag in ("--scope", "--fail-on", "--sarif", "--uri-prefix", "--json"):
        assert flag in scan and flag in known
    assert "fail-on" in action["inputs"] and set(FAIL_ON) >= {"none", "low", "high"}


def test_example_workflow_uses_action_path():
    yaml = pytest.importorskip("yaml")
    wf = yaml.safe_load((PKG / "examples" / "v4hooks.yml").read_text())
    steps = wf["jobs"]["v4hooks"]["steps"]
    assert any("0xlordgrace/v4hooks@" in s.get("uses", "") for s in steps)
    assert wf["jobs"]["v4hooks"]["permissions"]["security-events"] == "write"
