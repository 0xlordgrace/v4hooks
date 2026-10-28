"""Build robustness: via-ir retry and nested Foundry projects (found by the public-hook scan)."""

import json
import os
import stat
from pathlib import Path

import pytest

from v4hooks.scanner import find_foundry_roots, scan_project
from v4hooks.solast import BuildError, forge_build

FIXTURE = Path(__file__).parent / "fixtures" / "v4hooks" / "ast.json"


def _fake_forge(tmp_path, monkeypatch, needs_via_ir: bool):
    """A `forge` that writes the fixture as build-info, optionally only with --via-ir."""
    fx = json.loads(FIXTURE.read_text())
    bi = {
        "solcLongVersion": fx.get("solc", ""),
        "output": {"sources": {p: {"ast": s["ast"]} for p, s in fx["sources"].items()}},
        "input": {"sources": {p: {"content": s["content"]} for p, s in fx["sources"].items()}},
    }
    payload = tmp_path / "payload.json"
    payload.write_text(json.dumps(bi))
    log = tmp_path / "calls.log"
    script = tmp_path / "bin" / "forge"
    script.parent.mkdir()
    script.write_text(f"""#!/bin/sh
echo "$PWD $@" >> {log}
case "$*" in *--via-ir*) via=1;; *) via=0;; esac
if [ {int(needs_via_ir)} = 1 ] && [ $via = 0 ]; then echo "Error: Compiler error: Stack too deep." >&2; exit 1; fi
out=""; prev=""
for a in "$@"; do [ "$prev" = "--build-info-path" ] && out="$a"; prev="$a"; done
mkdir -p "$out" && cp {payload} "$out/x.json"
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{script.parent}{os.pathsep}{os.environ['PATH']}")
    return log


def test_retries_with_via_ir_on_stack_too_deep(tmp_path, monkeypatch):
    log = _fake_forge(tmp_path, monkeypatch, needs_via_ir=True)
    out = forge_build(tmp_path, tmp_path / "bi")
    assert (out / "x.json").exists()
    calls = log.read_text().splitlines()
    assert len(calls) == 2 and "--via-ir" in calls[1]


def test_no_retry_when_build_works(tmp_path, monkeypatch):
    log = _fake_forge(tmp_path, monkeypatch, needs_via_ir=False)
    forge_build(tmp_path, tmp_path / "bi")
    assert len(log.read_text().splitlines()) == 1


def test_other_build_errors_are_not_retried(tmp_path, monkeypatch):
    script = tmp_path / "bin" / "forge"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\necho 'Error: file not found' >&2\nexit 1\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{script.parent}{os.pathsep}{os.environ['PATH']}")
    with pytest.raises(BuildError, match="file not found"):
        forge_build(tmp_path, tmp_path / "bi")


def test_find_foundry_roots_skips_dependencies(tmp_path):
    for d in ("contracts/hooks", "contracts/other", "lib/forge-std", "contracts/hooks/lib/dep", "node_modules/x"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "foundry.toml").write_text("[profile.default]\n")
    assert find_foundry_roots(tmp_path) == [tmp_path / "contracts/hooks", tmp_path / "contracts/other"]
    (tmp_path / "foundry.toml").write_text("[profile.default]\n")
    assert find_foundry_roots(tmp_path) == [tmp_path]


def test_nested_projects_are_scanned_with_prefixed_paths(tmp_path, monkeypatch):
    log = _fake_forge(tmp_path, monkeypatch, needs_via_ir=False)
    repo = tmp_path / "repo"
    for d in ("packages/a", "packages/b"):
        (repo / d).mkdir(parents=True)
        (repo / d / "foundry.toml").write_text("[profile.default]\n")
    result = scan_project(repo, scope=["src/Cases"])
    assert len(log.read_text().splitlines()) == 2
    files = {f.file for f in result.findings}
    assert files == {"packages/a/src/Cases.sol", "packages/b/src/Cases.sol"}
    assert any(h.startswith("packages/a/") for h in result.hooks)
