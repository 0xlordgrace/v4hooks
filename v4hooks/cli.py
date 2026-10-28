"""`v4hooks`: the standalone command line (no Ghost Orchid needed).

    v4hooks scan <foundry-project> [--sarif out.sarif] [--json out.json] [--fail-on low]
    v4hooks explain scan.json [--base-url URL --model NAME | --no-model]
    v4hooks bench [--labels labels.yaml]
    v4hooks prove <foundry-project> [--fork-url URL --address Hook=0x...] [--json out.json]

Exit codes for `scan`: 0 = no finding at or above --fail-on, 1 = findings, 2 = build error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import __version__
from .model import SEVERITIES

FAIL_ON = ("none", *reversed(SEVERITIES))  # none, info, low, medium, high, critical


def _scan(args: argparse.Namespace) -> int:
    from .detectors import DETECTORS_BY_ID
    from .sarif import to_sarif
    from .scanner import scan_project
    from .solast import BuildError

    try:
        dets = [DETECTORS_BY_ID[d] for d in args.detector] if args.detector else None
    except KeyError as e:
        print(f"unknown detector {e}; choose from {', '.join(DETECTORS_BY_ID)}", file=sys.stderr)
        return 2
    try:
        result = scan_project(Path(args.project), scope=args.scope or None, build_info=args.build_info, detectors=dets)
    except BuildError as e:
        print(str(e), file=sys.stderr)
        return 2
    for f in result.findings:
        print(f"{f.file}:{f.line_start}: {f.detector} [{f.severity}/{f.confidence}] {f.contract}.{f.function}: {f.message}")
    print(f"{len(result.hooks)} hook(s) scanned, {len(result.findings)} finding(s)")
    if args.github_annotations:
        prefix = (args.uri_prefix or "").strip("/")
        for f in result.findings:
            level = {"critical": "error", "high": "error", "medium": "warning", "low": "warning"}.get(f.severity, "notice")
            path = f"{prefix}/{f.file}" if prefix else f.file
            msg = f.message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::{level} file={path},line={f.line_start},endLine={f.line_end},"
                  f"title={f.detector} {f.contract}.{f.function}::{msg}")
    if args.json:
        Path(args.json).write_text(result.to_json())
    if args.sarif:
        sarif = to_sarif(result, uri_prefix=args.uri_prefix or "", tool_version=__version__)
        Path(args.sarif).write_text(json.dumps(sarif, indent=2, sort_keys=True) + "\n")
    if args.fail_on == "none":
        return 0
    threshold = SEVERITIES.index(args.fail_on)
    return 1 if any(SEVERITIES.index(f.severity) <= threshold for f in result.findings) else 0


def _explain(args: argparse.Namespace) -> int:
    from .explain import backend_from_config, explain
    from .model import HookFinding

    raw = Path(args.scan_json).read_bytes()
    findings = [HookFinding.from_dict(d) for d in json.loads(raw)["findings"]]
    backend = None
    if not args.no_model:
        backend = backend_from_config({}, base_url=args.base_url, model=args.model, api_key_env=args.api_key_env)
        if backend is None:
            print("no model configured (--base-url/--model or V4HOOKS_BASE_URL/V4HOOKS_MODEL); template report",
                  file=sys.stderr)
    report = explain(findings, backend, scan_sha256=hashlib.sha256(raw).hexdigest()[:16])
    fallen = [i.source for i in report.items if i.source.startswith("template (")]
    if fallen:
        print(f"warning: {len(fallen)} of {len(report.items)} finding(s) fell back to the template; "
              f"first reason: {fallen[0][len('template ('):-1]}", file=sys.stderr)
    md = report.to_markdown()
    if args.out:
        Path(args.out).write_text(md)
    else:
        print(md)
    return 0


def _bench(args: argparse.Namespace) -> int:
    from .benchmark import DEFAULT_LABELS, render_table, run_benchmark

    labels = Path(args.labels) if args.labels else DEFAULT_LABELS
    if not labels.exists():
        print(f"labels file not found: {labels}", file=sys.stderr)
        return 2
    res = run_benchmark(labels, build_info=args.build_info)
    print(render_table(res))
    if args.json:
        Path(args.json).write_text(json.dumps(res.to_dict(), indent=2, sort_keys=True) + "\n")
    return 0


def _prove(args: argparse.Namespace) -> int:
    from .prove import prove_project
    from .solast import BuildError

    deployed = {}
    for a in args.address or []:
        name, _, addr = a.partition("=")
        deployed[name] = int(addr, 16)
    if args.fork_url and not deployed:
        print("--fork-url needs at least one --address Contract=0x...", file=sys.stderr)
        return 2
    try:
        run = prove_project(
            Path(args.project), scope=args.scope or None, build_info=args.build_info, fork_url=args.fork_url,
            deployed=deployed, pool_manager=int(args.pool_manager, 16) if args.pool_manager else None, keep=args.keep,
        )
    except BuildError as e:
        print(str(e), file=sys.stderr)
        return 2
    if not run.proofs:
        print("no V4H-01 findings to prove (prove only covers V4H-01: callbacks a stranger can call)")
    for p in run.proofs:
        print(f"{p.status:12} {p.contract}.{p.callback}" + (f"  ({p.reason})" if p.reason else ""))
    counts = {s: sum(p.status == s for p in run.proofs) for s in ("proven", "reaches-pm", "reverted", "no-effect",
                                                                    "unsupported")}
    print(", ".join(f"{n} {s}" for s, n in counts.items()))
    if args.json:
        Path(args.json).write_text(json.dumps(run.to_dict(), indent=2, sort_keys=True) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="v4hooks", description="Deterministic security scanner for Uniswap v4 hooks")
    p.add_argument("--version", action="version", version=f"v4hooks {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="build with forge and run the detectors")
    s.add_argument("project", help="Foundry project root")
    s.add_argument("--scope", action="append", help="source path prefix to report on (repeatable; default src/)")
    s.add_argument("--build-info", help="use an existing `forge build --build-info` directory")
    s.add_argument("--detector", action="append", help="only run these detector ids (repeatable)")
    s.add_argument("--json", help="write findings JSON here")
    s.add_argument("--sarif", help="write SARIF 2.1.0 here (GitHub Code Scanning)")
    s.add_argument("--uri-prefix", help="path from the repo root to the project, for SARIF file links")
    s.add_argument("--github-annotations", action="store_true",
                   help="also print GitHub workflow-command annotations (PR diff annotations without Code Scanning)")
    s.add_argument("--fail-on", choices=FAIL_ON, default="low",
                   help="exit 1 if any finding is at least this severe (default: low)")
    s.set_defaults(func=_scan)

    e = sub.add_parser("explain", help="write a markdown report for a scan (optional local model)")
    e.add_argument("scan_json")
    e.add_argument("--out", "-o")
    e.add_argument("--base-url", help="OpenAI-compatible endpoint, e.g. http://localhost:11434/v1")
    e.add_argument("--model")
    e.add_argument("--api-key-env", help="name of the env var holding the API key, if any")
    e.add_argument("--no-model", action="store_true", help="template report, no model call")
    e.set_defaults(func=_explain)

    b = sub.add_parser("bench", help="score the detectors against a labelled corpus")
    b.add_argument("--labels")
    b.add_argument("--build-info")
    b.add_argument("--json")
    b.set_defaults(func=_bench)

    r = sub.add_parser("prove", help="generate and run a Foundry test per V4H-01 finding")
    r.add_argument("project", help="Foundry project root")
    r.add_argument("--scope", action="append", help="source path prefix (repeatable; default src/)")
    r.add_argument("--build-info", help="use an existing `forge build --build-info` directory")
    r.add_argument("--fork-url", help="RPC URL: test the deployed hook on a fork instead of a fresh deploy")
    r.add_argument("--address", action="append", help="Contract=0x... deployed address (fork mode, repeatable)")
    r.add_argument("--pool-manager", help="the chain's PoolManager address (fork mode)")
    r.add_argument("--json", help="write proof results JSON here")
    r.add_argument("--keep", action="store_true", help="keep the generated test in test/v4hooks_proof/")
    r.set_defaults(func=_prove)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
