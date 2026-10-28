"""Run the V4H detectors over a Foundry project (or prebuilt build-info).

Output is deterministic: findings are sorted and the JSON contains no
timestamps, so two scans of the same code with the same solc are byte-identical.
"""

from __future__ import annotations

import dataclasses
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detectors import ALL_DETECTORS, Detector, find_hooks
from .model import HookFinding
from .solast import BuildError, Unit, forge_build, load_build_info

SCHEMA_VERSION = 1


@dataclass
class ScanResult:
    findings: list[HookFinding]
    hooks: list[str]
    solc: list[str]
    timings_ms: dict[str, float] = field(default_factory=dict)  # not serialized by default

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_VERSION,
            "tool": "v4hooks",
            "solc": self.solc,
            "detectors": [d.id for d in ALL_DETECTORS],
            "hooks": self.hooks,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n"


def scan_units(
    units: list[Unit],
    scope: list[str] | None = None,
    detectors: list[Detector] | None = None,
) -> ScanResult:
    detectors = detectors or ALL_DETECTORS
    hooks = find_hooks(units, scope)
    timings = {d.id: 0.0 for d in detectors}
    seen: dict[str, HookFinding] = {}
    for hook in hooks:
        for d in detectors:
            t0 = time.perf_counter()
            for f in d.run(hook):
                seen.setdefault(f.fingerprint, f)
            timings[d.id] += (time.perf_counter() - t0) * 1000
    findings = sorted(seen.values(), key=HookFinding.sort_key)
    return ScanResult(
        findings=findings,
        hooks=sorted(f"{h.contract.path}:{h.name}" for h in hooks),
        solc=sorted({u.solc for u in units}),
        timings_ms=timings,
    )


SKIP_DIRS = {"lib", "node_modules", ".git", "out", "cache", "dependencies", "broadcast"}


def find_foundry_roots(path: Path) -> list[Path]:
    """``path`` itself if it has a foundry.toml, else every nested Foundry project
    (not descending into dependencies or into a project already found)."""
    path = Path(path)
    if (path / "foundry.toml").is_file():
        return [path]
    roots: list[Path] = []
    for child in sorted(p for p in path.iterdir() if p.is_dir() and p.name not in SKIP_DIRS and not p.name.startswith(".")):
        roots.extend(find_foundry_roots(child))
    return roots


def scan_project(
    project: Path,
    scope: list[str] | None = None,
    build_info: Path | None = None,
    detectors: list[Detector] | None = None,
) -> ScanResult:
    """Build ``project`` with forge (unless ``build_info`` is given) and scan it.

    ``scope`` is a list of source path prefixes relative to the project root
    (default: ``src/``) — dependencies in lib/ are read for inheritance but not
    reported on. If ``project`` has no foundry.toml, every nested Foundry project
    is scanned and file paths are reported relative to ``project``.
    """
    scope = scope if scope is not None else ["src/"]
    project = Path(project)
    if build_info:
        return scan_units(load_build_info(Path(build_info)), scope, detectors)
    roots = find_foundry_roots(project)
    if not roots:
        raise BuildError(f"no foundry.toml in {project} or its subdirectories")
    if roots == [project]:
        return scan_units(load_build_info(forge_build(project)), scope, detectors)
    findings: list[HookFinding] = []
    hooks: list[str] = []
    solc: set[str] = set()
    timings: dict[str, float] = {}
    for root in roots:
        rel = root.relative_to(project).as_posix()
        part = scan_units(load_build_info(forge_build(root)), scope, detectors)
        findings += [dataclasses.replace(f, file=f"{rel}/{f.file}") for f in part.findings]
        hooks += [f"{rel}/{h}" for h in part.hooks]
        solc |= set(part.solc)
        for k, v in part.timings_ms.items():
            timings[k] = timings.get(k, 0.0) + v
    return ScanResult(findings=sorted(findings, key=HookFinding.sort_key), hooks=sorted(hooks),
                      solc=sorted(solc), timings_ms=timings)
