"""Score the detectors against a labelled corpus: TP / FP / FN and time per detector."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detectors import ALL_DETECTORS
from .scanner import scan_units
from .solast import forge_build, load_build_info

# Only present in a source checkout; installed packages pass --labels.
DEFAULT_LABELS = Path(__file__).resolve().parents[1] / "corpus" / "labels.yaml"


@dataclass
class DetectorScore:
    detector: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    ms: float = 0.0
    tp_confirmed: int = 0
    fp_confirmed: int = 0
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def precision_confirmed(self) -> float | None:
        n = self.tp_confirmed + self.fp_confirmed
        return self.tp_confirmed / n if n else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None


@dataclass
class BenchResult:
    scores: dict[str, DetectorScore]
    build_ms: float
    hooks_scanned: int
    unlabelled: list[str]
    out_of_scope: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "build_ms": round(self.build_ms, 1),
            "hooks_scanned": self.hooks_scanned,
            "unlabelled_hooks": self.unlabelled,
            "out_of_scope": self.out_of_scope,
            "detectors": {
                d: {
                    "tp": s.tp, "fp": s.fp, "fn": s.fn,
                    "precision": s.precision, "recall": s.recall,
                    "tp_confirmed": s.tp_confirmed, "fp_confirmed": s.fp_confirmed,
                    "precision_confirmed": s.precision_confirmed,
                    "ms": round(s.ms, 2),
                    "false_positives": s.false_positives,
                    "false_negatives": s.false_negatives,
                }
                for d, s in self.scores.items()
            },
        }


def _norm_fn(name: str) -> str:
    """BaseHook-style hooks implement `beforeSwap` in `_beforeSwap`. Labels may name
    either; treat them as one function so a finding isn't scored as both an FP and an FN."""
    return name[1:] if name.startswith("_") else name


def run_benchmark(labels_path: Path = DEFAULT_LABELS, build_info: Path | None = None) -> BenchResult:
    import yaml  # optional dependency: only the benchmark reads YAML

    labels = yaml.safe_load(Path(labels_path).read_text())
    project = (Path(labels_path).parent if not labels.get("project") else Path(labels_path).parent / labels["project"])
    t0 = time.perf_counter()
    bi = Path(build_info) if build_info else forge_build(project)
    units = load_build_info(bi)
    build_ms = (time.perf_counter() - t0) * 1000

    result = scan_units(units, labels.get("scope"))
    contracts: dict[str, Any] = labels.get("contracts", {})
    scores = {d.id: DetectorScore(d.id, ms=result.timings_ms.get(d.id, 0.0)) for d in ALL_DETECTORS}

    expected = {
        (c, e["detector"], _norm_fn(e["function"]))
        for c, spec in contracts.items()
        for e in (spec or {}).get("expect", [])
    }
    # Informational findings (e.g. "never calls validateHookPermissions") are shown in
    # scan output but not scored: the labelling rule treats them as non-findings.
    scored = [f for f in result.findings if f.severity != "info"]
    # A label matches a finding if it names the finding's function or the callback the
    # finding is about: V4H-03 anchors "flag on, not implemented" on the permissions
    # function, while a labeller may name the callback.
    matched: set[tuple] = set()
    for f in sorted(scored, key=lambda f: f.sort_key()):
        aliases = {_norm_fn(f.function)}
        if isinstance(f.evidence.get("callback"), str):
            aliases.add(_norm_fn(f.evidence["callback"]))
        hits = {k for k in expected if k[0] == f.contract and k[1] == f.detector and k[2] in aliases}
        s = scores[f.detector]
        if hits:
            new_hits = hits - matched
            s.tp += len(new_hits)
            if f.confidence == "confirmed":
                s.tp_confirmed += len(new_hits)
            matched |= hits
        else:
            s.fp += 1
            s.fp_confirmed += f.confidence == "confirmed"
            s.false_positives.append(f"{f.contract}.{_norm_fn(f.function)}")
    for key in sorted(expected - matched):
        s = scores[key[1]]
        s.fn += 1
        s.false_negatives.append(f"{key[0]}.{key[2]}")

    scanned = [h.split(":")[-1] for h in result.hooks]
    oos = [
        {"contract": c, **o} for c, spec in contracts.items() for o in (spec or {}).get("out_of_scope", [])
    ]
    return BenchResult(
        scores=scores,
        build_ms=build_ms,
        hooks_scanned=len(scanned),
        unlabelled=sorted(set(scanned) - set(contracts)),
        out_of_scope=oos,
    )


def render_table(res: BenchResult) -> str:
    def pct(x: float | None) -> str:
        return "  n/a" if x is None else f"{x * 100:5.1f}%"

    lines = [
        f"hooks scanned: {res.hooks_scanned}   forge build + AST load: {res.build_ms:.0f} ms",
        "",
        f"{'detector':<8} {'TP':>3} {'FP':>3} {'FN':>3} {'precision':>10} {'recall':>8} {'time':>9}"
        f"   {'confirmed TP/FP':>15} {'precision':>10}",
    ]
    for s in res.scores.values():
        lines.append(
            f"{s.detector:<8} {s.tp:>3} {s.fp:>3} {s.fn:>3} {pct(s.precision):>10} {pct(s.recall):>8} {s.ms:>7.1f}ms"
            f"   {f'{s.tp_confirmed}/{s.fp_confirmed}':>15} {pct(s.precision_confirmed):>10}"
        )
    for s in res.scores.values():
        for fp in s.false_positives:
            lines.append(f"  FP {s.detector}: {fp}")
        for fn in s.false_negatives:
            lines.append(f"  FN {s.detector}: {fn}")
    for o in res.out_of_scope:
        lines.append(f"  out of scope (missed by design): {o['contract']}.{o.get('function', '?')} [{o['class']}]")
    if res.unlabelled:
        lines.append(f"  unlabelled hooks (not scored): {', '.join(res.unlabelled)}")
    return "\n".join(lines)
