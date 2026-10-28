"""Turn detector output into a readable report, optionally with a model's help.

The model is a writer, not a judge:
  * It is called once per detector finding and sees only that finding.
  * It cannot add findings: the report iterates over detector output, never over
    model output.
  * Severity, location, contract and function always come from the detector. The
    model may *suggest* a different severity; that is shown as a note only.
  * A reply that cites lines outside the finding's range, or is malformed, is
    rejected and that finding falls back to the deterministic template.

Any OpenAI-compatible endpoint works: Ollama (http://localhost:11434/v1),
llama.cpp ``llama-server`` (http://localhost:8080/v1), LM Studio, vLLM, or a
hosted API. API keys are read from an environment variable named in config,
never stored.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlparse

from .model import SEVERITIES, HookFinding

PROMPT_VERSION = "v4hooks-explain-1"

SYSTEM_PROMPT = """You are a smart-contract security writer. A deterministic static \
analyzer has already found the issue below in a Uniswap v4 hook. Your job is to explain \
it clearly and propose a fix. Rules:
- Do not report any other issue. Do not change the location.
- Only reference line numbers inside the given snippet range.
- Reply with ONE JSON object and nothing else:
{"title": str, "explanation": str, "fix": str, "cited_lines": [int], \
"severity_suggestion": "critical|high|medium|low|info", "exploitability": 1-5}"""

DETECTOR_FIXES = {
    "V4H-01": "Restrict the callback to the PoolManager: inherit BaseHook (OpenZeppelin uniswap-hooks or "
    "v4-periphery) and override the internal `_callback`, or add `onlyPoolManager` / "
    "`if (msg.sender != address(poolManager)) revert NotPoolManager();`.",
    "V4H-02": "Bind the hook to the pools it is meant to serve: enable beforeInitialize and revert for "
    "unexpected PoolKeys (currencies, fee, tickSpacing, or a single allowed PoolId), and/or key the "
    "state by PoolId and check `key.toId()` against an allowlist in the callback.",
    "V4H-03": "Make getHookPermissions() match the implemented callbacks exactly, mine the hook address "
    "with HookMiner for those flags, and call Hooks.validateHookPermissions in the constructor "
    "(BaseHook does this).",
}


class Backend(Protocol):
    def describe(self) -> dict[str, Any]: ...

    def complete(self, system: str, user: str) -> str: ...


@dataclass
class OpenAICompatBackend:
    base_url: str
    model: str
    api_key_env: str | None = None
    temperature: float = 0.0
    seed: int = 7
    max_tokens: int = 800  # one write-up is ~150-400 words of JSON
    json_mode: bool = True  # response_format=json_object; dropped automatically if the server rejects it
    reasoning_effort: str | None = "low"  # the detector already did the analysis; None = server default
    thinking: bool | None = False  # Qwen-style thinking via chat_template_kwargs; None = server default
    timeout: float = 600.0

    def describe(self) -> dict[str, Any]:
        host = urlparse(self.base_url).netloc or self.base_url
        return {"backend": "openai-compatible", "endpoint": host, "model": self.model,
                "temperature": self.temperature, "seed": self.seed, "max_tokens": self.max_tokens,
                "json_mode": self.json_mode, "reasoning_effort": self.reasoning_effort,
                "thinking": self.thinking}

    def request_body(self, system: str, user: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": self.temperature,
            "seed": self.seed,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        if self.json_mode:
            body["response_format"] = {"type": "json_object"}
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort
        if self.thinking is not None:
            body["chat_template_kwargs"] = {"enable_thinking": self.thinking}
        return body

    def complete(self, system: str, user: str) -> str:
        key = os.environ.get(self.api_key_env, "") if self.api_key_env else ""
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        body = self.request_body(system, user)
        text = self._post(url, body, headers)
        if text is None or (not text.strip() and "response_format" in body):
            # Some servers reject JSON mode (400); others, e.g. gpt-oss on oMLX, silently
            # return an empty completion. Retry once without it; the prompt still asks for JSON.
            body.pop("response_format", None)
            text = self._post(url, body, headers) or ""
        return strip_thinking(text)

    def _post(self, url: str, body: dict[str, Any], headers: dict[str, str]) -> str | None:
        """Reply text, or None if the server rejected JSON mode with a 400."""
        import httpx  # optional dependency: only needed when a model is configured

        resp = httpx.post(url, json=body, headers=headers, timeout=self.timeout)
        if resp.status_code == 400 and "response_format" in body:
            return None
        resp.raise_for_status()
        data = resp.json()
        return ((data.get("choices") or [{}])[0].get("message") or {}).get("content") or ""


def extract_json(text: str) -> dict[str, Any] | None:
    """The first JSON object in a model reply, fenced or bare."""
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidates = [fence.group(1)] if fence else []
    start = text.find("{")
    if start >= 0:
        depth = 0
        for i, ch in enumerate(text[start:], start):
            depth += ch == "{"
            depth -= ch == "}"
            if depth == 0:
                candidates.append(text[start : i + 1])
                break
    for cand in candidates:
        try:
            obj = json.loads(cand)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def strip_thinking(text: str) -> str:
    """Drop <think>...</think> blocks some models emit inline, so their braces can't
    be mistaken for the JSON reply."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def backend_from_config(cfg: dict[str, Any] | None, *, base_url: str | None = None, model: str | None = None,
                        api_key_env: str | None = None) -> OpenAICompatBackend | None:
    """Build the backend from ``v4hooks.reporter`` in config.yaml, CLI flags, or env.

    Precedence: explicit args > V4HOOKS_BASE_URL / V4HOOKS_MODEL / V4HOOKS_API_KEY_ENV env > config.
    Returns None when no model is configured (template-only reports).
    """
    rc = ((cfg or {}).get("v4hooks") or {}).get("reporter") or {}
    base_url = base_url or os.environ.get("V4HOOKS_BASE_URL") or rc.get("base_url")
    model = model or os.environ.get("V4HOOKS_MODEL") or rc.get("model")
    if not base_url or not model:
        return None
    defaults = OpenAICompatBackend(base_url="", model="")
    return OpenAICompatBackend(
        base_url=base_url,
        model=model,
        api_key_env=api_key_env or os.environ.get("V4HOOKS_API_KEY_ENV") or rc.get("api_key_env"),
        temperature=float(rc.get("temperature", defaults.temperature)),
        seed=int(rc.get("seed", defaults.seed)),
        max_tokens=int(rc.get("max_tokens", defaults.max_tokens)),
        json_mode=bool(rc.get("json_mode", defaults.json_mode)),
        reasoning_effort=rc.get("reasoning_effort", defaults.reasoning_effort),
        thinking=rc.get("thinking", defaults.thinking),
    )


@dataclass
class Explained:
    finding: HookFinding
    title: str
    explanation: str
    fix: str
    source: str  # "model" | "template" | "template (model rejected: ...)"
    severity_note: str = ""
    exploitability: int | None = None


@dataclass
class Report:
    items: list[Explained]
    meta: dict[str, Any] = field(default_factory=dict)

    def to_markdown(self) -> str:
        m = self.meta
        out = [
            "# Uniswap v4 hook scan report",
            "",
            f"- Findings: {len(self.items)} (from deterministic detectors; the model only writes prose)",
            f"- Scan input sha256: `{m.get('scan_sha256', '')}`",
            f"- Writer: {json.dumps(m.get('backend', {'backend': 'template'}), sort_keys=True)}",
            f"- Prompt: `{PROMPT_VERSION}` sha256 `{m.get('prompt_sha256', '')}`",
            "",
        ]
        if not self.items:
            out.append("No findings.")
        for i, e in enumerate(self.items, 1):
            f = e.finding
            out += [
                f"## {i}. [{f.severity.upper()}] {e.title}",
                "",
                f"- **Detector:** {f.detector} — {f.title}",
                f"- **Confidence:** {f.confidence}",
                f"- **Location:** `{f.file}:{f.line_start}-{f.line_end}` (`{f.contract}.{f.function}`)",
                f"- **Fingerprint:** `{f.fingerprint}`",
                f"- **Written by:** {e.source}",
            ]
            if e.severity_note:
                out.append(f"- **Writer's severity note:** {e.severity_note}")
            if e.source == "model":
                out += ["", "### Explanation", "", e.explanation]
            out += ["", "### Detector evidence", "", f.message, "", "```solidity", f.snippet, "```",
                    "", "### Suggested fix", "", e.fix, ""]
        return "\n".join(out).rstrip() + "\n"


def template_explanation(f: HookFinding) -> Explained:
    return Explained(
        finding=f,
        title=f"{f.title} in {f.contract}.{f.function}",
        explanation=f.message,
        fix=DETECTOR_FIXES.get(f.detector, "See detector evidence."),
        source="template",
    )


def finding_prompt(f: HookFinding) -> str:
    return json.dumps(
        {
            "detector": f.detector,
            "detector_title": f.title,
            "severity": f.severity,
            "contract": f.contract,
            "function": f.function,
            "file": f.file,
            "line_range": [f.line_start, f.line_end],
            "detector_message": f.message,
            "evidence": f.evidence,
            "snippet_first_line": f.line_start,
            "snippet": f.snippet,
            "reference_fix": DETECTOR_FIXES.get(f.detector, ""),
        },
        indent=2,
        sort_keys=True,
    )


def validate_reply(f: HookFinding, reply: dict[str, Any] | None) -> str | None:
    """Return a rejection reason, or None if the reply is acceptable."""
    if reply is None:
        return "no JSON object in reply"
    for k in ("title", "explanation", "fix"):
        if not isinstance(reply.get(k), str) or not reply[k].strip():
            return f"missing {k}"
    cited = reply.get("cited_lines") or []
    if not isinstance(cited, list) or not all(isinstance(x, int) for x in cited):
        return "cited_lines is not a list of ints"
    outside = [x for x in cited if not f.line_start <= x <= f.line_end]
    if outside:
        return f"cites lines outside {f.line_start}-{f.line_end}: {outside}"
    other_ids = {"V4H-01", "V4H-02", "V4H-03"} - {f.detector}
    text = " ".join(str(reply.get(k, "")) for k in ("title", "explanation", "fix"))
    if any(i in text for i in other_ids):
        return "reply refers to a different detector's finding"
    return None


def explain(findings: list[HookFinding], backend: Backend | None = None, scan_sha256: str = "") -> Report:
    items: list[Explained] = []
    for f in findings:
        base = template_explanation(f)
        if backend is None:
            items.append(base)
            continue
        try:
            raw = backend.complete(SYSTEM_PROMPT, finding_prompt(f))
            reply = extract_json(raw)
            reason = validate_reply(f, reply)
        except Exception as e:  # network / server errors degrade to template, never abort the report
            reply, reason = None, f"backend error: {type(e).__name__}"
        if reason:
            base.source = f"template (model output rejected: {reason})"
            items.append(base)
            continue
        assert reply is not None
        note = ""
        sugg = str(reply.get("severity_suggestion", "")).lower()
        if sugg in SEVERITIES and sugg != f.severity:
            note = f"suggested {sugg}; detector severity {f.severity} is kept"
        expl = reply.get("exploitability")
        items.append(
            Explained(
                finding=f,
                title=reply["title"].strip(),
                explanation=reply["explanation"].strip(),
                fix=reply["fix"].strip(),
                source="model",
                severity_note=note,
                exploitability=expl if isinstance(expl, int) and 1 <= expl <= 5 else None,
            )
        )
    items.sort(key=rank_key)
    return Report(
        items=items,
        meta={
            "scan_sha256": scan_sha256,
            "backend": backend.describe() if backend else {"backend": "template"},
            "prompt_sha256": hashlib.sha256((PROMPT_VERSION + SYSTEM_PROMPT).encode()).hexdigest()[:16],
        },
    )


def rank_key(e: Explained) -> tuple:
    """Detector severity first; the model's exploitability score only breaks ties."""
    f = e.finding
    return (SEVERITIES.index(f.severity), -(e.exploitability or 0), *f.sort_key())
