"""Report writer: the model can phrase findings but never add or relocate them."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from fake_openai_server import FakeOpenAIServer  # noqa: E402

from v4hooks.explain import OpenAICompatBackend, backend_from_config, explain  # noqa: E402
from v4hooks.model import HookFinding  # noqa: E402


def _finding(**kw) -> HookFinding:
    base = dict(
        detector="V4H-01", title="Hook callback not restricted to PoolManager", severity="high",
        contract="Hook", function="beforeSwap", file="src/Hook.sol", line_start=10, line_end=20,
        message="Hook.beforeSwap has no msg.sender check.", evidence={"callback": "beforeSwap"},
        snippet="function beforeSwap(...) external {",
    )
    base.update(kw)
    return HookFinding(**base)


def _reply(**kw):
    body = {"title": "Anyone can call beforeSwap", "explanation": "Line 12 lacks a gate.",
            "fix": "Add onlyPoolManager.", "cited_lines": [12], "severity_suggestion": "high",
            "exploitability": 4}
    body.update(kw)
    return {"text": json.dumps(body)}


def _backend(srv):
    return OpenAICompatBackend(base_url=srv.base_url, model="fake-model")


def test_template_report_without_model():
    md = explain([_finding()]).to_markdown()
    assert "[HIGH]" in md and "src/Hook.sol:10-20" in md and "template" in md
    assert "onlyPoolManager" in md  # canned fix


def test_model_writes_prose_but_detector_owns_facts():
    with FakeOpenAIServer([_reply(severity_suggestion="critical")]) as srv:
        rep = explain([_finding()], _backend(srv))
    [item] = rep.items
    assert item.source == "model" and item.title == "Anyone can call beforeSwap"
    assert item.finding.severity == "high"  # not upgraded
    assert "suggested critical" in item.severity_note
    req = srv.requests[0]
    assert req["temperature"] == 0.0 and req["seed"] == 7


def test_one_call_per_finding_and_no_extra_findings():
    # Even if the model "reports" more issues, the report has exactly the detector's.
    sneaky = _reply(explanation="Also, V4H-02: the hook never validates the PoolKey!")
    with FakeOpenAIServer([sneaky, _reply(cited_lines=[31])]) as srv:
        rep = explain([_finding(), _finding(function="afterSwap", line_start=30, line_end=40,
                                            snippet="x")], _backend(srv))
    assert len(srv.requests) == 2
    assert len(rep.items) == 2
    rejected = [i for i in rep.items if i.source.startswith("template")]
    assert len(rejected) == 1 and "different detector" in rejected[0].source


@pytest.mark.parametrize(
    "reply,reason",
    [
        (_reply(cited_lines=[99]), "outside 10-20"),
        ({"text": "I think this is fine."}, "no JSON"),
        (_reply(fix=""), "missing fix"),
    ],
)
def test_bad_replies_fall_back_to_template(reply, reason):
    with FakeOpenAIServer([reply]) as srv:
        [item] = explain([_finding()], _backend(srv)).items
    assert reason in item.source
    assert item.explanation == "Hook.beforeSwap has no msg.sender check."


def test_backend_down_degrades_gracefully():
    dead = OpenAICompatBackend(base_url="http://127.0.0.1:9/v1", model="x", timeout=1)
    [item] = explain([_finding()], dead).items
    assert "backend error" in item.source


def test_ranking_by_detector_severity_then_exploitability():
    findings = [_finding(severity="medium", function="a"), _finding(function="b"), _finding(function="c")]
    script = [_reply(), _reply(exploitability=2), _reply(exploitability=5)]
    with FakeOpenAIServer(script) as srv:
        rep = explain(findings, _backend(srv))
    assert [i.finding.function for i in rep.items] == ["c", "b", "a"]


def test_backend_config_precedence(monkeypatch):
    cfg = {"v4hooks": {"reporter": {"base_url": "http://localhost:11434/v1", "model": "qwen", "seed": 3}}}
    monkeypatch.delenv("V4HOOKS_BASE_URL", raising=False)
    monkeypatch.delenv("V4HOOKS_MODEL", raising=False)
    assert backend_from_config({}) is None
    b = backend_from_config(cfg)
    assert (b.base_url, b.model, b.seed) == ("http://localhost:11434/v1", "qwen", 3)
    monkeypatch.setenv("V4HOOKS_MODEL", "llama")
    assert backend_from_config(cfg).model == "llama"
    assert backend_from_config(cfg, model="explicit").model == "explicit"
    assert "api_key" not in json.dumps(b.describe())


def test_request_carries_generation_settings():
    with FakeOpenAIServer([_reply()]) as srv:
        explain([_finding()], _backend(srv))
    req = srv.requests[0]
    assert req["max_tokens"] == 800
    assert req["response_format"] == {"type": "json_object"}
    assert req["reasoning_effort"] == "low"
    assert req["chat_template_kwargs"] == {"enable_thinking": False}


def test_server_defaults_omit_optional_fields():
    with FakeOpenAIServer([_reply()]) as srv:
        b = OpenAICompatBackend(base_url=srv.base_url, model="m", json_mode=False,
                                reasoning_effort=None, thinking=None)
        explain([_finding()], b)
    req = srv.requests[0]
    assert not {"response_format", "reasoning_effort", "chat_template_kwargs"} & req.keys()


def test_thinking_block_is_stripped_before_parsing():
    think = {"text": "<think>maybe {\"title\": \"wrong\"}</think>" + _reply()["text"]}
    with FakeOpenAIServer([think]) as srv:
        [item] = explain([_finding()], _backend(srv)).items
    assert item.source == "model" and item.title == "Anyone can call beforeSwap"


def test_settings_read_from_config(monkeypatch):
    monkeypatch.delenv("V4HOOKS_BASE_URL", raising=False)
    monkeypatch.delenv("V4HOOKS_MODEL", raising=False)
    cfg = {"v4hooks": {"reporter": {"base_url": "http://x/v1", "model": "q", "max_tokens": 1200,
                                    "thinking": None, "reasoning_effort": "medium"}}}
    b = backend_from_config(cfg)
    assert (b.max_tokens, b.thinking, b.reasoning_effort, b.json_mode) == (1200, None, "medium", True)


def test_empty_reply_in_json_mode_retries_without_it():
    # gpt-oss on oMLX returns an empty completion (not a 400) when response_format is set.
    def responder(body):
        return {"text": ""} if "response_format" in body else _reply()

    with FakeOpenAIServer(responder) as srv:
        [item] = explain([_finding()], _backend(srv)).items
    assert item.source == "model"
    assert len(srv.requests) == 2 and "response_format" not in srv.requests[1]


def test_api_key_env_name_from_environment(monkeypatch):
    monkeypatch.setenv("V4HOOKS_BASE_URL", "http://localhost:8001/v1")
    monkeypatch.setenv("V4HOOKS_MODEL", "Qwen3.8-27B-4bit")
    monkeypatch.setenv("V4HOOKS_API_KEY_ENV", "OMLX_API_KEY")
    assert backend_from_config({}).api_key_env == "OMLX_API_KEY"


def test_bench_matches_callback_entry_and_implementation_names():
    # Labellers name the external callback ("beforeSwap"); detectors anchor on the
    # implementation ("_beforeSwap"). The scorer must treat them as the same function.
    from v4hooks.benchmark import _norm_fn

    assert _norm_fn("_beforeSwap") == _norm_fn("beforeSwap") == "beforeSwap"
    assert _norm_fn("unlockCallback") == "unlockCallback"
