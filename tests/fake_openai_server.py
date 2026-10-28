"""A scripted OpenAI-compatible chat server for exercising pi without an API key.

Each POST to /v1/chat/completions pops the next scripted reply. A reply is either
{"text": "..."} or {"tool": name, "args": {...}}. Instead of a list, ``script``
may be a callable ``(request_body) -> reply`` for tests where concurrent sessions
make ordering nondeterministic. Streaming and non-streaming requests are both
answered, since pi streams by default.
"""

from __future__ import annotations

import itertools
import json
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class FakeOpenAIServer:
    def __init__(self, script: list[dict[str, Any]] | Callable[[dict[str, Any]], dict[str, Any]]):
        self.responder = script if callable(script) else None
        self.script = [] if callable(script) else list(script)
        self.requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def do_GET(self):
                self._json(200, {"object": "list", "data": [{"id": "fake-model", "object": "model"}]})

            def do_POST(self):
                length = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                with server._lock:
                    server.requests.append(body)
                    if server.responder:
                        reply = server.responder(body)
                    else:
                        reply = server.script.pop(0) if server.script else {"text": "done"}
                if body.get("stream"):
                    self._stream(reply)
                else:
                    self._json(200, _completion(reply))

            def _json(self, code, payload):
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _stream(self, reply):
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.end_headers()
                for chunk in _chunks(reply):
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()


_USAGE = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}


def _completion(reply):
    msg: dict[str, Any] = {"role": "assistant", "content": reply.get("text")}
    finish = "stop"
    if "tool" in reply:
        msg["tool_calls"] = [_tool_call(reply)]
        finish = "tool_calls"
    return {
        "id": "cmpl-fake",
        "object": "chat.completion",
        "model": "fake-model",
        "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
        "usage": _USAGE,
    }


_CALL_IDS = itertools.count(1)


def _tool_call(reply):
    return {
        "id": f"call_{next(_CALL_IDS)}",
        "type": "function",
        "function": {"name": reply["tool"], "arguments": json.dumps(reply.get("args", {}))},
    }


def _chunks(reply):
    base = {"id": "cmpl-fake", "object": "chat.completion.chunk", "model": "fake-model"}
    if "tool" in reply:
        call = _tool_call(reply)
        call["index"] = 0
        yield {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [call]}}]}
        yield {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}], "usage": _USAGE}
    else:
        yield {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": reply.get("text", "")}}]}
        yield {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": _USAGE}
