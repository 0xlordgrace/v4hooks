"""Rebuild tests/fixtures/v4hooks/ast.json from ./project (needs forge).

    python tests/fixtures/v4hooks/regen.py
"""

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
from v4hooks.solast import forge_build  # noqa: E402

bi_dir = forge_build(HERE / "project")
(bi,) = sorted(bi_dir.glob("*.json"))
data = json.loads(bi.read_text())
fixture = {
    "solc": data.get("solcLongVersion", ""),
    "sources": {
        path: {"ast": src["ast"], "content": data["input"]["sources"][path]["content"]}
        for path, src in sorted(data["output"]["sources"].items())
    },
}
(HERE / "ast.json").write_text(json.dumps(fixture, separators=(",", ":"), sort_keys=True))
print(f"wrote {HERE / 'ast.json'} ({(HERE / 'ast.json').stat().st_size // 1024} KiB)")
