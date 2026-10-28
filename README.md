# v4hooks: Uniswap v4 hook security scanner

Deterministic detectors find bugs in Uniswap v4 hooks. A local model (optional) turns
their output into a readable report. **The model never decides what is a finding.**

The detectors are based on the patterns in Trail of Bits' "Building secure Uniswap v4
hooks":

| ID | Detects | Default severity |
|----|---------|------------------|
| V4H-01 | A hook callback or `unlockCallback` that does something and is not gated by `msg.sender == poolManager`. Also flags a sender check against the wrong principal (owner, router). | high |
| V4H-02 | A callback writes state shared across pools (not keyed by `PoolId`) or transfers a `key.currencyN` token, while neither `beforeInitialize` nor the callback restricts which pool is calling. | medium / high |
| V4H-03 | `getHookPermissions()` disagrees with the code: a flag is on but the callback is the reverting BaseHook placeholder, a callback is implemented but its flag is off, a `*ReturnDelta` flag is set without its base flag, or `Hooks.validateHookPermissions` is never called. | high / medium / low |

## Quick start

Scanning needs only
Python 3.10+ and Foundry's `forge` on PATH.

```bash
pip install "git+https://github.com/0xlordgrace/v4hooks"

v4hooks scan path/to/foundry-project                     # findings to stdout; exit 1 at/above --fail-on
v4hooks scan . --sarif v4hooks.sarif --json scan.json    # SARIF for Code Scanning, JSON for reports
v4hooks explain scan.json --no-model                     # markdown report from templates
v4hooks explain scan.json --base-url http://localhost:11434/v1 --model qwen2.5-coder:14b -o report.md
```

`scan` options:
- `--scope src/` (repeatable): what to report on. Dependencies are still read for
  inheritance.
- `--fail-on none|info|low|medium|high|critical`: default `low`.
- `--detector V4H-01`: run only some detectors.
- `--build-info DIR`: reuse an existing `forge build --build-info` output.
- `--uri-prefix`: the path from the repo root to the project, for SARIF links.

Extras: `pip install "v4hooks[report]"` adds `httpx` for model-written reports, and
`[bench]` adds `pyyaml` for `v4hooks bench`.

## Use in CI (GitHub Action)

Add [`examples/v4hooks.yml`](examples/v4hooks.yml) to `.github/workflows/`:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
    with: { submodules: recursive }
  - uses: 0xlordgrace/v4hooks@main
    with:
      project: .
      fail-on: high
```

The Action installs Foundry, builds your project and runs the scan. It uploads the
findings to **Code Scanning**, so they appear as annotations on pull requests, then
fails the job according to `fail-on`. On private repositories, Code Scanning needs
GitHub Advanced Security; set `upload-sarif: false` to only gate on `fail-on`.
The SARIF file stays in the workspace for other steps.

## How it works

1. `forge build --build-info --force` into a fresh directory. solc writes the full
   compact-JSON AST for every source.
2. `find_hooks` picks the concrete leaf contracts that inherit `IHooks` or declare
   IHooks-shaped callbacks.
3. Each detector walks the AST. It resolves inheritance with solc's C3 linearization and
   resolves virtual internal calls against the most-derived contract. Modifiers and helper
   functions are followed up to six calls deep.
4. Findings are de-duplicated by fingerprint, then sorted. The JSON has no timestamps, so
   the same code compiled with the same solc gives byte-identical output.

There are no new Python dependencies. Slither and Aderyn are not required.

## Proving V4H-01 findings (`v4hooks prove`)

A static finding says "the shape is there". `prove` checks whether a stranger can
actually use it:

```bash
v4hooks prove path/to/foundry-project                       # fresh deploy
v4hooks prove path/to/foundry-project --fork-url $RPC \
    --address MyHook=0x... --pool-manager 0x...              # the deployed hook, on a fork
```

For each V4H-01 finding it writes a Foundry test in `test/v4hooks_proof/`, runs only that
directory (`FOUNDRY_TEST`), and deletes it afterwards (`--keep` keeps it). The test:

1. deploys the hook at an address whose low bits carry its permission flags, with a
   stand-in PoolManager (or, with `--fork-url`, uses the deployed address);
2. calls the flagged callback from an address that isn't the PoolManager, trying a few
   argument sets an attacker could pick (empty `hookData`, the attacker's address, zeroed
   bytes that decode as any struct, zero amounts);
3. reports one status per finding:

| status | meaning |
|---|---|
| `proven` | the call succeeded and wrote hook storage |
| `reaches-pm` | the call succeeded and called into the PoolManager, but wrote no hook storage |
| `reverted` | every attempt reverted; the reason is shown (e.g. an owner check) |
| `no-effect` | the call succeeded but changed nothing visible |
| `unsupported` | no test could be built (unknown flag layout, constructor reverts with default arguments, …) |

Only `proven` is evidence. Anything else means "not shown", not "safe": a fresh deploy
has empty state, so a callback that only does damage once positions or orders exist
will look like `no-effect`. Fork mode tests against real state. The generated tests use
no forge-std and nothing outside the project. Never run a proof against mainnet itself.

## The model backend

Any OpenAI-compatible `/chat/completions` endpoint works: oMLX (Apple Silicon, `http://localhost:8001/v1`, needs `--api-key-env` pointing at a var holding its key), Ollama, llama.cpp
`llama-server`, LM Studio, vLLM, or a hosted API. Configure it in `config.yaml`:

```yaml
v4hooks:
  reporter:
    base_url: http://localhost:11434/v1
    model: qwen2.5-coder:14b
    api_key_env: null     # only for hosted APIs: the NAME of an env var
    temperature: 0.0
    seed: 7
    max_tokens: 800
    json_mode: true          # auto-dropped if the server rejects response_format
    reasoning_effort: low    # gpt-oss style; null = server default
    thinking: false          # Qwen-style thinking off; null = server default
```

Measured on oMLX (M-series, 2 findings): gpt-oss-20b-OptiQ-4bit 33s; Qwen3.8-27B-4bit
7 min with thinking on, 66s with `thinking: false`, with better prose. Both had every
reply accepted.

The `V4HOOKS_BASE_URL` / `V4HOOKS_MODEL` environment variables and the `--base-url` /
`--model` flags override the config.

These guardrails live in `explain.py` and are covered by `tests/test_v4hooks_explain.py`:

- The model is called once per detector finding and sees only that finding.
- The report iterates over detector findings. Extra issues in a model reply are discarded.
- Severity, file, lines, contract and function always come from the detector. A
  different severity the model suggests appears as a note.
- A reply is rejected, and that finding falls back to the template text, when it:
  - cites lines outside the finding,
  - mentions another detector's ID,
  - is missing a field, or
  - is not JSON.
- If the backend is down, the report is still produced from templates.
- The report header records the model, endpoint host, temperature, seed, prompt hash and
  the sha256 of the scan input.

## Benchmark corpus (`corpus/`)

| Group | Contracts |
|-------|-----------|
| Vulnerable repros (`src/vulnerable/`) | `CorkStyleHook`: unguarded `beforeSwap` that pays out hook funds, any pool can attach. `UnguardedUnlockHook`: Bunni-style rebalancer with an open `unlockCallback`. `WrongGuardHook`, `AnyPoolPointsHook`, `DeadInitGuardHook`, `BrickedSwapHook`, `UnvalidatedFlagsHook`. |
| Labelled miss | `BunniStyleRoundingHook`: a rounding bug, which none of these detectors look for. It is reported as "out of scope" rather than hidden. |
| Clean negatives | `src/clean/SinglePoolGuardedHook` and all 12 concrete hooks from OpenZeppelin `uniswap-hooks` v1.2.1 (fetched by `corpus/setup.sh`). |

Ground truth is in `corpus/labels.yaml`. Fetch the dependency, then score:

```bash
corpus/setup.sh
v4hooks bench
```

## Tests

```bash
pip install -e ".[report,bench]" pytest
pytest -m "not integration"            # no forge needed
corpus/setup.sh && pytest -m integration   # needs forge
```

The detector unit tests run on `tests/fixtures/v4hooks/ast.json`, an AST snapshot of
`tests/fixtures/v4hooks/project/`. After editing that project's `Cases.sol`, regenerate
the snapshot with `python tests/fixtures/v4hooks/regen.py`.

## Limitations (honest list)

- These are static heuristics. V4H-02 in particular infers "this hook should serve
  specific pools" from shared-state writes. A hook that is deliberately multi-pool and
  keeps a global ledger on purpose will be flagged, and that may be correct to discuss in
  an audit, but it is not always a bug.
- Guards are recognised in `require`/`assert` and `if (...) revert`. Guards in inline
  assembly or in external calls are not seen.
- The address-bit check is "is `validateHookPermissions` ever called". The detector does
  not yet read deployment scripts or mined salts.
- The corpus results are in-sample. The detectors were tuned while it was being built, so
  the numbers show the detectors work on these cases, not how they generalise. Adding
  third-party hooks the detectors have never seen is the next step.
