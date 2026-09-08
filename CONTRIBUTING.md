# Contributing

## Ground rules

1. No exploit code. PRs that add shellcode, weaponized payloads, or anything that attacks a target will be closed.
2. Don't touch the scope guard. `ScopeViolationError` must always raise — no softening, no bypassing.
3. Type everything. The project runs `mypy --strict`. Every new function needs annotations.
4. Keep ruff happy. Run `uv run ruff check scanner/` before submitting.
5. Verify manually before opening a PR: run the CLI against a host you control and confirm the reported ports/services match reality. See [Prove the results are real](README.md#prove-the-results-are-real).

## Setup

```bash
git clone https://github.com/eyadgamer1/banshee.git
cd banshee
uv sync
uv run ruff check scanner/
uv run mypy scanner/
```

## Adding a fingerprinter

1. Create `scanner/fingerprint/my_fp.py` implementing the `Fingerprinter` protocol
2. Register it in `scanner/fingerprint/__init__.py` inside `get_fingerprinters()`

## Adding a plugin rule

Add a `.yaml` file to `config/plugins/` following the schema in `config/plugins/example.yaml`. No code change needed.

## Commit format

```
feat(fingerprint): add SMB banner grabber
fix(engine): raise scope violation on empty target list
docs: add Compose example to README
```

## Questions

Open a [Discussion](https://github.com/eyadgamer1/banshee/discussions) instead of an issue for general questions.
