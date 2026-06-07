# Contributing

## Ground rules

1. No exploit code. PRs that add shellcode, weaponized payloads, or anything that attacks a target will be closed.
2. Don't touch the scope guard. `ScopeViolationError` must always raise — no softening, no bypassing.
3. Tests must pass before you open a PR. Run `uv run pytest` locally first.
4. Type everything. The project runs `mypy --strict`. Every new function needs annotations.
5. Keep ruff happy. Run `uv run ruff check scanner/` before submitting.

## Setup

```bash
git clone https://github.com/eyadgamer1/banshee.git
cd banshee
uv sync
uv run pytest
uv run ruff check scanner/
uv run mypy scanner/
```

## Adding a fingerprinter

1. Create `scanner/fingerprint/my_fp.py` implementing the `Fingerprinter` protocol
2. Register it in `scanner/fingerprint/__init__.py` inside `get_fingerprinters()`
3. Write tests in `tests/test_fingerprint_my_fp.py`

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
