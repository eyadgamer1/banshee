# Contributing to BANSHEE

## Ground rules

1. **No exploitation.** PRs that add exploit payloads, weaponized shellcode, or active attack capabilities will be closed without review.
2. **Scope guard is sacred.** Never submit code that bypasses or softens `ScopeViolationError`.
3. **All PRs must pass the test suite.** Run `uv run pytest` before opening a PR — it must be green.
4. **Type annotations required.** The project runs `mypy --strict`. Add types to every new function.
5. **Ruff clean.** Run `uv run ruff check scanner/ tests/` before submitting.

## Dev setup

```bash
git clone https://github.com/eyadgamer1/banshee.git
cd banshee
uv sync
uv run pytest          # 239+ tests must pass
uv run ruff check scanner/ tests/
uv run mypy scanner/
```

## Adding a fingerprinter

1. Create `scanner/fingerprint/my_fp.py` implementing the `Fingerprinter` protocol
2. Register it in `scanner/fingerprint/__init__.py` → `get_fingerprinters()`
3. Write tests in `tests/test_fingerprint_my_fp.py`
4. Document in this file if it uses network probes

## Adding a plugin rule

Add a `.yaml` to `config/plugins/` following the schema in `config/plugins/example.yaml`. No code change needed.

## Commit style

```
feat(fingerprint): add SMB banner grabber
fix(engine): scope violation now raised on empty target set
test(budget): parametrize timing template regression
docs: add Docker Compose example
```

## Questions?

Open a [Discussion](https://github.com/eyadgamer1/banshee/discussions) rather than an issue for questions.
