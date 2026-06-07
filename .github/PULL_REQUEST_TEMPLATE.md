## What does this PR do?

<!-- One paragraph. What changed and why. -->

## Type of change

- [ ] Bug fix
- [ ] New fingerprinter / discoverer
- [ ] New output format
- [ ] Detection rule / plugin
- [ ] Docs / config
- [ ] Refactor / performance

## Checklist

- [ ] `uv run pytest` passes (239+ tests green)
- [ ] `uv run ruff check scanner/ tests/` passes
- [ ] `uv run mypy scanner/` passes
- [ ] No new code bypasses or softens `ScopeViolationError`
- [ ] No exploit payloads, weaponized code, or active attack logic added
- [ ] `--enrich` (external data) remains opt-in with the loud warning
