# Contributing

Small, focused repo — the bar for contributing is low.

## Before opening a PR

```bash
pip install -e ".[test]"
pytest test/ --ignore=test/test_postgres_integration.py   # sqlite + mocked backends
mypy src
ruff check src test
```

If you have a local Postgres instance, also run the concurrency proof:

```bash
createdb pg_rate_limiter_test
PG_RATE_LIMITER_TEST_DATABASE_URL=postgresql+asyncpg://localhost/pg_rate_limiter_test pytest test/test_postgres_integration.py
```

CI runs all of the above on every push/PR (the Postgres job uses a GitHub
Actions service container, no local Docker required). If your change adds a
new code path, add a test for it rather than only checking manually.

## Style

- Comments explain *why*, not *what* — the code says what it does.
- Keep the module split as-is (`domain.py` for types, `backends.py` for the
  actual DB statements, `service.py` for the public `RateLimiter` API,
  `model.py` for the table, `cleanup.py` standalone) unless a change
  genuinely needs a new module.
- No new dependencies for something the standard library or an existing
  dependency already covers.

## Reporting bugs

Open an issue with the policy shape (limit/window/failure_mode), what you
expected, and what you got — a minimal repro against SQLite is preferred
since it needs no external DB.

## Security issues

Do not open a public issue — see [SECURITY.md](SECURITY.md).
