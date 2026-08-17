# pg-rate-limiter

A Postgres-backed, atomic, batched API rate limiter for FastAPI/SQLAlchemy
apps. No Redis required.

## Problem it solves

Most rate limiters assume you already run Redis. If you don't — and plenty
of small-to-mid FastAPI apps run on nothing but Postgres — adding Redis
*just* for rate limiting is a whole extra service to provision, monitor,
and keep available, for one narrow job.

This library does the job with the database you already have, using
Postgres's `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` as an atomic
upsert-and-increment. It also solves a subtler problem competent naive
implementations get wrong: when one request needs to check *multiple*
subjects at once (e.g. both the caller's IP and their user id), doing that
as N sequential `hit()` calls is N round trips and leaves a real
consistency gap if the Nth call fails after the first N-1 succeeded. This
library batches that into one round trip, one commit, all-or-nothing.

## Where this came from

Extracted from a production FastAPI app's rate limiter after a database
audit turned up two real findings on the underlying table:

- **Sequence exhaustion, found while cheap.** The table's primary key was
  `int4` (max ~2.1 billion). At this table's write rate — every
  IP+user-limited request writes 2 rows — that's a genuine long-run risk,
  not a hypothetical one. It was fixed while the table was still small
  (~2,000 rows, a fast `ALTER COLUMN ... TYPE bigint` with no backfill)
  instead of deferred to a future, higher-stakes migration. **The gotcha
  inside that fix**: widening the *column* to bigint isn't enough on its
  own — the auto-created sequence backing it keeps its own separate
  `int4`-bound ceiling until you explicitly `ALTER SEQUENCE ... AS bigint`
  too. This library ships bigint (with a SQLite-compatible variant) from
  the start so nobody using it has to rediscover that.
- **Concurrency, proven, not just reasoned about.** The batched upsert path
  had only ever been exercised against SQLite, sequentially — never against
  real Postgres, under real concurrency. A dedicated test (`test/
  test_postgres_integration.py` in this repo) fires 8 genuinely concurrent
  hits at the same subject and asserts the count lands at exactly 8. It
  does.

If you're running a rate limiter on top of Postgres already, both of these
are worth checking for regardless of whether you use this library.

## Quickstart

```bash
pip install pg-rate-limiter
```

```python
from fastapi import Depends, FastAPI, Request, Response
from pg_rate_limiter import RateLimitPolicy, RateLimiter

limiter = RateLimiter(subject_secret="a-fresh-random-secret-you-generate")
policy = RateLimitPolicy(name="public_api", limit=60, window_seconds=60)

app = FastAPI()

@app.get("/hello")
async def hello(request: Request, response: Response, db=Depends(get_db_session)):
    await limiter.enforce_ip_limit(request, response, policy, db)
    return {"message": "hi"}
```

That's it for the happy path. See [Setup](#setup) for creating the table.

## Architecture

- **`domain.py`** — plain dataclasses/enums: `RateLimitPolicy` (name, limit,
  window, failure mode), `RateLimitDecision` (allowed, remaining, reset_at,
  backend status).
- **`backends.py`** — the actual atomic upsert, dialect-aware (Postgres and
  SQLite; SQLite is what the test suite runs against, Postgres is what you
  deploy against).
- **`service.py`** — the public `RateLimiter` class: wraps a backend with
  the failure-mode contract (shared → local fallback → fail-open →
  fail-closed) and the FastAPI-facing `enforce_*` helpers.
- **`model.py`** — the `rate_limit_buckets` SQLAlchemy table.
- **`cleanup.py`** — standalone script, no FastAPI/library import, for a
  scheduled job to delete expired rows.

Each policy hit is keyed by `(policy_name, subject_hmac, window)`, where
`window = floor(now / window_seconds)` — a fixed-window counter, not a
sliding one (see [Roadmap](#roadmap--where-to-contribute) for why that's a
known tradeoff, not an oversight).

## Requirements

- Python 3.10+
- Postgres 13+ (for `INSERT ... ON CONFLICT ... RETURNING`) — SQLite works
  for local dev/tests, but is not a supported concurrent-write target
- FastAPI 0.115+, SQLAlchemy 2.0+, `asyncpg` for the Postgres driver

## Setup

Create the table via your own Alembic migration (or call
`Base.metadata.create_all` directly in a script/test):

```python
from pg_rate_limiter import Base
# Base.metadata has one table: rate_limit_buckets
```

Then construct one `RateLimiter` at app startup and reuse it — it holds the
local-fallback cache, so a fresh instance per request defeats that fallback:

```python
limiter = RateLimiter(
    subject_secret=os.environ["RATE_LIMIT_SUBJECT_SECRET"],  # dedicated, see Security
    allow_local_fallback=False,  # True only in dev/test, see Security
)
```

## Run it

```bash
git clone https://github.com/hirad121/pg-rate-limiter
cd pg-rate-limiter
pip install -e ".[test]"
createdb pg_rate_limiter_dev
python -c "
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from pg_rate_limiter import Base

async def main():
    engine = create_async_engine('postgresql+asyncpg://localhost/pg_rate_limiter_dev')
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
asyncio.run(main())
"
```

## Use it

```python
# Per-IP only:
await limiter.enforce_ip_limit(request, response, policy, db)

# Per-IP AND per-user, strictest of the two wins, one DB round trip:
await limiter.enforce_user_limit(request, response, policy, user_id, db)

# Arbitrary subject list (e.g. phone number + challenge id), deduped,
# one DB round trip:
await limiter.enforce_subject_limits(response, policy, ["phone:+1555...", "challenge:abc"], db)
```

Every `enforce_*` call sets `X-RateLimit-Limit`/`-Remaining`/`-Reset`
headers on `response` and raises `HTTPException(429)` when exceeded.

## API reference

| Function | Use for |
|---|---|
| `RateLimiter(subject_secret, allow_local_fallback=False, on_backend_failure=None)` | one instance per app |
| `enforce_ip_limit(request, response, policy, db)` | anonymous/public endpoints |
| `enforce_user_limit(request, response, policy, user_id, db)` | authenticated endpoints, IP+user combined |
| `enforce_subject_limits(response, policy, subjects, db)` | multi-subject cases (e.g. OTP challenge + phone) |
| `hit(policy, subject, db)` / `hit_many(policy, subjects, db)` | lower-level, returns a `RateLimitDecision` without raising |
| `probe_backend(db)` | readiness check — raises 503 if the shared backend is unreachable |
| `delete_expired_buckets(db, limit=5000)` | called by `cleanup.py`, or call directly from your own scheduler |

## Security

- **`subject_secret` must be dedicated — no fallback to another app
  secret.** The source app this was extracted from had
  `RATE_LIMIT_SUBJECT_SECRET` fall back to a shared app-wide auth secret
  when unset, coupling two unrelated purposes (rotating one silently
  affected the other). This library removes that fallback entirely and
  requires an explicit, non-empty secret — generate a fresh random value
  for it (`openssl rand -hex 32`), don't reuse one from anywhere else.
- **Only an HMAC-SHA256 digest of the subject is ever persisted** — the raw
  IP address or user id is never written to the `rate_limit_buckets` table.
- **`FAIL_OPEN` is an explicit, per-policy opt-in, never the default.** A
  policy set to `FAIL_OPEN` means: if the shared backend is unreachable,
  requests are allowed through *without* rate limiting until it recovers.
  That's the right tradeoff for some endpoints (don't take down public
  reads because the limiter DB hiccupped) and the wrong one for others
  (payment/auth endpoints should almost always be `FAIL_CLOSED`). Choose
  per policy, don't blanket-default to open.
- **`allow_local_fallback=True` is for dev/test only.** In a multi-instance
  deployment, the local fallback counter is per-process, not shared — it
  will under-count real traffic against a real limit. Leave it `False` in
  production; a Postgres outage should hit your configured
  `failure_mode`, not silently degrade to a per-instance guess.
- Report a vulnerability: see [SECURITY.md](SECURITY.md).

## Advantages / tradeoffs

**Advantages:**
- No Redis dependency — one fewer service to run, if you're already on Postgres.
- Atomic batched multi-subject hits (see [Architecture](#architecture)) — closes a real consistency gap sequential-per-subject implementations have.
- Fail-open/fail-closed configurable per policy, not global.
- HMAC'd subjects — no raw PII persisted.
- A dedicated real-Postgres concurrency test exists specifically to prove the atomicity claim, not just unit tests against mocks (see [Verified](#verified-not-just-claimed) for its actual run status).

**Tradeoffs — read before adopting:**
- **Every hit is a database write.** This is fundamentally slower than an in-memory or Redis-backed limiter — you're trading raw throughput for not needing another service. At high QPS, this adds real load to your Postgres instance.
- **Not a sliding-window limiter.** Fixed windows can allow up to ~2x the configured limit across a window boundary (a burst right at the edge of one window, then another right at the start of the next). Fine for most abuse-prevention use cases; not fine if you need a hard, precise ceiling.
- **Single Postgres instance, no built-in sharding.** At very high write volume, this table becomes a hot spot. There's no partitioning story here yet (see [Roadmap](#roadmap--where-to-contribute)).
- If you already run Redis for anything else, a Redis-based limiter (`slowapi`, `fastapi-limiter`) will outperform this and is the more conventional choice — this library exists for the specific case where you don't.

## For agents / automated contributors

- `src/pg_rate_limiter/domain.py` has zero external coupling — safe to read first, defines every type used everywhere else.
- `backends.py` is the only file that talks to the database directly (dialect-aware SQL). `service.py` is the only file that owns the failure-mode contract (local fallback → fail-open → fail-closed) and is what applications actually call.
- `test/test_service.py` is the executable spec for `service.py` and `backends.py` — read it before changing either.
- `test/test_postgres_integration.py` is skipped unless `PG_RATE_LIMITER_TEST_DATABASE_URL` is set — don't assume it ran just because `pytest` exited 0.
- Before proposing a change: `pytest test/ --ignore=test/test_postgres_integration.py && mypy src && ruff check src test` — CI (`.github/workflows/ci.yml`) runs the full suite including the Postgres integration job on every push/PR.

## Testing

```bash
pip install -e ".[test]"
pytest test/ --ignore=test/test_postgres_integration.py   # sqlite + mocked backends, no external DB needed
```

To run the real-Postgres concurrency proof locally:

```bash
createdb pg_rate_limiter_test
PG_RATE_LIMITER_TEST_DATABASE_URL=postgresql+asyncpg://localhost/pg_rate_limiter_test pytest test/test_postgres_integration.py
```

CI runs both jobs on every push/PR — the Postgres job uses a GitHub Actions
`postgres:` service container, so no local Docker is required to get CI
coverage even if you can't run the integration test locally yourself.

## Verified, not just claimed

Before publishing, this was actually run — not just written and assumed to work:

- **The full sqlite/mocked test suite** (`pytest test/ --ignore=test/test_postgres_integration.py`, 19 tests) passes on a fresh install, in a clean venv, with the exact pinned dependency versions in `pyproject.toml`. `ruff check` and `mypy src` are both clean too.
- **The real-Postgres concurrency test** (`test_concurrent_hits_on_same_subject_produce_no_lost_updates`) was written specifically to reproduce the source app's own proven result (8 concurrent hits on one subject → `hit_count == 8`, no lost updates). It couldn't be run against a local Postgres instance before this repo's first push (the only local Postgres available had a superuser password this effort didn't have access to, and reading the sibling app's real `.env` to find one was correctly refused rather than worked around) — so it ran for the first time in CI on the first push instead: [run 32030240960](https://github.com/hirad121/pg-rate-limiter/actions/runs/32030240960), `postgres-integration` job, **passed**. It has since also been run locally against real Postgres (a dedicated scratch role, not the app's own credentials) and passed there too.
- **What wasn't independently re-verified**: sustained high-QPS load against a real deployment — the concurrency test proves correctness under concurrent access, not throughput under sustained production-scale traffic. If you're evaluating this for a high-QPS use case, benchmark it against your own workload before adopting.

## Gotchas

- **`bigint`, not `int4`, on the primary key — including the sequence, not just the column.** If you ever hand-roll your own migration instead of using `Base.metadata.create_all`, remember `ALTER SEQUENCE ... AS bigint` in addition to `ALTER COLUMN ... TYPE bigint` — the sequence has its own separate bound.
- **SQLite and Postgres use different `ON CONFLICT` syntax** (`constraint=` vs `index_elements=`) — `backends.py` branches on `db.get_bind().dialect.name`. If you add a third dialect, that branch needs a new case; there's no generic fallback.
- **`policy_name` is unconstrained** (plain `String`, no `CHECK`/enum). Deliberate — a new policy is just a new set of rows, no schema migration needed — but nothing at the schema level stops a future caller from interpolating untrusted data into a policy name. Every call site in this library uses static string literals; keep it that way in your own code too.
- **Local fallback state is per-process and never shared** — see [Security](#security)'s note on `allow_local_fallback`.

## Roadmap / where to contribute

Being upfront about what this repo doesn't have yet, ranked by how
self-contained the work is:

**Good first issues** (no design decisions needed, clear done-condition):
- A `probe_backend()`-based `/healthz` example wired into a minimal FastAPI app in `examples/`.
- A `mypy --strict` pass — currently just plain `mypy`, tightening it is mechanical.
- Expose `RATE_LIMIT_BUCKET_CLEANUP_BATCH_LIMIT` as a `cleanup.py` CLI flag instead of only an env var.

**Needs a design proposal first:**
- **Sliding-window option.** Would need a second algorithm (e.g. token bucket or a rolling log) alongside the current fixed-window one, selectable per policy — real design tradeoffs on storage cost vs. precision.
- **Pluggable Redis backend**, so a project can start on Postgres and migrate to Redis later without changing call sites — needs a backend interface `PostgresRateLimiter` and any future backend both implement.
- **Partitioning/sharding story for `rate_limit_buckets` at very high write volume** — no current plan, flagged as a known scaling ceiling in [Tradeoffs](#advantages--tradeoffs).

## License

MIT — see [LICENSE](LICENSE).
