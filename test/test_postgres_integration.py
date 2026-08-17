"""Runs only against a real Postgres instance -- skipped automatically if
PG_RATE_LIMITER_TEST_DATABASE_URL isn't set (see README's Testing section
for how to run this locally). This is the one test that actually proves
the atomicity claim; everything else in test_service.py runs against
SQLite or mocks and cannot exercise Postgres's real row-lock behavior
under concurrency.
"""

import asyncio
import os

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from pg_rate_limiter.domain import RateLimitPolicy
from pg_rate_limiter.model import Base
from pg_rate_limiter.service import RateLimiter

DATABASE_URL = os.getenv("PG_RATE_LIMITER_TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="set PG_RATE_LIMITER_TEST_DATABASE_URL to a real Postgres URL to run this test",
)


@pytest.mark.asyncio
async def test_concurrent_hits_on_same_subject_produce_no_lost_updates():
    """8 genuinely concurrent hit() calls for the same
    (policy_name, subject_hmac, window) triple must land at exactly
    hit_count == 8 -- no lost updates. This is the real-world case the
    ON CONFLICT ... DO UPDATE ... RETURNING upsert exists to guarantee:
    many requests for the same IP/user arriving at once must all be
    counted, not silently overwrite each other's increment.
    """
    engine = create_async_engine(DATABASE_URL, future=True)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

        limiter = RateLimiter("integration-test-secret")
        policy = RateLimitPolicy(name="concurrency_probe", limit=1000, window_seconds=3600)

        async def one_hit():
            async with session_factory() as session:
                return await limiter._postgres_rate_limiter.hit(policy, "ip:203.0.113.10", session)

        results = await asyncio.gather(*(one_hit() for _ in range(8)))

        # Every concurrent call must see a distinct, gapless count -- proves
        # no two calls read-then-wrote the same stale value.
        assert sorted(results) == list(range(1, 9))

        async with session_factory() as session:
            final = await limiter._postgres_rate_limiter.hit(policy, "ip:203.0.113.10", session)
        assert final == 9
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()
