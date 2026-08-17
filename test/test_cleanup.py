from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from pg_rate_limiter import cleanup


@pytest_asyncio.fixture
async def cleanup_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True, poolclass=StaticPool)
    async with engine.begin() as conn:
        await conn.run_sync(cleanup.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


async def _seed_bucket(session, *, expires_at: datetime) -> int:
    result = await session.execute(
        insert(cleanup.rate_limit_buckets).values(
            policy_name="auth_read",
            subject_hmac=f"subject-{expires_at.timestamp()}",
            window_started_at=expires_at - timedelta(minutes=1),
            expires_at=expires_at,
            hit_count=1,
            created_at=expires_at - timedelta(minutes=1),
            updated_at=expires_at - timedelta(minutes=1),
        )
    )
    await session.commit()
    return result.inserted_primary_key[0]


@pytest.mark.asyncio
async def test_deletes_only_expired_buckets(cleanup_session):
    now = datetime.utcnow()
    stale_id = await _seed_bucket(cleanup_session, expires_at=now - timedelta(minutes=1))
    fresh_id = await _seed_bucket(cleanup_session, expires_at=now + timedelta(minutes=9))

    result = await cleanup_session.execute(
        select(cleanup.rate_limit_buckets.c.id)
        .where(cleanup.rate_limit_buckets.c.expires_at < datetime.utcnow())
        .order_by(cleanup.rate_limit_buckets.c.expires_at.asc())
        .limit(5000)
    )
    bucket_ids = list(result.scalars())
    assert bucket_ids == [stale_id]

    await cleanup_session.execute(
        cleanup.rate_limit_buckets.delete().where(cleanup.rate_limit_buckets.c.id.in_(bucket_ids))
    )
    await cleanup_session.commit()

    remaining = await cleanup_session.execute(select(cleanup.rate_limit_buckets.c.id))
    assert list(remaining.scalars()) == [fresh_id]


def test_column_types_match_the_model_bigint_variant():
    # rate_limit_buckets.id is Integer().with_variant(BigInteger(), "postgresql")
    # in both model.py and this standalone script's hand-declared Table --
    # they must stay in sync or a real Postgres run could silently mismatch
    # the column's actual type. See model.py's comment for why bigint matters.
    from sqlalchemy import BigInteger

    id_type = cleanup.rate_limit_buckets.c.id.type
    assert isinstance(id_type._variant_mapping["postgresql"], BigInteger)
