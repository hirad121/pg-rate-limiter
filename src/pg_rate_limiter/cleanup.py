"""Standalone cleanup script -- deletes expired rate_limit_buckets rows.
Intended to run on a schedule (cron, GitHub Actions, etc.) against your
production database. Doesn't import the rest of this package on purpose:
runnable with just this file + sqlalchemy + an async DB driver, so it can
be copied into a deploy image without pulling in FastAPI.

Usage:
    DATABASE_URL=postgresql+asyncpg://... python -m pg_rate_limiter.cleanup
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import BigInteger, Column, DateTime, Integer, MetaData, String, Table, delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

metadata = MetaData()
rate_limit_buckets = Table(
    "rate_limit_buckets",
    metadata,
    Column("id", Integer().with_variant(BigInteger(), "postgresql"), primary_key=True),
    Column("policy_name", String, nullable=False),
    Column("subject_hmac", String, nullable=False),
    Column("window_started_at", DateTime, nullable=False),
    Column("expires_at", DateTime, nullable=False),
    Column("hit_count", Integer, nullable=False),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
)


def _async_url(url: str) -> str:
    if url.startswith("sqlite+aiosqlite://"):
        return url
    if url.startswith("sqlite:///"):
        return url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    if not url.startswith(("postgresql://", "postgresql+asyncpg://")):
        return url

    parts = urlsplit(url)
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    normalized_query_pairs = []
    for key, value in query_pairs:
        if key == "sslmode":
            normalized_query_pairs.append(("ssl", value))
            continue
        if key == "channel_binding":
            continue
        normalized_query_pairs.append((key, value))

    return urlunsplit(
        (
            "postgresql+asyncpg",
            parts.netloc,
            parts.path,
            urlencode(normalized_query_pairs),
            parts.fragment,
        )
    )


async def _run_cleanup() -> int:
    database_url = (os.getenv("DATABASE_URL") or "").strip()
    if not database_url:
        raise RuntimeError("DATABASE_URL must be set.")

    batch_limit = int((os.getenv("RATE_LIMIT_BUCKET_CLEANUP_BATCH_LIMIT") or "5000").strip())
    engine = create_async_engine(_async_url(database_url), future=True, poolclass=NullPool)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with session_factory() as session:
            result = await session.execute(
                select(rate_limit_buckets.c.id)
                .where(rate_limit_buckets.c.expires_at < datetime.utcnow())
                .order_by(rate_limit_buckets.c.expires_at.asc())
                .limit(batch_limit)
            )
            bucket_ids = list(result.scalars())
            if bucket_ids:
                await session.execute(delete(rate_limit_buckets).where(rate_limit_buckets.c.id.in_(bucket_ids)))
                await session.commit()
            deleted = len(bucket_ids)
        return deleted
    finally:
        await engine.dispose()


def main() -> None:
    deleted = asyncio.run(_run_cleanup())
    print(f"Deleted {deleted} expired rate_limit_buckets rows")


if __name__ == "__main__":
    main()
