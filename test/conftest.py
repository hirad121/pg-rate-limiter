import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from pg_rate_limiter.model import Base


@pytest_asyncio.fixture
async def sqlite_session():
    """In-memory SQLite session with the rate_limit_buckets table created.
    StaticPool keeps the same in-memory DB alive across connections within
    a single test (":memory:" SQLite is otherwise per-connection).
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True, poolclass=StaticPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()
