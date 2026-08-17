from datetime import datetime, timedelta

import pytest
from fastapi import Response
from sqlalchemy import select

from pg_rate_limiter.backends import subject_hmac
from pg_rate_limiter.domain import (
    GuardFailureMode,
    GuardRequestClass,
    LimiterBackendStatus,
    RateLimitDecision,
    RateLimitPolicy,
)
from pg_rate_limiter.model import RateLimitBucket
from pg_rate_limiter.service import RateLimiter

SECRET = "test-secret-do-not-use-in-prod"


@pytest.mark.asyncio
async def test_hit_returns_count_from_database_backend(monkeypatch):
    limiter = RateLimiter(SECRET)

    async def fake_hit(policy, subject, db):
        assert policy.name == "auth_read"
        assert subject == "ip:203.0.113.10"
        assert db == "db-session"
        return 2

    monkeypatch.setattr(limiter._postgres_rate_limiter, "hit", fake_hit)

    result = await limiter.hit(
        RateLimitPolicy(name="auth_read", limit=5, window_seconds=60),
        "ip:203.0.113.10",
        "db-session",
    )

    assert result.allowed is True
    assert result.remaining == 3


@pytest.mark.asyncio
async def test_hit_fails_closed_when_backend_unavailable_and_no_local_fallback():
    limiter = RateLimiter(SECRET, allow_local_fallback=False)

    async def fake_hit(policy, subject, db):
        raise RuntimeError("db unavailable")

    limiter._postgres_rate_limiter.hit = fake_hit  # type: ignore[method-assign]

    with pytest.raises(Exception) as exc_info:
        await limiter.hit(
            RateLimitPolicy(name="auth_read", limit=5, window_seconds=60),
            "ip:203.0.113.10",
            object(),
        )

    assert getattr(exc_info.value, "status_code", None) == 503
    assert getattr(exc_info.value, "detail", None) == {
        "code": "rate_limit_backend_unavailable",
        "message": "Rate limiting unavailable.",
    }


@pytest.mark.asyncio
async def test_hit_falls_back_locally_when_allowed():
    limiter = RateLimiter(SECRET, allow_local_fallback=True)

    async def fake_hit(policy, subject, db):
        raise RuntimeError("db unavailable")

    limiter._postgres_rate_limiter.hit = fake_hit  # type: ignore[method-assign]

    result = await limiter.hit(
        RateLimitPolicy(name="auth_read", limit=5, window_seconds=60),
        "ip:203.0.113.10",
        object(),
    )

    assert result.backend_status == LimiterBackendStatus.LOCAL
    assert result.degraded is True


@pytest.mark.asyncio
async def test_hit_fails_open_for_public_policy_when_backend_unavailable():
    limiter = RateLimiter(SECRET, allow_local_fallback=False)

    class DummySession:
        def __init__(self):
            self.rollback_calls = 0

        async def rollback(self):
            self.rollback_calls += 1

    async def fake_hit(policy, subject, db):
        raise RuntimeError("db unavailable")

    limiter._postgres_rate_limiter.hit = fake_hit  # type: ignore[method-assign]
    db = DummySession()

    result = await limiter.hit(
        RateLimitPolicy(
            name="public_read",
            limit=5,
            window_seconds=60,
            request_class=GuardRequestClass.PUBLIC_READ,
            failure_mode=GuardFailureMode.FAIL_OPEN,
        ),
        "ip:203.0.113.10",
        db,
    )

    assert result.allowed is True
    assert result.backend_status == LimiterBackendStatus.UNAVAILABLE
    assert result.degraded is True
    assert db.rollback_calls == 1


@pytest.mark.asyncio
async def test_hit_rolls_back_before_fail_closed_response():
    limiter = RateLimiter(SECRET, allow_local_fallback=False)

    class DummySession:
        def __init__(self):
            self.rollback_calls = 0

        async def rollback(self):
            self.rollback_calls += 1

    async def fake_hit(policy, subject, db):
        raise RuntimeError("db unavailable")

    limiter._postgres_rate_limiter.hit = fake_hit  # type: ignore[method-assign]
    db = DummySession()

    with pytest.raises(Exception) as exc_info:
        await limiter.hit(
            RateLimitPolicy(name="auth_read", limit=5, window_seconds=60),
            "ip:203.0.113.10",
            db,
        )

    assert getattr(exc_info.value, "status_code", None) == 503
    assert db.rollback_calls == 1


@pytest.mark.asyncio
async def test_enforce_subject_limits_deduplicates_subjects_and_applies_strictest_headers():
    limiter = RateLimiter(SECRET)
    calls = []

    async def fake_hit_many(policy, subjects, db):
        calls.append(list(subjects))
        return {
            subject: RateLimitDecision(
                allowed=True,
                remaining=4 if subject == "phone:9120000000" else 2,
                reset_at=100 if subject == "phone:9120000000" else 80,
                backend_status=LimiterBackendStatus.SHARED,
            )
            for subject in subjects
        }

    limiter.hit_many = fake_hit_many  # type: ignore[method-assign]
    response = Response()
    policy = RateLimitPolicy(name="internal_otp_finalize", limit=5, window_seconds=600)

    result = await limiter.enforce_subject_limits(
        response,
        policy,
        ["phone:9120000000", "phone:9120000000", "challenge:challenge-1"],
        "db-session",
    )

    # Exactly one batched call, not one per subject -- deduped subject list, in order.
    assert calls == [["phone:9120000000", "challenge:challenge-1"]]
    assert result.allowed is True
    assert result.remaining == 2
    assert result.reset_at == 80
    assert response.headers["X-RateLimit-Limit"] == "5"
    assert response.headers["X-RateLimit-Remaining"] == "2"
    assert response.headers["X-RateLimit-Reset"] == "80"


@pytest.mark.asyncio
async def test_enforce_subject_limits_denies_when_any_subject_is_blocked():
    limiter = RateLimiter(SECRET)
    calls = []

    async def fake_hit_many(policy, subjects, db):
        calls.append(list(subjects))
        return {
            subject: RateLimitDecision(
                allowed=subject != "challenge:blocked",
                remaining=0 if subject == "challenge:blocked" else 4,
                reset_at=100,
                backend_status=LimiterBackendStatus.SHARED,
            )
            for subject in subjects
        }

    limiter.hit_many = fake_hit_many  # type: ignore[method-assign]
    response = Response()
    policy = RateLimitPolicy(name="internal_otp_finalize", limit=5, window_seconds=600)

    with pytest.raises(Exception) as exc_info:
        await limiter.enforce_subject_limits(
            response,
            policy,
            ["phone:9120000000", "challenge:blocked"],
            "db-session",
        )

    assert calls == [["phone:9120000000", "challenge:blocked"]]
    assert getattr(exc_info.value, "status_code", None) == 429
    assert response.headers["X-RateLimit-Remaining"] == "0"


@pytest.mark.asyncio
async def test_hit_many_returns_counts_from_database_backend():
    limiter = RateLimiter(SECRET)

    async def fake_hit_many(policy, subjects, db):
        assert policy.name == "auth_read"
        assert subjects == ["ip:203.0.113.10", "user:user-1"]
        assert db == "db-session"
        return {"ip:203.0.113.10": 2, "user:user-1": 1}

    limiter._postgres_rate_limiter.hit_many = fake_hit_many  # type: ignore[method-assign]

    result = await limiter.hit_many(
        RateLimitPolicy(name="auth_read", limit=5, window_seconds=60),
        ["ip:203.0.113.10", "user:user-1"],
        "db-session",
    )

    assert result["ip:203.0.113.10"].allowed is True
    assert result["ip:203.0.113.10"].remaining == 3
    assert result["user:user-1"].remaining == 4


@pytest.mark.asyncio
async def test_hit_many_falls_back_locally_per_subject_when_allowed():
    limiter = RateLimiter(SECRET, allow_local_fallback=True)

    async def fake_hit_many(policy, subjects, db):
        raise RuntimeError("db unavailable")

    limiter._postgres_rate_limiter.hit_many = fake_hit_many  # type: ignore[method-assign]

    result = await limiter.hit_many(
        RateLimitPolicy(name="auth_read", limit=5, window_seconds=60),
        ["ip:203.0.113.10", "user:user-1"],
        object(),
    )

    assert result["ip:203.0.113.10"].backend_status == LimiterBackendStatus.LOCAL
    assert result["ip:203.0.113.10"].degraded is True
    assert result["user:user-1"].backend_status == LimiterBackendStatus.LOCAL
    assert result["user:user-1"].degraded is True


@pytest.mark.asyncio
async def test_enforce_user_limit_uses_a_single_round_trip(monkeypatch):
    import pg_rate_limiter.service as service_module

    monkeypatch.setattr(service_module, "get_client_ip", lambda request, trusted: "203.0.113.10")

    limiter = RateLimiter(SECRET, allow_local_fallback=False)

    class DummyDB:
        def __init__(self):
            self.execute_calls = 0
            self.commit_calls = 0

        def get_bind(self):
            return type("Bind", (), {"dialect": type("Dialect", (), {"name": "sqlite"})()})()

        async def execute(self, stmt):
            self.execute_calls += 1

            class Result:
                def __iter__(self_inner):
                    class Row:
                        def __init__(self_row, subject_hmac_value, hit_count):
                            self_row.subject_hmac = subject_hmac_value
                            self_row.hit_count = hit_count

                    return iter(
                        [
                            Row(subject_hmac("ip:203.0.113.10", SECRET), 1),
                            Row(subject_hmac("user:user-1", SECRET), 2),
                        ]
                    )

            return Result()

        async def commit(self):
            self.commit_calls += 1

    class DummyRequest:
        client = None
        headers = {}

    db = DummyDB()
    response = Response()
    policy = RateLimitPolicy(name="auth_read", limit=5, window_seconds=60)

    result = await limiter.enforce_user_limit(DummyRequest(), response, policy, "user-1", db)

    # One combined upsert covering both the IP and user subjects, instead of
    # one execute+commit pair per subject.
    assert db.execute_calls == 1
    assert db.commit_calls == 1
    assert result.allowed is True
    assert result.remaining == 3  # min(5-1, 5-2)
    assert response.headers["X-RateLimit-Remaining"] == "3"


@pytest.mark.asyncio
async def test_db_hit_uses_sqlite_upsert(sqlite_session):
    limiter = RateLimiter(SECRET)
    policy = RateLimitPolicy(name="auth_read", limit=5, window_seconds=60)
    first = await limiter._postgres_rate_limiter.hit(policy, "ip:203.0.113.10", sqlite_session)
    second = await limiter._postgres_rate_limiter.hit(policy, "ip:203.0.113.10", sqlite_session)

    assert first == 1
    assert second == 2


@pytest.mark.asyncio
async def test_db_hit_many_uses_sqlite_upsert(sqlite_session):
    limiter = RateLimiter(SECRET)
    policy = RateLimitPolicy(name="auth_read", limit=5, window_seconds=60)
    first = await limiter._postgres_rate_limiter.hit_many(
        policy, ["ip:203.0.113.10", "user:user-1"], sqlite_session
    )
    second = await limiter._postgres_rate_limiter.hit_many(
        policy, ["ip:203.0.113.10", "user:user-1"], sqlite_session
    )

    assert first == {"ip:203.0.113.10": 1, "user:user-1": 1}
    assert second == {"ip:203.0.113.10": 2, "user:user-1": 2}

    rows = (await sqlite_session.execute(select(RateLimitBucket))).scalars().all()
    # One row per distinct subject, not a shared/merged row.
    assert len(rows) == 2


@pytest.mark.asyncio
async def test_delete_expired_buckets_removes_only_expired_rows(sqlite_session):
    limiter = RateLimiter(SECRET)
    now = datetime.utcnow()
    sqlite_session.add_all(
        [
            RateLimitBucket(
                policy_name="auth_read",
                subject_hmac="expired",
                window_started_at=now - timedelta(minutes=2),
                expires_at=now - timedelta(minutes=1),
                hit_count=2,
            ),
            RateLimitBucket(
                policy_name="auth_read",
                subject_hmac="active",
                window_started_at=now,
                expires_at=now + timedelta(minutes=1),
                hit_count=1,
            ),
        ]
    )
    await sqlite_session.commit()

    deleted = await limiter.delete_expired_buckets(sqlite_session, limit=100)

    remaining = await sqlite_session.scalar(select(RateLimitBucket).where(RateLimitBucket.subject_hmac == "active"))
    expired = await sqlite_session.scalar(select(RateLimitBucket).where(RateLimitBucket.subject_hmac == "expired"))

    assert deleted == 1
    assert remaining is not None
    assert expired is None


def test_get_client_ip_uses_socket_ip_when_proxy_is_untrusted():
    import ipaddress

    from starlette.requests import Request

    from pg_rate_limiter.backends import get_client_ip

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-forwarded-for", b"203.0.113.10")],
        "client": ("198.51.100.7", 50000),
    }
    request = Request(scope)
    trusted = [ipaddress.ip_network("127.0.0.1/32")]

    assert get_client_ip(request, trusted) == "198.51.100.7"


def test_get_client_ip_honors_trusted_proxy_header():
    import ipaddress

    from starlette.requests import Request

    from pg_rate_limiter.backends import get_client_ip

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"cf-connecting-ip", b"203.0.113.10")],
        "client": ("127.0.0.1", 50000),
    }
    request = Request(scope)
    trusted = [ipaddress.ip_network("127.0.0.1/32")]

    assert get_client_ip(request, trusted) == "203.0.113.10"


def test_get_client_ip_ignores_invalid_forwarded_values():
    import ipaddress

    from starlette.requests import Request

    from pg_rate_limiter.backends import get_client_ip

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-forwarded-for", b"not-an-ip")],
        "client": ("127.0.0.1", 50000),
    }
    request = Request(scope)
    trusted = [ipaddress.ip_network("127.0.0.1/32")]

    assert get_client_ip(request, trusted) == "127.0.0.1"


def test_subject_secret_is_required():
    with pytest.raises(ValueError):
        RateLimiter("")
