from __future__ import annotations

import hashlib
import hmac
import ipaddress
import time
from datetime import datetime, timezone
from threading import Lock

from cachetools import TTLCache
from fastapi import Request
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from pg_rate_limiter.domain import GuardRequestClass, RateLimitPolicy
from pg_rate_limiter.model import RateLimitBucket

_local_rate_limit_cache = TTLCache(maxsize=4096, ttl=60 * 60)
_local_rate_limit_lock = Lock()


def get_client_ip(request: Request, trusted_proxy_networks: list) -> str:
    """trusted_proxy_networks: list of ipaddress network objects (e.g.
    [ipaddress.ip_network("10.0.0.0/8")]) whose direct connections are
    trusted to set cf-connecting-ip/x-forwarded-for. Pass an empty list
    if this app isn't behind a trusted reverse proxy -- the direct socket
    IP is used as-is in that case, which is the safe default.
    """
    direct_ip = request.client.host if request.client and request.client.host else "unknown"
    try:
        direct_addr = ipaddress.ip_address(direct_ip)
    except ValueError:
        return direct_ip

    if any(direct_addr in network for network in trusted_proxy_networks):
        forwarded = request.headers.get("cf-connecting-ip") or request.headers.get("x-forwarded-for")
        if forwarded:
            candidate = forwarded.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                return direct_ip
            return candidate

    return direct_ip


def bucket_key(policy: RateLimitPolicy, subject: str) -> tuple[str, int]:
    window = int(time.time() // policy.window_seconds)
    return f"ratelimit:{policy.name}:{subject}:{window}", window


def window_started_at(window: int, window_seconds: int) -> datetime:
    return datetime.fromtimestamp(window * window_seconds, tz=timezone.utc).replace(tzinfo=None)


def expires_at(window: int, window_seconds: int) -> datetime:
    return datetime.fromtimestamp((window + 1) * window_seconds, tz=timezone.utc).replace(tzinfo=None)


def subject_hmac(subject: str, secret: str) -> str:
    """secret must be a dedicated, explicitly-configured value -- see
    README's Security section for why this deliberately has no fallback
    to some other app-wide secret. Reusing a secret across two unrelated
    purposes means rotating one silently affects the other.
    """
    return hmac.new(secret.encode("utf-8"), subject.encode("utf-8"), hashlib.sha256).hexdigest()


class LocalRateLimiter:
    def hit(self, policy: RateLimitPolicy, subject: str) -> int:
        key, _window = bucket_key(policy, subject)
        with _local_rate_limit_lock:
            current_count = int(_local_rate_limit_cache.get(key, 0)) + 1
            _local_rate_limit_cache[key] = current_count
            return current_count


class PostgresRateLimiter:
    def __init__(self, subject_secret: str) -> None:
        if not subject_secret:
            raise ValueError("subject_secret must be a non-empty, dedicated secret")
        self._subject_secret = subject_secret

    def _build_statement(self, policy: RateLimitPolicy, subject: str, db: AsyncSession):
        _, window = bucket_key(policy, subject)
        now = datetime.utcnow()
        values = {
            "policy_name": policy.name,
            "subject_hmac": subject_hmac(subject, self._subject_secret),
            "window_started_at": window_started_at(window, policy.window_seconds),
            "expires_at": expires_at(window, policy.window_seconds),
            "hit_count": 1,
            "created_at": now,
            "updated_at": now,
        }

        bind_getter = getattr(db, "get_bind", None)
        bind = bind_getter() if callable(bind_getter) else getattr(db, "bind", None)
        dialect_name = bind.dialect.name if bind is not None else ""
        if dialect_name == "postgresql":
            return (
                pg_insert(RateLimitBucket)
                .values(**values)
                .on_conflict_do_update(
                    constraint="uq_rate_limit_buckets_policy_subject_window",
                    set_={
                        "hit_count": RateLimitBucket.hit_count + 1,
                        "updated_at": now,
                        "expires_at": values["expires_at"],
                    },
                )
                .returning(RateLimitBucket.hit_count)
            )
        if dialect_name == "sqlite":
            return (
                sqlite_insert(RateLimitBucket)
                .values(**values)
                .on_conflict_do_update(
                    index_elements=["policy_name", "subject_hmac", "window_started_at"],
                    set_={
                        "hit_count": RateLimitBucket.hit_count + 1,
                        "updated_at": now,
                        "expires_at": values["expires_at"],
                    },
                )
                .returning(RateLimitBucket.hit_count)
            )
        raise RuntimeError(f"Unsupported rate-limit database dialect: {dialect_name}")

    async def hit(self, policy: RateLimitPolicy, subject: str, db: AsyncSession) -> int:
        statement = self._build_statement(policy, subject, db)
        result = await db.execute(statement)
        await db.commit()
        return int(result.scalar_one())

    def _build_statement_many(self, policy: RateLimitPolicy, subjects: list[str], db: AsyncSession):
        # window/window_started_at/expires_at depend only on policy.window_seconds
        # and the current time -- never on subject -- so every row in this batch
        # shares the identical window. Safe to compute once from any subject.
        _, window = bucket_key(policy, subjects[0])
        now = datetime.utcnow()
        shared_window_started_at = window_started_at(window, policy.window_seconds)
        shared_expires_at = expires_at(window, policy.window_seconds)
        rows = [
            {
                "policy_name": policy.name,
                "subject_hmac": subject_hmac(subject, self._subject_secret),
                "window_started_at": shared_window_started_at,
                "expires_at": shared_expires_at,
                "hit_count": 1,
                "created_at": now,
                "updated_at": now,
            }
            for subject in subjects
        ]

        bind_getter = getattr(db, "get_bind", None)
        bind = bind_getter() if callable(bind_getter) else getattr(db, "bind", None)
        dialect_name = bind.dialect.name if bind is not None else ""
        if dialect_name == "postgresql":
            return (
                pg_insert(RateLimitBucket)
                .values(rows)
                .on_conflict_do_update(
                    constraint="uq_rate_limit_buckets_policy_subject_window",
                    set_={
                        "hit_count": RateLimitBucket.hit_count + 1,
                        "updated_at": now,
                        "expires_at": shared_expires_at,
                    },
                )
                .returning(RateLimitBucket.subject_hmac, RateLimitBucket.hit_count)
            )
        if dialect_name == "sqlite":
            return (
                sqlite_insert(RateLimitBucket)
                .values(rows)
                .on_conflict_do_update(
                    index_elements=["policy_name", "subject_hmac", "window_started_at"],
                    set_={
                        "hit_count": RateLimitBucket.hit_count + 1,
                        "updated_at": now,
                        "expires_at": shared_expires_at,
                    },
                )
                .returning(RateLimitBucket.subject_hmac, RateLimitBucket.hit_count)
            )
        raise RuntimeError(f"Unsupported rate-limit database dialect: {dialect_name}")

    async def hit_many(
        self, policy: RateLimitPolicy, subjects: list[str], db: AsyncSession
    ) -> dict[str, int]:
        """Upsert-and-increment multiple subjects under the same policy/window
        in a single round trip (one execute + one commit), instead of one
        hit() call per subject. Returns {subject: hit_count}.
        """
        if not subjects:
            return {}
        statement = self._build_statement_many(policy, subjects, db)
        result = await db.execute(statement)
        await db.commit()
        counts_by_hmac = {row.subject_hmac: int(row.hit_count) for row in result}
        return {subject: counts_by_hmac[subject_hmac(subject, self._subject_secret)] for subject in subjects}

    async def probe(self, db: AsyncSession) -> None:
        probe_policy = RateLimitPolicy(
            name="readiness_probe",
            limit=1,
            window_seconds=60,
            request_class=GuardRequestClass.PUBLIC_READ,
        )
        try:
            statement = self._build_statement(probe_policy, "system:readiness", db)
            await db.execute(statement)
        finally:
            rollback = getattr(db, "rollback", None)
            if callable(rollback):
                await rollback()
