from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from datetime import datetime

from fastapi import HTTPException, Request, Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from pg_rate_limiter.backends import (
    LocalRateLimiter,
    PostgresRateLimiter,
    bucket_key,
    get_client_ip,
)
from pg_rate_limiter.domain import (
    GuardFailureMode,
    LimiterBackendStatus,
    RateLimitDecision,
    RateLimitPolicy,
)
from pg_rate_limiter.model import RateLimitBucket

logger = logging.getLogger(__name__)


class RateLimiter:
    """Owns the shared (Postgres) and local-fallback limiter state for one
    app. Create one instance at app startup and reuse it -- it holds the
    local-fallback cache/lock, so a fresh instance per request would defeat
    the fallback path.

    Args:
        subject_secret: dedicated HMAC secret for hashing rate-limit
            subjects (IPs/user ids) before they're persisted. Required,
            no fallback -- generate a fresh random value for this, don't
            reuse a secret from anywhere else in your app (see README's
            Security section for why).
        allow_local_fallback: if True, a Postgres failure falls back to an
            in-process, per-instance counter instead of failing per
            policy.failure_mode. Intended for dev/test only -- in a
            multi-instance deployment the local fallback is NOT shared
            across instances, so it under-counts real traffic. Defaults to
            False; set True explicitly for local dev.
        on_backend_failure: optional callback invoked with a short string
            tag whenever the shared backend is unavailable (e.g. to wire
            into your own metrics/alerting). No-op by default.
    """

    def __init__(
        self,
        subject_secret: str,
        *,
        allow_local_fallback: bool = False,
        on_backend_failure: Callable[[str], None] | None = None,
    ) -> None:
        self._postgres_rate_limiter = PostgresRateLimiter(subject_secret)
        self._allow_local_fallback = allow_local_fallback
        self._on_backend_failure = on_backend_failure or (lambda _tag: None)

    async def _rollback_session_safely(self, db: AsyncSession) -> None:
        rollback = getattr(db, "rollback", None)
        if not callable(rollback):
            return
        try:
            await rollback()
        except Exception:
            logger.warning("rate_limit_rollback_failed", exc_info=True)

    def _build_rate_limit_unavailable(self) -> HTTPException:
        return HTTPException(
            status_code=503,
            detail={
                "code": "rate_limit_backend_unavailable",
                "message": "Rate limiting unavailable.",
            },
        )

    def _decision_from_count(
        self,
        *,
        policy: RateLimitPolicy,
        count: int,
        reset_at: int,
        backend_status: LimiterBackendStatus,
        degraded: bool = False,
    ) -> RateLimitDecision:
        remaining = max(0, policy.limit - count)
        return RateLimitDecision(
            allowed=count <= policy.limit,
            remaining=remaining,
            reset_at=reset_at,
            backend_status=backend_status,
            degraded=degraded,
        )

    def _degraded_fail_open_decision(self, policy: RateLimitPolicy, reset_at: int) -> RateLimitDecision:
        return RateLimitDecision(
            allowed=True,
            remaining=policy.limit,
            reset_at=reset_at,
            backend_status=LimiterBackendStatus.UNAVAILABLE,
            degraded=True,
        )

    def _local_hit_rate_limit(self, policy: RateLimitPolicy, subject: str) -> int:
        return LocalRateLimiter().hit(policy, subject)

    async def hit(self, policy: RateLimitPolicy, subject: str, db: AsyncSession) -> RateLimitDecision:
        _, window = bucket_key(policy, subject)
        reset_at = (window + 1) * policy.window_seconds
        try:
            current_count = await self._postgres_rate_limiter.hit(policy, subject, db)
            decision = self._decision_from_count(
                policy=policy,
                count=current_count,
                reset_at=reset_at,
                backend_status=LimiterBackendStatus.SHARED,
            )
        except Exception:
            await self._rollback_session_safely(db)
            if self._allow_local_fallback:
                current_count = self._local_hit_rate_limit(policy, subject)
                decision = self._decision_from_count(
                    policy=policy,
                    count=current_count,
                    reset_at=reset_at,
                    backend_status=LimiterBackendStatus.LOCAL,
                    degraded=True,
                )
            elif policy.failure_mode == GuardFailureMode.FAIL_OPEN:
                decision = self._degraded_fail_open_decision(policy, reset_at)
            else:
                logger.exception("rate_limit_backend_unavailable policy=%s", policy.name)
                self._on_backend_failure(f"rate_limit_backend:{policy.name}")
                raise self._build_rate_limit_unavailable()
        return decision

    async def hit_many(
        self, policy: RateLimitPolicy, subjects: list[str], db: AsyncSession
    ) -> dict[str, RateLimitDecision]:
        """Batched sibling of hit(): increments every subject under the same
        policy/window in a single DB round trip instead of one per subject.
        Same failure contract as hit() -- applied identically across every
        subject on a single shared failure, since they share one underlying
        DB call.
        """
        _, window = bucket_key(policy, subjects[0])
        reset_at = (window + 1) * policy.window_seconds

        decisions: dict[str, RateLimitDecision] = {}
        try:
            counts = await self._postgres_rate_limiter.hit_many(policy, subjects, db)
            for subject in subjects:
                decisions[subject] = self._decision_from_count(
                    policy=policy,
                    count=counts[subject],
                    reset_at=reset_at,
                    backend_status=LimiterBackendStatus.SHARED,
                )
        except Exception:
            await self._rollback_session_safely(db)
            if self._allow_local_fallback:
                for subject in subjects:
                    current_count = self._local_hit_rate_limit(policy, subject)
                    decisions[subject] = self._decision_from_count(
                        policy=policy,
                        count=current_count,
                        reset_at=reset_at,
                        backend_status=LimiterBackendStatus.LOCAL,
                        degraded=True,
                    )
            elif policy.failure_mode == GuardFailureMode.FAIL_OPEN:
                for subject in subjects:
                    decisions[subject] = self._degraded_fail_open_decision(policy, reset_at)
            else:
                logger.exception("rate_limit_backend_unavailable policy=%s", policy.name)
                self._on_backend_failure(f"rate_limit_backend:{policy.name}")
                raise self._build_rate_limit_unavailable()

        return decisions

    async def probe_backend(self, db: AsyncSession) -> str:
        try:
            await self._postgres_rate_limiter.probe(db)
            return LimiterBackendStatus.SHARED.value
        except Exception:
            self._on_backend_failure("rate_limit_backend:readiness")
            raise self._build_rate_limit_unavailable()

    def _apply_headers(self, response: Response, policy: RateLimitPolicy, result: RateLimitDecision) -> None:
        response.headers["X-RateLimit-Limit"] = str(policy.limit)
        response.headers["X-RateLimit-Remaining"] = str(result.remaining)
        response.headers["X-RateLimit-Reset"] = str(result.reset_at)
        if result.degraded:
            response.headers["X-Guard-Mode"] = "degraded"
            response.headers["X-Guard-Backend"] = result.backend_status.value

    async def enforce_ip_limit(
        self,
        request: Request,
        response: Response,
        policy: RateLimitPolicy,
        db: AsyncSession,
        *,
        trusted_proxy_networks: list | None = None,
    ) -> RateLimitDecision:
        result = await self.hit(policy, f"ip:{get_client_ip(request, trusted_proxy_networks or [])}", db)
        self._apply_headers(response, policy, result)
        if not result.allowed:
            self._on_backend_failure(f"rate_limit:{policy.name}")
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        return result

    async def enforce_user_limit(
        self,
        request: Request,
        response: Response,
        policy: RateLimitPolicy,
        user_id: str,
        db: AsyncSession,
        *,
        trusted_proxy_networks: list | None = None,
    ) -> RateLimitDecision:
        ip_subject = f"ip:{get_client_ip(request, trusted_proxy_networks or [])}"
        user_subject = f"user:{user_id}"
        decisions = await self.hit_many(policy, [ip_subject, user_subject], db)
        ip_result = decisions[ip_subject]
        user_result = decisions[user_subject]
        remaining = min(ip_result.remaining, user_result.remaining)
        reset_at = min(ip_result.reset_at, user_result.reset_at)
        degraded = ip_result.degraded or user_result.degraded
        backend_status = (
            user_result.backend_status
            if user_result.backend_status != LimiterBackendStatus.SHARED
            else ip_result.backend_status
        )
        result = RateLimitDecision(
            allowed=ip_result.allowed and user_result.allowed,
            remaining=remaining,
            reset_at=reset_at,
            backend_status=backend_status,
            degraded=degraded,
        )
        self._apply_headers(response, policy, result)
        if not result.allowed:
            self._on_backend_failure(f"rate_limit:{policy.name}")
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        return result

    async def enforce_subject_limits(
        self,
        response: Response,
        policy: RateLimitPolicy,
        subjects: Iterable[str],
        db: AsyncSession,
    ) -> RateLimitDecision:
        """Batched via hit_many: bucket_key()'s window depends only on
        policy.window_seconds and current time, never on subject, so every
        subject passed here already shares an identical window -- safe to
        bundle into a single INSERT ... ON CONFLICT DO UPDATE covering all
        of them at once. Also closes a consistency gap a naive per-subject
        loop would have: a DB failure partway through could otherwise leave
        earlier subjects incremented and later ones not.
        """
        seen: set[str] = set()
        deduped_subjects: list[str] = []
        for subject in subjects:
            if not subject or subject in seen:
                continue
            seen.add(subject)
            deduped_subjects.append(subject)

        if not deduped_subjects:
            result = RateLimitDecision(
                allowed=True,
                remaining=policy.limit,
                reset_at=0,
                backend_status=LimiterBackendStatus.SHARED,
            )
        else:
            decisions_by_subject = await self.hit_many(policy, deduped_subjects, db)
            decisions = [decisions_by_subject[subject] for subject in deduped_subjects]
            backend_status = decisions[0].backend_status
            for decision in decisions:
                if decision.backend_status != LimiterBackendStatus.SHARED:
                    backend_status = decision.backend_status
                    break
            result = RateLimitDecision(
                allowed=all(decision.allowed for decision in decisions),
                remaining=min(decision.remaining for decision in decisions),
                reset_at=min(decision.reset_at for decision in decisions),
                backend_status=backend_status,
                degraded=any(decision.degraded for decision in decisions),
            )

        self._apply_headers(response, policy, result)
        if not result.allowed:
            self._on_backend_failure(f"rate_limit:{policy.name}")
            raise HTTPException(status_code=429, detail="Rate limit exceeded.")
        return result

    async def delete_expired_buckets(self, db: AsyncSession, *, limit: int = 5000) -> int:
        result = await db.execute(
            select(RateLimitBucket.id)
            .where(RateLimitBucket.expires_at < datetime.utcnow())
            .order_by(RateLimitBucket.expires_at.asc())
            .limit(limit)
        )
        bucket_ids = list(result.scalars())
        if not bucket_ids:
            return 0

        await db.execute(delete(RateLimitBucket).where(RateLimitBucket.id.in_(bucket_ids)))
        await db.commit()
        return len(bucket_ids)
