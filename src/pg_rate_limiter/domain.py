from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class GuardRequestClass(str, Enum):
    PUBLIC_READ = "public_read"
    AUTHENTICATED_READ = "authenticated_read"
    AUTH_EXCHANGE = "auth_exchange"
    MUTATION = "mutation"
    # Global (not per-user/per-IP) capacity guards -- protect a shared
    # resource from being exhausted by many different accounts/IPs each
    # individually staying under their own limit.
    GLOBAL_GUARD = "global_guard"


class GuardFailureMode(str, Enum):
    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


class LimiterBackendStatus(str, Enum):
    SHARED = "shared"
    LOCAL = "local"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class RateLimitPolicy:
    name: str
    limit: int
    window_seconds: int
    request_class: GuardRequestClass = GuardRequestClass.AUTHENTICATED_READ
    failure_mode: GuardFailureMode = GuardFailureMode.FAIL_CLOSED


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    reset_at: int
    backend_status: LimiterBackendStatus
    degraded: bool = False
