from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"
    __table_args__ = (
        UniqueConstraint(
            "policy_name",
            "subject_hmac",
            "window_started_at",
            name="uq_rate_limit_buckets_policy_subject_window",
        ),
        Index("ix_rate_limit_buckets_expires_at", "expires_at"),
    )

    # bigint, not int4 -- a rate limiter can easily be the highest
    # per-request write volume table in an app's schema (a single
    # enforce_user_limit-style call writes 2 rows: one per-IP, one
    # per-user, on every rate-limited endpoint). An int4 sequence is a
    # real long-run exhaustion risk under sustained traffic -- this
    # exact issue was found via a production database audit after the
    # table had already grown past the point where widening it was
    # cheap. Start on bigint here so nobody has to repeat that fix.
    #
    # Integer().with_variant(BigInteger(), "postgresql"), not a bare
    # BigInteger(): SQLite's implicit rowid-based autoincrement only
    # triggers for a plain Integer PK, not BigInteger -- this lets tests
    # run against SQLite while Postgres still gets the bigint column and
    # a bigint-bound sequence (ALTER SEQUENCE ... AS bigint, see the
    # migration gotcha in README's Gotchas section).
    id = Column(Integer().with_variant(BigInteger(), "postgresql"), primary_key=True)
    policy_name = Column(String, nullable=False)
    subject_hmac = Column(String, nullable=False)
    window_started_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    hit_count = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
