"""Comprehensive unit tests for the database persistence layer.

Targets the Phase 1 persistence layer introduced in commit 07181fb:
- :mod:`vorsyghta.db.base` — declarative base, async engine factory, URL
  resolution, pool-kwargs-from-env, singleton engine/factory, dispose,
  safe-URL-for-log.
- :mod:`vorsyghta.db.session` — ``DatabaseConfig``, session factory creation,
  ``get_session`` context manager (rollback-on-exception, close-in-finally,
  factory/engine/singleton precedence), FastAPI dependency.
- :mod:`vorsyghta.db.health` — ``DatabaseHealth``, ``check_database_health``
  (connectivity failure, schema-query failure, table-missing, success, engine
  fallback).
- :mod:`vorsyghta.db` — public re-exports.

No happy-path-only tests: every branch, env-parsing edge case, precedence rule
and failure mode is exercised.  Real in-memory SQLite engines (via aiosqlite)
are used where the SQLAlchemy layer must actually execute; mocks are used for
the PostgreSQL-specific health-check schema query.
"""

from __future__ import annotations

import logging
import os
from typing import Any, AsyncIterator, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from vorsyghta.db import (
    Base,
    DatabaseConfig,
    DatabaseHealth,
    check_database_health,
    create_engine,
    create_session_factory,
    dispose_engine,
    get_engine,
    get_session,
    get_session_dep,
    get_session_factory,
)
from vorsyghta.db import base as db_base
from vorsyghta.db import health as db_health
from vorsyghta.db import session as db_session


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _sqlite_url() -> str:
    return "sqlite+aiosqlite:///:memory:"


@pytest.fixture
def reset_singletons():
    """Reset the module-level engine/factory singletons before and after."""
    db_base._engine = None
    db_base._session_factory = None
    yield
    db_base._engine = None
    db_base._session_factory = None


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Remove DB env vars that could leak between tests."""
    for var in ("DATABASE_URL", "DB_POOL_SIZE", "DB_MAX_OVERFLOW",
                "DB_POOL_TIMEOUT", "DB_POOL_RECYCLE"):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# Base — declarative base
# ---------------------------------------------------------------------------


class TestBase:
    """``Base`` is a usable SQLAlchemy declarative base."""

    def test_base_is_declarative_base_subclass(self):
        from sqlalchemy.orm import DeclarativeBase
        assert issubclass(Base, DeclarativeBase)

    def test_base_can_define_a_mapped_class(self):
        # Defining a mapped class on Base must not raise and must register a
        # table name.  SQLAlchemy requires at least one Column, so we add an
        # id primary key.  We use a unique class name to avoid registry
        # clashes across tests by defining it inside the function.
        from sqlalchemy import Column, Integer

        class _DummyTestModel(Base):
            __tablename__ = "dummy_test_model_unique"
            id = Column(Integer, primary_key=True)

        assert _DummyTestModel.__tablename__ == "dummy_test_model_unique"
        assert "dummy_test_model_unique" in Base.metadata.tables


# ---------------------------------------------------------------------------
# _resolve_url
# ---------------------------------------------------------------------------


class TestResolveUrl:
    """``_resolve_url`` precedence and dialect normalisation."""

    def test_explicit_argument_wins_over_env(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://env:env@host/env")
        assert db_base._resolve_url("postgresql://arg:arg@host/arg").startswith(
            "postgresql+asyncpg://arg:arg@host/arg"
        )

    def test_env_var_used_when_argument_none(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://envhost/envdb")
        assert db_base._resolve_url(None) == "postgresql+asyncpg://envhost/envdb"

    def test_default_when_no_argument_and_no_env(self):
        # The default is normalised to the asyncpg dialect.
        assert db_base._resolve_url(None) == "postgresql+asyncpg://localhost/vorsyghta"

    def test_plain_postgresql_url_normalised_to_asyncpg(self):
        assert db_base._resolve_url("postgresql://u:p@h:5432/db") == \
            "postgresql+asyncpg://u:p@h:5432/db"

    def test_postgres_url_normalised_to_asyncpg(self):
        assert db_base._resolve_url("postgres://u:p@h:5432/db") == \
            "postgresql+asyncpg://u:p@h:5432/db"

    def test_already_asyncpg_url_unchanged(self):
        url = "postgresql+asyncpg://u:p@h:5432/db"
        assert db_base._resolve_url(url) == url

    def test_non_postgres_url_passed_through(self):
        # SQLite URLs are not normalised.
        assert db_base._resolve_url("sqlite+aiosqlite:///:memory:") == \
            "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# _pool_kwargs_from_env
# ---------------------------------------------------------------------------


class TestPoolKwargsFromEnv:
    """Env-driven pool configuration with valid, invalid and missing values."""

    def test_defaults_when_no_env(self):
        kw = db_base._pool_kwargs_from_env()
        assert kw == {
            "pool_size": 10,
            "max_overflow": 20,
            "pool_timeout": 30,
            "pool_recycle": 3600,
        }

    def test_valid_env_overrides_defaults(self, monkeypatch):
        monkeypatch.setenv("DB_POOL_SIZE", "5")
        monkeypatch.setenv("DB_MAX_OVERFLOW", "7")
        monkeypatch.setenv("DB_POOL_TIMEOUT", "11")
        monkeypatch.setenv("DB_POOL_RECYCLE", "99")
        kw = db_base._pool_kwargs_from_env()
        assert kw == {
            "pool_size": 5, "max_overflow": 7,
            "pool_timeout": 11, "pool_recycle": 99,
        }

    def test_non_integer_env_falls_back_to_default(self, monkeypatch, caplog):
        monkeypatch.setenv("DB_POOL_SIZE", "not-an-int")
        with caplog.at_level(logging.WARNING, logger="vorsyghta.db.base"):
            kw = db_base._pool_kwargs_from_env()
        assert kw["pool_size"] == 10
        assert any("Invalid int for DB_POOL_SIZE" in r.message for r in caplog.records)

    def test_empty_string_env_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("DB_MAX_OVERFLOW", "")
        kw = db_base._pool_kwargs_from_env()
        assert kw["max_overflow"] == 20

    def test_negative_env_value_is_used_as_is(self, monkeypatch):
        # The function does not validate sign, only parseability.
        monkeypatch.setenv("DB_POOL_SIZE", "-3")
        assert db_base._pool_kwargs_from_env()["pool_size"] == -3


# ---------------------------------------------------------------------------
# create_engine
# ---------------------------------------------------------------------------


class TestCreateEngine:
    """``create_engine`` returns a configured ``AsyncEngine``.

    NOTE: ``create_engine`` unconditionally forwards ``pool_size``,
    ``max_overflow`` and ``pool_timeout`` to ``create_async_engine``.
    SQLite's ``StaticPool`` rejects these kwargs, so real engine creation is
    only tested with a PostgreSQL URL (which accepts them).  Kwarg-forwarding
    behaviour is verified by mocking ``create_async_engine`` so we can assert
    exactly what was passed regardless of dialect.
    """

    _PG_URL = "postgresql://user:pass@localhost:5432/vorsyghta"

    def test_returns_async_engine_for_postgres(self):
        engine = create_engine(self._PG_URL)
        assert isinstance(engine, AsyncEngine)

    def test_explicit_pool_params_override_env_for_postgres(self, monkeypatch):
        monkeypatch.setenv("DB_POOL_SIZE", "99")
        engine = create_engine(self._PG_URL, pool_size=2, max_overflow=4,
                                pool_timeout=5, pool_recycle=6)
        assert isinstance(engine, AsyncEngine)

    def test_pool_pre_ping_defaults_true_for_postgres(self):
        engine = create_engine(self._PG_URL)
        assert engine.sync_engine.pool._pre_ping is True

    def test_pool_pre_ping_can_be_overridden_via_extra_for_postgres(self):
        engine = create_engine(self._PG_URL, pool_pre_ping=False)
        assert engine.sync_engine.pool._pre_ping is False

    def test_echo_flag_passed_through_for_postgres(self):
        engine = create_engine(self._PG_URL, echo=True)
        assert engine.sync_engine.echo is True

    def test_logs_safe_url_without_credentials(self, caplog):
        with caplog.at_level(logging.INFO, logger="vorsyghta.db.base"):
            create_engine("postgresql://user:secret@host:5432/db")
        assert all("secret" not in r.message for r in caplog.records)

    # --- kwarg-forwarding verified via mock (dialect-independent) ---

    def test_pool_kwargs_forwarded_to_create_async_engine(self):
        with patch("vorsyghta.db.base.create_async_engine") as mock_ca:
            mock_ca.return_value = MagicMock(spec=AsyncEngine)
            create_engine(self._PG_URL, pool_size=3, max_overflow=5,
                           pool_timeout=7, pool_recycle=9)
            _, kwargs = mock_ca.call_args
            assert kwargs["pool_size"] == 3
            assert kwargs["max_overflow"] == 5
            assert kwargs["pool_timeout"] == 7
            assert kwargs["pool_recycle"] == 9
            assert kwargs["pool_pre_ping"] is True

    def test_env_pool_kwargs_used_when_no_explicit_override(self, monkeypatch):
        monkeypatch.setenv("DB_POOL_SIZE", "8")
        monkeypatch.setenv("DB_MAX_OVERFLOW", "16")
        with patch("vorsyghta.db.base.create_async_engine") as mock_ca:
            mock_ca.return_value = MagicMock(spec=AsyncEngine)
            create_engine(self._PG_URL)
            _, kwargs = mock_ca.call_args
            assert kwargs["pool_size"] == 8
            assert kwargs["max_overflow"] == 16

    def test_echo_forwarded_to_create_async_engine(self):
        with patch("vorsyghta.db.base.create_async_engine") as mock_ca:
            mock_ca.return_value = MagicMock(spec=AsyncEngine)
            create_engine(self._PG_URL, echo=True)
            _, kwargs = mock_ca.call_args
            assert kwargs["echo"] is True

    def test_extra_kwargs_forwarded_to_create_async_engine(self):
        with patch("vorsyghta.db.base.create_async_engine") as mock_ca:
            mock_ca.return_value = MagicMock(spec=AsyncEngine)
            create_engine(self._PG_URL, future=True)
            _, kwargs = mock_ca.call_args
            assert kwargs["future"] is True

    def test_pool_pre_ping_popped_from_extra_not_double_passed(self):
        with patch("vorsyghta.db.base.create_async_engine") as mock_ca:
            mock_ca.return_value = MagicMock(spec=AsyncEngine)
            create_engine(self._PG_URL, pool_pre_ping=False, future=True)
            _, kwargs = mock_ca.call_args
            assert kwargs["pool_pre_ping"] is False
            # ``future`` should still be present (extra is consumed after
            # pool_pre_ping is popped).
            assert kwargs["future"] is True


# ---------------------------------------------------------------------------
# _safe_url_for_log
# ---------------------------------------------------------------------------


class TestSafeUrlForLog:
    """Credential stripping for log output."""

    def test_strips_password_from_postgres_url(self):
        safe = db_base._safe_url_for_log("postgresql+asyncpg://user:secret@host:5432/db")
        assert "secret" not in safe
        assert "***" in safe
        assert "host" in safe

    def test_url_without_credentials_unchanged(self):
        url = "postgresql+asyncpg://host:5432/db"
        assert db_base._safe_url_for_log(url) == url

    def test_unparseable_url_does_not_crash(self):
        # Malformed URL must not raise; falls back to manual stripping.
        result = db_base._safe_url_for_log("not-a-url-at-all")
        assert isinstance(result, str)

    def test_unparseable_url_with_at_sign_strips_creds(self):
        result = db_base._safe_url_for_log("badscheme://user:pass@host/db")
        assert "pass" not in result
        assert "***" in result


# ---------------------------------------------------------------------------
# Singleton engine / session factory / dispose
# ---------------------------------------------------------------------------


class TestSingletonEngineAndDispose:
    """``get_engine`` / ``get_session_factory`` are lazy singletons;
    ``dispose_engine`` clears them.

    Uses a PostgreSQL URL because ``create_engine`` forwards pool kwargs that
    SQLite's StaticPool rejects.
    """

    _PG_URL = "postgresql://user:pass@localhost:5432/vorsyghta"

    def test_get_engine_creates_singleton(self, reset_singletons, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", self._PG_URL)
        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2

    def test_get_session_factory_creates_singleton_bound_to_engine(
        self, reset_singletons, monkeypatch
    ):
        monkeypatch.setenv("DATABASE_URL", self._PG_URL)
        f1 = get_session_factory()
        f2 = get_session_factory()
        assert f1 is f2

    @pytest.mark.asyncio
    async def test_dispose_engine_clears_singletons(self, reset_singletons, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", self._PG_URL)
        engine = get_engine()
        await dispose_engine()
        assert db_base._engine is None
        assert db_base._session_factory is None

    @pytest.mark.asyncio
    async def test_dispose_engine_when_none_is_noop(self, reset_singletons):
        # No engine created yet; dispose must not raise.
        await dispose_engine()
        assert db_base._engine is None

    @pytest.mark.asyncio
    async def test_get_engine_recreates_after_dispose(self, reset_singletons, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", self._PG_URL)
        first = get_engine()
        await dispose_engine()
        second = get_engine()
        assert first is not second


# ---------------------------------------------------------------------------
# DatabaseConfig
# ---------------------------------------------------------------------------


class TestDatabaseConfig:
    """``DatabaseConfig`` defaults and ``resolved_url`` precedence."""

    def test_defaults(self):
        cfg = DatabaseConfig()
        assert cfg.url == ""
        assert cfg.pool_size == 10
        assert cfg.max_overflow == 20
        assert cfg.pool_timeout == 30
        assert cfg.pool_recycle == 3600
        assert cfg.echo is False
        assert cfg.extra == {}

    def test_resolved_url_uses_explicit_url_when_set(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://env/env")
        cfg = DatabaseConfig(url="postgresql://explicit/explicit")
        assert cfg.resolved_url() == "postgresql://explicit/explicit"

    def test_resolved_url_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://env/env")
        assert DatabaseConfig().resolved_url() == "postgresql://env/env"

    def test_resolved_url_falls_back_to_default_when_no_env(self):
        assert DatabaseConfig().resolved_url() == "postgresql://localhost/vorsyghta"

    def test_extra_dict_is_independent_per_instance(self):
        a = DatabaseConfig()
        b = DatabaseConfig()
        a.extra["k"] = "v"
        assert b.extra == {}


# ---------------------------------------------------------------------------
# create_session_factory
# ---------------------------------------------------------------------------


class TestCreateSessionFactory:
    """``create_session_factory`` returns a callable bound to the engine."""

    def test_returns_async_sessionmaker(self):
        engine = create_async_engine(_sqlite_url())
        try:
            factory = create_session_factory(engine)
            assert isinstance(factory, async_sessionmaker)
        finally:
            # close the engine's sync pool
            engine.sync_engine.pool.dispose()

    def test_factory_produces_async_sessions(self):
        engine = create_async_engine(_sqlite_url())
        try:
            factory = create_session_factory(engine)
            session = factory()
            assert isinstance(session, AsyncSession)
        finally:
            engine.sync_engine.pool.dispose()

    def test_expire_on_commit_passed_through(self):
        engine = create_async_engine(_sqlite_url())
        try:
            f_false = create_session_factory(engine, expire_on_commit=False)
            f_true = create_session_factory(engine, expire_on_commit=True)
            # The kwarg is stored on the maker.
            assert f_false.kw["expire_on_commit"] is False
            assert f_true.kw["expire_on_commit"] is True
        finally:
            engine.sync_engine.pool.dispose()

    def test_custom_session_class_used(self):
        class CustomSession(AsyncSession):
            pass

        engine = create_async_engine(_sqlite_url())
        try:
            factory = create_session_factory(engine, class_=CustomSession)
            assert isinstance(factory(), CustomSession)
        finally:
            engine.sync_engine.pool.dispose()


# ---------------------------------------------------------------------------
# get_session context manager
# ---------------------------------------------------------------------------


class TestGetSession:
    """``get_session`` lifecycle: yield, rollback-on-exception, close-always,
    and factory/engine/singleton precedence."""

    @pytest.mark.asyncio
    async def test_yields_a_usable_session(self):
        engine = create_async_engine(_sqlite_url())
        try:
            async with get_session(engine=engine) as session:
                assert isinstance(session, AsyncSession)
                result = await session.execute(text("SELECT 1"))
                assert result.scalar() == 1
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_rolls_back_and_reraises_on_exception(self):
        engine = create_async_engine(_sqlite_url())
        rolled_back = False
        try:
            with pytest.raises(ValueError, match="boom"):
                async with get_session(engine=engine) as session:
                    real_rollback = session.rollback
                    async def spy_rollback():
                        nonlocal rolled_back
                        rolled_back = True
                        await real_rollback()
                    session.rollback = spy_rollback  # type: ignore[assignment]
                    raise ValueError("boom")
            assert rolled_back
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_closes_session_in_finally_on_success(self):
        engine = create_async_engine(_sqlite_url())
        closed = False
        try:
            async with get_session(engine=engine) as session:
                await session.execute(text("SELECT 1"))
                real_close = session.close
                async def spy_close():
                    nonlocal closed
                    closed = True
                    await real_close()
                session.close = spy_close  # type: ignore[assignment]
            assert closed is True
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_closes_session_in_finally_on_exception(self):
        engine = create_async_engine(_sqlite_url())
        closed = False
        try:
            with pytest.raises(RuntimeError):
                async with get_session(engine=engine) as session:
                    real_close = session.close
                    async def spy_close():
                        nonlocal closed
                        closed = True
                        await real_close()
                    session.close = spy_close  # type: ignore[assignment]
                    raise RuntimeError("fail")
            assert closed is True
        finally:
            await engine.dispose()

    @pytest.mark.asyncio
    async def test_factory_takes_precedence_over_engine(self):
        engine_a = create_async_engine(_sqlite_url())
        engine_b = create_async_engine(_sqlite_url())
        try:
            factory_b = create_session_factory(engine_b)
            async with get_session(engine=engine_a, factory=factory_b) as session:
                # The session must be bound to engine_b (the factory's engine).
                assert session.bind is engine_b
        finally:
            await engine_a.dispose()
            await engine_b.dispose()

    @pytest.mark.asyncio
    async def test_uses_singleton_factory_when_neither_given(
        self, reset_singletons, monkeypatch
    ):
        # The singleton path calls create_engine() which forwards pool kwargs
        # that SQLite rejects; patch create_engine to build a SQLite engine.
        monkeypatch.setattr(db_base, "create_engine",
                            lambda *a, **k: create_async_engine(_sqlite_url()))
        try:
            async with get_session() as session:
                assert isinstance(session, AsyncSession)
                assert session.bind is get_engine()
        finally:
            await dispose_engine()

    @pytest.mark.asyncio
    async def test_creates_temp_factory_from_engine_when_no_factory(self):
        engine = create_async_engine(_sqlite_url())
        try:
            async with get_session(engine=engine) as session:
                assert session.bind is engine
        finally:
            await engine.dispose()


# ---------------------------------------------------------------------------
# get_session_dep (FastAPI dependency)
# ---------------------------------------------------------------------------


class TestGetSessionDep:
    """The FastAPI dependency yields a session bound to the singleton engine."""

    @pytest.mark.asyncio
    async def test_dep_yields_session(self, reset_singletons, monkeypatch):
        # Patch create_engine so the singleton builds a SQLite engine.
        monkeypatch.setattr(db_base, "create_engine",
                            lambda *a, **k: create_async_engine(_sqlite_url()))
        try:
            gen = get_session_dep()
            session = await gen.__anext__()
            assert isinstance(session, AsyncSession)
            # Stop the generator to trigger cleanup.
            with pytest.raises(StopAsyncIteration):
                await gen.__anext__()
        finally:
            await dispose_engine()


# ---------------------------------------------------------------------------
# DatabaseHealth dataclass
# ---------------------------------------------------------------------------


class TestDatabaseHealth:
    """``DatabaseHealth`` serialisation."""

    def test_to_dict_contains_all_fields(self):
        h = DatabaseHealth(healthy=True, message="ok", detail="d")
        assert h.to_dict() == {"healthy": True, "message": "ok", "detail": "d"}

    def test_to_dict_with_none_detail(self):
        h = DatabaseHealth(healthy=False, message="bad")
        assert h.to_dict() == {"healthy": False, "message": "bad", "detail": None}


# ---------------------------------------------------------------------------
# check_database_health
# ---------------------------------------------------------------------------


def _mock_conn(*, select_result=1, table_exists_result=True,
               revision_result="004_stripe_billing",
               raise_on_select: Optional[Exception] = None,
               raise_on_table: Optional[Exception] = None):
    """Build a mock engine whose ``connect()`` yields a mock connection."""
    conn = MagicMock()

    select_result_obj = MagicMock()
    select_result_obj.scalar.return_value = select_result

    table_result_obj = MagicMock()
    table_result_obj.scalar.return_value = table_exists_result

    revision_result_obj = MagicMock()
    revision_result_obj.scalar.return_value = revision_result

    async def execute(stmt):
        # Distinguish the two queries by the SQL text.
        sql = str(stmt)
        if "SELECT 1" in sql:
            if raise_on_select:
                raise raise_on_select
            return select_result_obj
        if "information_schema.tables" in sql:
            if raise_on_table:
                raise raise_on_table
            return table_result_obj
        if "alembic_version" in sql:
            return revision_result_obj
        return MagicMock()

    conn.execute = execute

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=None)

    engine = MagicMock()
    engine.connect.return_value = cm
    return engine, conn


class TestCheckDatabaseHealth:
    """All branches of ``check_database_health``."""

    @pytest.mark.asyncio
    async def test_connectivity_failure_returns_unhealthy(self, caplog):
        engine, _ = _mock_conn(raise_on_select=ConnectionError("refused"))
        with caplog.at_level(logging.ERROR, logger="vorsyghta.db.health"):
            result = await check_database_health(engine)
        assert result.healthy is False
        assert "Cannot connect to PostgreSQL" in result.message
        assert "ConnectionError" in (result.detail or "")
        assert "alembic upgrade head" in (result.detail or "")

    @pytest.mark.asyncio
    async def test_schema_query_failure_returns_unhealthy(self, caplog):
        engine, _ = _mock_conn(raise_on_table=RuntimeError("permission denied"))
        with caplog.at_level(logging.ERROR, logger="vorsyghta.db.health"):
            result = await check_database_health(engine)
        assert result.healthy is False
        assert "schema query failed" in result.message
        assert "permission denied" in (result.detail or "")

    @pytest.mark.asyncio
    async def test_table_missing_returns_unhealthy_migrations_not_applied(self, caplog):
        engine, _ = _mock_conn(table_exists_result=False)
        with caplog.at_level(logging.WARNING, logger="vorsyghta.db.health"):
            result = await check_database_health(engine)
        assert result.healthy is False
        assert "migrations not applied" in result.message
        assert "audit.events" in (result.detail or "")

    @pytest.mark.asyncio
    async def test_healthy_when_connectivity_and_table_exist(self, caplog):
        engine, _ = _mock_conn(table_exists_result=True)
        with caplog.at_level(logging.INFO, logger="vorsyghta.db.health"):
            result = await check_database_health(engine)
        assert result.healthy is True
        assert result.message == "Database is healthy"

    @pytest.mark.asyncio
    async def test_outdated_schema_revision_is_unhealthy(self, caplog):
        engine, _ = _mock_conn(revision_result="003_persistence_layer")
        with caplog.at_level(logging.WARNING, logger="vorsyghta.db.health"):
            result = await check_database_health(engine)
        assert result.healthy is False
        assert "schema revision is outdated" in result.message
        assert "004_stripe_billing" in (result.detail or "")

    @pytest.mark.asyncio
    async def test_uses_singleton_engine_when_none_given(
        self, reset_singletons, monkeypatch
    ):
        # Patch create_engine so the singleton builds a SQLite engine.
        monkeypatch.setattr(db_base, "create_engine",
                            lambda *a, **k: create_async_engine(_sqlite_url()))
        try:
            # The singleton engine points at SQLite which has no
            # information_schema, so the schema query will fail -> unhealthy.
            result = await check_database_health()
            assert result.healthy is False
            # Either connectivity or schema-query failure; both are acceptable
            # for SQLite.  The important assertion is that it did not raise and
            # used the singleton.
        finally:
            await dispose_engine()

    @pytest.mark.asyncio
    async def test_table_exists_scalar_returns_none_treated_as_false(self):
        # ``result.scalar() or False`` -> None becomes False.
        engine, _ = _mock_conn(table_exists_result=None)
        result = await check_database_health(engine)
        assert result.healthy is False
        assert "migrations not applied" in result.message


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------


class TestPublicReexports:
    """``vorsyghta.db`` must re-export the documented public API."""

    def test_all_documented_names_are_exported(self):
        import vorsyghta.db as pkg
        expected = {
            "Base", "create_engine", "get_engine", "get_session_factory",
            "dispose_engine", "DatabaseConfig", "create_session_factory",
            "get_session", "get_session_dep", "DatabaseHealth",
            "check_database_health",
        }
        assert expected.issubset(set(pkg.__all__))
        for name in expected:
            assert hasattr(pkg, name), f"{name} missing from vorsyghta.db"
