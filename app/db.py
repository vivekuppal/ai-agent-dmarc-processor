# app/db.py
from typing import AsyncGenerator, Optional
import logging
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import (
    AsyncSession, AsyncEngine,
    create_async_engine,
    async_sessionmaker)
from pydantic_settings import BaseSettings, SettingsConfigDict
from app.utils import get_secret


logger = logging.getLogger(__name__)

# Globals (initialized lazily)
engine: Optional[AsyncEngine] = None
SessionLocal: Optional[async_sessionmaker[AsyncSession]] = None


class Settings(BaseSettings):
    """
    Settings for the DB
    """
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")
    DATABASE_URL: str | None = None
    GCE_ENV: bool = False
    GCP_PROJECT_ID: str | None = None
    DB_SECRET_NAME: str = "DATABASE_URL"  # change if needed


settings = Settings()


def resolve_database_url() -> str:
    """Return a usable DATABASE_URL or raise with a helpful message."""
    if settings.DATABASE_URL:
        return settings.DATABASE_URL

    if settings.GCE_ENV:
        if not settings.GCP_PROJECT_ID:
            raise RuntimeError("GCE_ENV=true but GCP_PROJECT_ID is not set.")
        secret_name = settings.DB_SECRET_NAME
        value = get_secret(project_id=settings.GCP_PROJECT_ID,
                           secret_name=secret_name)
        if not value:
            raise RuntimeError(f"Secret {secret_name} returned empty value.")
        return value
    else:
        value = get_secret(project_id=settings.GCP_PROJECT_ID,
                           env_var=secret_name)
        return value

    raise RuntimeError(
        "DATABASE_URL is not set. Either provide it as an env var, or set "
        "GCE_ENV=true and configure Secret Manager access."
    )


def init_engine() -> None:
    """Initialize SQLAlchemy async engine + sessionmaker once."""
    global engine, SessionLocal
    if engine is not None:
        return
    url = resolve_database_url()
    engine = create_async_engine(url, pool_pre_ping=True)
    SessionLocal = async_sessionmaker(engine, expire_on_commit=False,
                                      class_=AsyncSession)
    logger.info("DB engine initialized.")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency."""
    if SessionLocal is None:
        init_engine()
    assert SessionLocal is not None  # for type checkers
    async with SessionLocal() as session:
        yield session


async def dispose_engine() -> None:
    """Call on shutdown to close the pool cleanly."""
    global engine
    if engine is not None:
        await engine.dispose()
        engine = None
        logger.info("DB engine disposed.")


# Create engine once (pooling enabled by default)
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,             # tune for Cloud Run concurrency
    pool_recycle=1800,       # recycle idle conns
    pool_timeout=15,         # fail fast if pool exhausted
)

# Session factory
SessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


@asynccontextmanager
async def maybe_transaction(session):
    if session.in_transaction():
        # Reuse existing transaction
        yield session
    else:
        async with session.begin():
            yield session


# Example usage
# async def db_operation(db: AsyncSession, idem_key: str) -> None:
#     """Example DB operation using the session."""
#     async with db.begin():
#         # Perform database operations here
#         from sqlalchemy.dialects.postgresql import insert
#         stmt = insert(DMARCReport).values(
#             idem_key=idem_key).on_conflict_do_nothing(
#             index_elements=[DMARCReport.idem_key])
#         await db.execute(stmt)
#         await db.commit()

    # Committed or rolled back automatically by context manager
    # No need to call db.commit() explicitly
    # If an exception occurs, the transaction will be rolled back automatically
