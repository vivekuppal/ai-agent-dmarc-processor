# app/db.py
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker)
from contextlib import asynccontextmanager
from pydantic_settings import BaseSettings
from app.models import DMARCReport
import os


class Settings(BaseSettings):
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")


settings = Settings()

# Create engine once (pooling enabled by default)
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,             # tune for Cloud Run concurrency
    max_overflow=10,         # burst handling
)

# Session factory
SessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an AsyncSession with proper cleanup."""
    async with SessionLocal() as session:
        try:
            yield session
        finally:
            # session closed by context manager
            ...


@asynccontextmanager
async def maybe_transaction(session):
    if session.in_transaction():
        # Reuse existing transaction
        yield session
    else:
        async with session.begin():
            yield session


# Example usage
async def db_operation(db: AsyncSession, idem_key: str) -> None:
    """Example DB operation using the session."""
    async with db.begin():
        # Perform database operations here
        from sqlalchemy.dialects.postgresql import insert
        stmt = insert(DMARCReport).values(
            idem_key=idem_key).on_conflict_do_nothing(
            index_elements=[DMARCReport.idem_key])
        await db.execute(stmt)
        await db.commit()

    # Committed or rolled back automatically by context manager
    # No need to call db.commit() explicitly
    # If an exception occurs, the transaction will be rolled back automatically
