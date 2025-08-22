# app/processor.py
from __future__ import annotations
from typing import Any, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import DMARCReport


async def process_notification(*, content: bytes,
                               context: Dict[str, Any],
                               db: AsyncSession) -> Dict[str, Any]:
    """
    Implement component logic here.
    'content' is the exact bytes of the uploaded GCS object.
    'context' gives bucket/name/generation and the raw event payload.
    Return a JSON-serializable result.
    """
    try:

        return {"matches_count": 23}
    except Exception as ex:
        print(f"Error processing file: {ex}")
        return {"kind": "bytes", "size": len(content)}


async def db_operation(db: AsyncSession) -> Dict[str, Any]:
    """Example DB operation"""
    try:
        result = await db.execute(
            __import__("sqlalchemy").select(DMARCReport.id).where(
                DMARCReport.id == 23)
        )
        event = result.scalar_one_or_none()
        await db.commit()
        if event:
            return {"event_id": event.id,
                    "timestamp": event.timestamp.isoformat()}
        else:
            return {"event": None}
    except Exception as ex:
        print(f"DB operation error: {ex}")
        return {"error": str(ex)}


if __name__ == "__main__":
    print("Execute test code here.")
