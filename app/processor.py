# app/processor.py
from __future__ import annotations
from typing import Any, Dict
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException
from app.models import DMARCReport
from app.services.gcs_monitor import FileProcessor


async def process_notification(*,
                               content: bytes,
                               context: Dict[str, Any],
                               db: AsyncSession) -> Dict[str, Any]:
    """
    Implement component logic here.
    'content' is the exact bytes of the uploaded GCS object.
    'context' gives bucket/name/generation and the raw event payload.
    Return a JSON-serializable result.
    """
    try:
        # file_path should be complete input filename
        file_path = context.get("file_path", "")
        file_processor = FileProcessor.create(file_path, db=db)

        # process
        result = await file_processor.process_file(content=content,
                                                   file_path=file_path)
        return {
            'status': result,
            'message': 'Notification successfully processed'
        }

    except Exception as ex:
        print(f"Error processing file in process_notification: {ex}")
        raise HTTPException(status_code=500, detail=str(ex)) from ex


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
