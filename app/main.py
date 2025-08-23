# app/main.py
import base64
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional, Tuple
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException, Response, Depends
from google.cloud import storage
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine
from sqlalchemy import select, func

from app.processor import process_notification
from app.utils import verify_pubsub_jwt_if_required, json_dumps
from app.db import engine, get_db
from app.models import Base


# Load environment variables from .env file if it exists
if os.path.exists('.env'):
    from dotenv import load_dotenv
    load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger("uvicorn")
logger.setLevel(logging.INFO)

# Config via env
COMPONENT_NAME = os.getenv("COMPONENT_NAME", "ai-agent-dmarc-processor")
EXPECTED_EVENT_TYPE = os.getenv("EXPECTED_EVENT_TYPE", "OBJECT_FINALIZE")
OBJECT_PREFIX = os.getenv("OBJECT_PREFIX", "")
OUTPUT_PREFIX = os.getenv("OUTPUT_PREFIX", f"outputs/{COMPONENT_NAME}/")
READ_CHUNK_SIZE = int(os.getenv("READ_CHUNK_SIZE", "0"))  # 0 -> entire file


# Lazily created GCS client
_storage_client: Optional[storage.Client] = None


# TODO: do startup checks here
@asynccontextmanager
async def lifespan(local_app: FastAPI):
    # If you want to run startup checks or migrations, do it here
    # e.g., verify DB connectivity:
    # async with engine.begin() as conn:
    #     await conn.execute(text("SELECT 1"))
    yield
    await engine.dispose()


app = FastAPI(title=COMPONENT_NAME, lifespan=lifespan)


def get_storage() -> storage.Client:
    """ Returns a GCS client, creating it if not already done.
    """
    global _storage_client
    if _storage_client is None:
        _storage_client = storage.Client()
    return _storage_client


def _extract_event(body: Dict[str, Any]) -> Tuple[str, str, Optional[int], Dict[str, Any]]:
    """
    Supports the default 'wrapped' Pub/Sub push body and GCS notification payload.
    Returns: (bucket, object_id, generation, raw_payload)
    """
    # Default wrapped format: { "message": {"data": "...base64...", "attributes": {...}}, "subscription": "..." }
    msg = body.get("message") or {}
    attrs = msg.get("attributes") or {}

    bucket = attrs.get("bucketId")
    object_id = attrs.get("objectId")
    generation_raw = attrs.get("objectGeneration")
    event_type = attrs.get("eventType")
    payload_format = attrs.get("payloadFormat")

    # If not present in attributes, try data payload (GCS JSON API object)
    data_b64 = msg.get("data")
    payload = {}
    if data_b64:
        try:
            decoded = base64.b64decode(data_b64)
            payload = json.loads(decoded.decode("utf-8")) if decoded else {}
        except Exception:
            logger.warning("Failed to base64-decode/parse message.data; continuing with attributes only")

    if not bucket:
        bucket = payload.get("bucket")
    if not object_id:
        object_id = payload.get("name")
    generation = None
    if generation_raw:
        try:
            generation = int(generation_raw)
        except Exception:
            pass
    if generation is None:
        # GCS JSON API payload carries generation as string
        gen_str = payload.get("generation")
        if gen_str is not None:
            try:
                generation = int(gen_str)
            except Exception:
                pass

    # Basic gating
    if EXPECTED_EVENT_TYPE and event_type and event_type != EXPECTED_EVENT_TYPE:
        raise HTTPException(status_code=204,
                            detail=f"Ignored eventType={event_type}")

    if OBJECT_PREFIX and object_id and not object_id.startswith(OBJECT_PREFIX):
        raise HTTPException(status_code=204,
                            detail=f"Ignored prefix: {object_id}")

    if not bucket or not object_id:
        raise HTTPException(status_code=400,
                            detail="Missing bucket/object in event")

    return bucket, object_id, generation, {
        "attributes": attrs,
        "payloadFormat": payload_format,
        "payload": payload,
    }


def _download_exact_generation(bucket_name: str, object_id: str,
                               generation: Optional[int]) -> bytes:
    """
    Download the object bytes, pinning to a specific generation when provided.
    """
    client = get_storage()
    bucket = client.bucket(bucket_name)
    if generation is not None:
        blob = storage.Blob(name=object_id, bucket=bucket,
                            generation=generation)
        # Guard on the expected generation for strictness (safe if server supports it).
        return blob.download_as_bytes(if_generation_match=generation)
    else:
        # Fallback: live version (not ideal if multiple writes happen quickly)
        blob = bucket.blob(object_id)
        return blob.download_as_bytes()


@app.get("/health")
def health():
    """ Health check endpoint."""
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "component": COMPONENT_NAME
        }


@app.get('/')
def home():
    """Home endpoint for DMARC Report Processor AI agent"""
    return {
        'name': 'DMARC Report Processor AI Agent',
        'version': '1.0.0',
        'description': 'Automated DMARC report processing service',
        'status': 'running',
        'endpoints': {
            '/': 'Home page. Provides a list of available endpoints.',
            '/health': 'Health check endpoint',
            '/status': 'Application status and statistics',
            '/test-gcs': 'Test Google Cloud Storage connection',
            '/list-all-bucket-files': 'List all files in the GCS bucket',
            '/trigger-monitoring': 'Manual Trigger for processing files in GCS bucket',
            '/clear-gsm-cache': 'Clear cached Google Cloud Secret Manager secrets',
            '/local-test': 'Process a local DMARC XML file for testing',
            '/test-db': 'Test database connectivity',
            '/trigger': 'Pub/Sub push endpoint for GCS events'
        }
    }


@app.get('/status')
async def status(db: AsyncSession = Depends(get_db)):
    """Application status endpoint"""
    from app.models import DMARCReport, DMARCReportDetail, ProcessedFile

    try:
        dmarc_count = await db.scalar(
            select(func.count()).select_from(DMARCReport))
        detail_count = await db.scalar(
            select(func.count()).select_from(DMARCReportDetail))
        processed_count = await db.scalar(
            select(func.count()).select_from(ProcessedFile))

        status_info = {
            'status': 'running',
            'timestamp': datetime.now().isoformat(),
            'database': {
                'dmarc_reports': dmarc_count,
                'dmarc_report_details': detail_count,
                'processed_files': processed_count
            },
            'configuration': {
                'component_name': COMPONENT_NAME,
                'expected_event_type': EXPECTED_EVENT_TYPE,
                'object_prefix': OBJECT_PREFIX,
                'output_prefix': OUTPUT_PREFIX
            }
        }

        return status_info

    except Exception as e:
        logger.exception("status_failed")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.get('/list-all-bucket-files')
def list_all_bucket_files(db: AsyncSession = Depends(get_db)):
    """List all files in the GCS bucket including processed folder"""
    try:
        from app.services.gcs_monitor import GCSFileProcessor

        monitor = GCSFileProcessor(db)

        # Get all files in bucket (not just XML)
        all_blobs = list(monitor.bucket.list_blobs())

        # Separate files by location
        root_files = [
            blob.name for blob in all_blobs
            if '/' not in blob.name and not blob.name.startswith('processed/')
        ]
        # Files under 'processed/' subfolder
        processed_files = [
            blob.name for blob in all_blobs
            if blob.name.startswith('processed/') and not blob.name.endswith('/')
        ]
        # root_files = [blob.name for blob in all_blobs if not blob.name.startswith('processed/')]
        # processed_files = [blob.name for blob in all_blobs if blob.name.startswith('processed/')]

        return {
            'status': 'success',
            'bucket': monitor.bucket_name,
            'total_files': len(all_blobs),
            'root_files': root_files,
            'processed_files': processed_files,
            'processed_folder_exists': len(processed_files) > 0
        }

    except Exception as e:
        return {'status': 'error', 'error': str(e)}, 500


@app.get('/trigger-monitoring')
def trigger_monitoring(db: AsyncSession = Depends(get_db)):
    """Manually trigger GCS monitoring cycle for testing"""
    try:
        from app.services.gcs_monitor import GCSFileProcessor

        monitor = GCSFileProcessor(db)
        monitor.process_all_files()

        return {
            'status': 'success',
            'message': 'GCS monitoring cycle completed'
        }

    except Exception as e:
        return {'status': 'error', 'error': str(e)}, 500


@app.get("/clear-gsm-cache")
def clear_cached_secrets():
    """
    Clear the cached Google Cloud Secret Manager secrets.
    Useful if you know a secret has changed and you want to force a reload.
    """
    from app.utils import clear_gsm_cache
    clear_gsm_cache()
    return {"status": "ok", "message": "GSM cache cleared."}


@app.get("/local-test")
async def local_test(db: AsyncSession = Depends(get_db)):
    """
    Process the file smoke.xml locally"""
    with open("app/test_dmarc_sample.xml", "rb") as f:
        content_bytes = f.read()

    # Process the notification
    result = await process_notification(
            content=content_bytes,
            context={
                "filepath": "app/test_dmarc_sample.xml",
                "component": COMPONENT_NAME
            },
            db=db
        )
    print("Local test result:", result)
    return {"status": "ok", "component": COMPONENT_NAME, "result": result}


@app.get("/test-db")
async def test_db(db: AsyncSession = Depends(get_db)):
    """Test database connectivity."""
    from sqlalchemy import text

    try:
        await db.execute(text("SELECT 1"))
        return {"status": "success"}
    except Exception as e:
        # optional: logger.exception("db_test_failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/trigger")  # Pub/Sub push target
async def pubsub_push(request: Request,
                      db: AsyncSession = Depends(get_db)):
    """ Handles Pub/Sub push messages for GCS object finalize events.
        Expects a wrapped Pub/Sub message with a JSON body containing
        the event data.
    """
    # Optional: Verify OIDC token if you also configured Cloud Run to
    # allow unauthenticated or you want to double-check audience/issuer.
    # If your service requires auth, Cloud Run will already enforce it
    # before reaching the app.
    await verify_pubsub_jwt_if_required(request)

    try:
        body = await request.json()
    except Exception as ex:
        # If you enabled "payload unwrapping", body might be raw bytes; treat as no-op here.
        raise HTTPException(status_code=400,
                            detail="Expected JSON body from Pub/Sub (wrapped).") from ex

    try:
        bucket, object_id, generation, raw = _extract_event(body)
    except HTTPException as e:
        # 2xx acknowledges the message. Return 204 for "ignored" to avoid retries.
        if 200 <= e.status_code < 300:
            return Response(status_code=e.status_code)
        raise

    # Idempotency key (store/consult in your DB in future step)
    idem_key = f"{bucket}/{object_id}#{generation if generation is not None else 'live'}"
    logger.info(json_dumps({
        "msg": "event_received",
        "component": COMPONENT_NAME,
        "bucket": bucket,
        "object": object_id,
        "generation": generation,
        "idem_key": idem_key,
    }))

    # 1) Read object (by generation when available)
    try:
        content_bytes = _download_exact_generation(bucket, object_id,
                                                   generation)
    except Exception as e:
        logger.exception("download_failed")
        # Non-2xx => Pub/Sub will retry
        raise HTTPException(status_code=500,
                            detail=f"Download failed: {e}") from e

    # 2) Process
    try:
        # process the notification
        result = await process_notification(
            content=content_bytes,
            context={
                "bucket": bucket,
                "object": object_id,
                "generation": generation,
                "component": COMPONENT_NAME,
                "raw_event": raw,
                "filename": object_id
            },
            db=db
        )
    except Exception as e:
        logger.exception("processing_failed")
        raise HTTPException(status_code=500,
                            detail=f"Processing failed: {e}") from e

    # 3) (Optional) Write output next to source in a component-specific prefix
    try:
        if OUTPUT_PREFIX:
            out_name = f"{OUTPUT_PREFIX}{object_id}.gen{generation if generation is not None else 'live'}.json"
            client = get_storage()
            bucket_ref = client.bucket(bucket)
            out_blob = bucket_ref.blob(out_name)
            out_blob.upload_from_string(
                data=json_dumps({"result": result, "source": idem_key}),
                content_type="application/json",
            )
            logger.info(json_dumps({"msg": "output_written",
                                    "uri": f"gs://{bucket}/{out_name}"}))
    except Exception as e:
        logger.exception("output_write_failed")
        raise HTTPException(status_code=500,
                            detail="Output write failed") from e

    # Return 204 (no body) to ack push message immediately.
    return Response(status_code=204)


# --------------------------------------
# DB related utilities
# --------------------------------------
async def create_tables(local_engine: AsyncEngine = engine) -> None:
    """Create all tables using the async engine."""
    async with local_engine.begin() as conn:
        # run the synchronous DDL in the async context
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created successfully")


def main():
    """Main application entry point
    """
    # Use this only in local testing mode not in Cloud Run
    logger.info("Starting DMARC Report Processor")

    # Validate required environment variables
    required_vars = ['DATABASE_URL']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]

    if missing_vars:
        logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        exit(1)

    import asyncio

    asyncio.run(create_tables(engine))


if __name__ == '__main__':
    main()
