import logging
import os
from abc import ABC, abstractmethod
from typing import List, Callable, Dict, Optional, Tuple, Any
from urllib.parse import urlparse, unquote
from google.cloud import storage
from google.cloud.exceptions import GoogleCloudError
from sqlalchemy import select, insert, update
from sqlalchemy.ext.asyncio import AsyncSession
from lxml import etree
from app.models import ProcessedFile
from app.services.validators import ValidationFramework
from app.services.dmarc_parser import DMARCParser
from app.utils import calculate_file_hash
from app.db import maybe_transaction


logger = logging.getLogger(__name__)


class FileProcessor(ABC):
    """Base class for file processors with pluggable factory & async I/O."""
    _registry: Dict[str, Callable[..., "FileProcessor"]] = {}

    """Abstract base class for file processors"""
    def __init__(self, db: AsyncSession, file_path: str = None):
        print("FileProcessor init")
        self.db = db
        self.file_path = file_path
        self.validator = ValidationFramework()
        self.parser = DMARCParser(db)

    # ----- Factory registration -----
    @classmethod
    def register_scheme(cls, scheme: str,
                        constructor: Callable[..., "FileProcessor"]) -> None:
        """Register a constructor for filename pattern
        """
        cls._registry[scheme.lower()] = constructor

    @staticmethod
    def _parse_uri(resource: str) -> Tuple[Optional[str], str, Optional[str]]:
        """
        Returns (scheme, path, netloc/bucket).
        For plain paths (no scheme), scheme=None and path=resource.
        """
        parsed = urlparse(resource)
        if parsed.scheme:
            path = parsed.path[1:] if parsed.path.startswith("/") else parsed.path
            return parsed.scheme.lower(), path, parsed.netloc
        return None, resource, None

    @classmethod
    def create(cls, resource: str, *, db: AsyncSession,
               **kwargs: Any) -> "FileProcessor":
        """
        Choose implementation by URI scheme.
        - Plain path or file:// → LocalFileProcessor
        - gs:// or gcs://      → GCSFileProcessor
        Extra kwargs are forwarded to the constructor (e.g., client=...).
        """
        scheme, path, netloc = cls._parse_uri(resource)

        # Local
        if scheme is None or scheme == "file":
            ctor = cls._registry.get("file")
            print(f"scheme: {scheme}. Creating LocalFileProcessor")
            if not ctor:
                raise ValueError("No handler registered for 'file' scheme.")
            # For file:// we already stripped leading slash in path above
            file_path = resource if scheme is None else f"/{path}"
            return ctor(db=db, file_path=file_path, **kwargs)

        # GCS
        if scheme in ("gs", "gcs"):
            print(f"scheme: {scheme}. Creating GCSFileProcessor")
            ctor = cls._registry.get("gs")
            if not ctor:
                raise ValueError("No handler registered for 'gs' scheme.")
            if not netloc:
                raise ValueError("GCS URI must be gs://<bucket>/<object>")
            return ctor(db=db, file_path=path, bucket=netloc, **kwargs)

        # Custom schemes (if registered)
        ctor = cls._registry.get(scheme)
        if ctor:
            return ctor(db=db, file_path=path, netloc=netloc, **kwargs)

        raise ValueError(f"Unsupported scheme '{scheme}' in resource: {resource}")

    async def check_file_processing_status(self, file_hash: str,
                                           file_path: str) -> tuple[str, int]:
        """
        Check file processing status and handle concurrent access

        Returns: ('skip' | 'duplicate' | 'process' | 'processing', existing_file_id)
        """
        try:
            result = await self.db.execute(
                select(ProcessedFile).where(
                    ProcessedFile.file_hash == file_hash,
                    ProcessedFile.duplicate_id.is_(None)
                )
            )
            existing_file = result.scalar_one_or_none()

            if existing_file:
                if existing_file.report_file == file_path and existing_file.status == "done":
                    return "skip", existing_file.id
                if existing_file.status == "processing":
                    return "processing", existing_file.id
                if existing_file.report_file != file_path:
                    return "duplicate", existing_file.id
                # exists but not 'done' (treat as skip/error state)
                return "skip", existing_file.id

            # not found → needs processing
            return "process", 0

        except Exception as e:
            logger.error(f"Error checking file processing status: {str(e)}")
            return "skip", 0
        finally:
            # IMPORTANT: close the implicit read tx so later code can start a new one
            if self.db.in_transaction():
                await self.db.rollback()

    async def start_file_processing(self, file_hash: str,
                                    report_file: str) -> int:
        """
        Try to claim a file by inserting a 'processing' row.
        Returns the new row's id if inserted;
        returns 0 if a row already exists.
        """
        try:

            stmt = (
                insert(ProcessedFile)
                .values(
                    file_hash=file_hash,
                    report_file=report_file,
                    status="processing",
                    dmarc_report_id=None,
                )
                # If we inserted, return id; if conflict, this returns no rows
                .returning(ProcessedFile.id)
            )

            async with maybe_transaction(self.db):
                res = await self.db.execute(stmt)
                new_id = res.scalar_one_or_none()

            if new_id is None:
                # Row already exists → per your requirement, return 0
                return 0

            # commit succeeded and we have a new id
            logger.info(f"Started processing file: {report_file} (processing_id={new_id})")
            return new_id

        except Exception as ex:
            logger.exception(f"Error starting file processing: {str(ex)}")
            if self.db.in_transaction():
                await self.db.rollback()
            return 0

    async def complete_file_processing(self, processing_id: int,
                                       dmarc_report_id: int) -> bool:
        """Mark file processing as complete (only if currently 'processing').
        """
        try:
            # transaction; commits/rolls back automatically
            stmt = (
                update(ProcessedFile)
                # only transition from processing→done
                .where(
                    ProcessedFile.id == processing_id,
                    ProcessedFile.status == "processing",
                )
                .values(
                    status="done",
                    dmarc_report_id=dmarc_report_id,
                )
                # get a bit of context for logging
                .returning(ProcessedFile.report_file)
            )
            async with maybe_transaction(self.db):
                res = await self.db.execute(stmt)
                row = res.first()  # None if no row matched/updated

            if row:
                report_file = row[0]
                logger.info(
                    f"Completed processing file: {report_file} (processing_id={processing_id}, dmarc_report_id={dmarc_report_id})"
                )
                return True
            else:
                # Either the row doesn't exist, or it wasn't in
                # 'processing' state.
                logger.warning(
                    f"No update performed for processing_id={processing_id} "
                    f"(not found or not in 'processing' state)."
                )
                return False

        except Exception:
            if self.db.in_transaction():
                await self.db.rollback()
            logger.exception("Error completing file processing")

    async def mark_file_as_error(self, processing_id: int) -> bool:
        """Mark file processing as failed."""
        try:
            stmt = (
                update(ProcessedFile)
                .where(ProcessedFile.id == processing_id,
                       ProcessedFile.status == "processing")
                .values(status="error")
                .returning(ProcessedFile.report_file)
            )
            async with maybe_transaction(self.db):
                res = await self.db.execute(stmt)
                row = res.first()  # None if no row matched

            if row:
                report_file = row[0]
                logger.error(f"Marked file as error: {report_file} (processing_id={processing_id})")
                return True
            else:
                logger.warning(f"No row found to mark as error (processing_id={processing_id}).")
                return False

        except Exception:
            logger.exception("Error marking file as error")
            if self.db.in_transaction():
                await self.db.rollback()

    async def mark_file_as_duplicate(self, file_hash: str,
                                     report_file: str,
                                     original_file_id: int) -> int:
        """
        Insert a 'duplicate' row pointing to the original file.
        Returns the new row id, or 0 on error.
        """
        try:
            async with maybe_transaction(self.db):
                dup = ProcessedFile(
                    file_hash=file_hash,
                    report_file=report_file,
                    status="duplicate",
                    duplicate_id=original_file_id,
                    dmarc_report_id=None,
                )
                self.db.add(dup)
                await self.db.flush()      # get dup.id from DB
                new_id = dup.id

            # committed successfully
            logger.info(f"Marked file as duplicate: {report_file} "
                        f"(original_id={original_file_id}, new_id={new_id})")
            return new_id

        except Exception:
            logger.exception("Error marking file as duplicate")
            if self.db.in_transaction():
                await self.db.rollback()
            return 0

    async def mark_file_as_processed(
        self,
        file_hash: str,
        dmarc_report_id: int,
        report_file: str,
        duplicate_id: int | None = None,
    ) -> int:
        """Mark a file as processed ('done') and record linkage
        to the DMARC report.
        """
        try:
            async with maybe_transaction(self.db):
                pf = ProcessedFile(
                    file_hash=file_hash,
                    report_file=report_file,
                    status="done",
                    dmarc_report_id=dmarc_report_id,
                    duplicate_id=duplicate_id,
                )
                self.db.add(pf)
                await self.db.flush()     # populate pf.id from DB
                new_id = pf.id

            logger.info(
                f"Marked file as processed: {report_file} "
                f"(hash={file_hash[:8]}..., dmarc_report_id={dmarc_report_id}, id={new_id})"
            )
            return new_id

        except Exception:
            logger.exception("Error marking file as processed")
            if self.db.in_transaction():
                await self.db.rollback()
            return 0

    def determine_report_source(self, file_name: str, content: bytes) -> str:
        """Determine the report source based on filename or org_name in XML or XML content.
        Fallback: return org_name value if present, else 'Unknown'."""
        file_name_lower = file_name.lower()

        # 1. Check filename first
        mapping = {
            'google': 'Google',
            'microsoft': 'Microsoft',
            'outlook': 'Microsoft',
            'yahoo': 'Yahoo',
            'amazon': 'Amazon',
            'comcast': 'Comcast',
            'reddit': 'Reddit',
            'emailsrvr': 'Emailsrvr',
            'mimecast': 'Mimecast',
            'netscape': 'Netscape',
            'thalesgroup': 'Thalesgroup',
            'aol': 'AOL',
            'yandex': 'Yandex',
            'sbcglobal': 'SBC',
            'att': 'ATT',
            'verizon': 'Verizon',
            'cloudflare': 'Cloudflare'
        }
        for key, source in mapping.items():
            if key in file_name_lower:
                return source

        # 2. Parse XML and check <feedback><report_metadata><org_name>
        try:
            root = etree.fromstring(content)
            org_name_el: Optional[etree._Element] = root.find(".//report_metadata/org_name")
            if org_name_el is not None and org_name_el.text:
                org_name_text = org_name_el.text.strip()
                org_name_lower = org_name_text.lower()
                for key, source in mapping.items():
                    if key in org_name_lower:
                        return source
                # 3. If no mapping match, return the org_name value itself
                return org_name_text
        except Exception:
            # swallow XML parse errors
            pass

        # 4. Fallback: scan content string
        try:
            content_str = content.decode("utf-8", errors="ignore").lower()
            for key, source in mapping.items():
                if key in content_str:
                    return source
        except UnicodeDecodeError:
            pass

        # 5. Default
        return "Unknown"

    @abstractmethod
    async def process_file(self, content: bytes, file_path: str) -> bool:
        """Process a single DMARC report file"""
        pass


class LocalFileProcessor(FileProcessor):
    """Process local files with concurrent processing protection."""

    async def process_file(self, content: bytes, file_path: str) -> bool:
        """Process a single DMARC report file with concurrent
        processing protection
        """
        logger.info(f"LocalFileProcessor: Processing file: {file_path}")
        processing_id = 0
        try:
            # Calculate file hash
            file_hash = calculate_file_hash(content)

            # Check processing status for concurrent access control
            action, existing_file_id = await self.check_file_processing_status(
                file_hash, file_path)

            if action == 'skip':
                return True
            elif action == 'processing':
                logger.info(f"File currently being processed by another instance, skipping: {file_path}")
                return True
            elif action == 'duplicate':
                # Mark as duplicate, move to processed
                await self.mark_file_as_duplicate(file_hash, file_path,
                                                  existing_file_id)
                logger.info(f"File marked as duplicate: {file_path} (original_id: {existing_file_id})")
                return True
            elif action == 'process':
                # Start processing - this creates the lock
                processing_id = await self.start_file_processing(file_hash,
                                                                 file_path)
                if processing_id == 0:
                    logger.error(f"Failed to start processing lock for: {file_path}")
                    return False
            else:
                logger.error(f"Unknown action from file status check: {action}")
                return False

            # Determine report source
            report_source = self.determine_report_source(file_name=file_path,
                                                         content=content)

            # Validate file
            validation_result = self.validator.validate_file(content,
                                                             file_path)
            if not validation_result.is_valid:
                logger.error(f"File validation failed for {file_path}: {validation_result.errors}")
                await self.mark_file_as_error(processing_id)
                return False

            # Parse DMARC report (creates entries in dmarc_reports and dmarc_report_details tables)
            dmarc_report_id = await self.parser.parse_and_store(content,
                                                                file_path,
                                                                report_source)
            if not dmarc_report_id:
                logger.error(f"Failed to parse DMARC report: {file_path}")
                await self.mark_file_as_error(processing_id)
                return False

            # Mark processing as complete
            await self.complete_file_processing(processing_id, dmarc_report_id)

            return True

        except Exception as e:
            logger.error(f"LocalFileProcessor: Error processing file {file_path}: {str(e)}")
            # Mark as error if we have a processing lock
            if processing_id > 0:
                await self.mark_file_as_error(processing_id)
            return False


class GCSFileProcessor(FileProcessor):
    """Process GCS files with concurrent processing protection."""

    def __init__(self, db: AsyncSession, file_path: str = None,
                 bucket: str = None):
        print("GCSFileProcessor init")
        super().__init__(db, file_path)
        if bucket:
            self.bucket_name = bucket
        else:
            # self.bucket_name = os.environ.get("GOOGLE_BUCKET")
            # hard coded here on purpose, since we do not want to
            # provide an env variable to the container. Bucket name
            # should be part of pub sub notification
            self.bucket_name = 'lai-dmarc-aggregate-reports'

        self.client = None
        self.bucket = None

        if not self.bucket_name:
            raise ValueError("GOOGLE_BUCKET environment variable is required")

        try:
            self.client = storage.Client()
            self._initialize_bucket()
        except Exception as e:
            logger.error(f"Failed to initialize Google Cloud Storage client: {str(e)}")
            logger.info("Make sure Google Cloud credentials are properly configured")
            raise

    def __del__(self):
        """Best-effort cleanup (not guaranteed to run on interpreter shutdown)."""
        try:
            self.close()
        except Exception:
            # Avoid raising during GC
            pass

    def close(self) -> None:
        """Gracefully release resources.
        """
        try:
            # Buckets are lightweight refs; just drop it.
            self.bucket = None
            # The client owns an HTTP session; close it if present.
            if self.client is not None:
                http = getattr(self.client, "_http", None)  # requests.Session
                if http is not None:
                    try:
                        http.close()
                    except Exception:
                        logger.warning("Failed to close GCS HTTP session cleanly", exc_info=True)
                # Drop client ref so GC can reclaim
                self.client = None
        except Exception:
            logger.exception("Error during GCSFileProcessor.close()")

    def _initialize_bucket(self):
        """Initialize GCS bucket connection"""
        try:
            # Create bucket reference without validating bucket metadata
            self.bucket = self.client.bucket(self.bucket_name)
            logger.info(f"GCS bucket client initialized for: {self.bucket_name}")
        except Exception as e:
            logger.error(f"Failed to initialize GCS bucket client: {str(e)}")
            raise

    def switch_bucket(self, new_bucket_name: str) -> None:
        """
        Close current bucket context and reinitialize to a different bucket.
        """
        if not new_bucket_name:
            raise ValueError("Bucket name must be a non-empty string")

        # If you want to *reuse* the client (faster), don't call self.close() here.
        # Just drop the bucket ref and rebind.
        try:
            if new_bucket_name == self.bucket_name and self.bucket is not None:
                logger.info(f"Already bound to bucket: {new_bucket_name}")
                return

            # Drop current bucket reference
            self.bucket = None
            self.bucket_name = new_bucket_name

            # Reuse existing client if available; otherwise create one.
            if self.client is None:
                self.client = storage.Client()

            self._initialize_bucket()
            logger.info(f"Switched GCS bucket to: {self.bucket_name}")
        except Exception:
            logger.exception(f"Failed to switch to bucket: {new_bucket_name}")
            raise

    def get_xml_files(self) -> List[storage.Blob]:
        """Get all XML files from the GCS bucket (excluding processed folder)
        """
        try:
            blobs = list(self.bucket.list_blobs())
            # Filter for XML files that are NOT in the processed folder
            xml_files = [
                blob for blob in blobs
                if blob.name.lower().endswith('.xml') and '/' not in blob.name and not blob.name.startswith('processed/')
            ]
            logger.info(f"Found {len(xml_files)} XML files in bucket (excluding processed folder)")
            return xml_files
        except GoogleCloudError as e:
            logger.error(f"Error listing files in bucket: {str(e)}")
            return []

    def copy_file_to(self, blob: storage.Blob, destination: str) -> bool:
        """
        Copy a GCS blob to another location in the same bucket.

        Args:
            blob: source blob object
            destination: destination object path. Can be:
                - "processed/<filename>.xml" (full path), or
                - "processed/" (folder; will reuse the source filename)
        """
        try:
            # If destination is a folder, append the source filename
            if destination.endswith("/"):
                destination = f"{destination}{os.path.basename(blob.name)}"

            dest_blob = self.bucket.blob(destination)

            # Copy data (and metadata) to the new object
            dest_blob.rewrite(blob)  # simple rewrite; good for same-bucket copies

            logger.info(f"Copied file: {blob.name} -> {destination}")
            return True

        except Exception as e:
            logger.error(f"Failed to copy file: {blob.name} -> {destination} - {e}")
            return False

    def move_file_to_processed(self, blob: storage.Blob) -> bool:
        """Move successfully processed file to processed folder"""
        try:
            # Create processed folder path
            processed_path = f"processed/{blob.name}"

            # Copy file to processed folder
            processed_blob = self.bucket.blob(processed_path)
            processed_blob.rewrite(blob)

            # Delete original file
            blob.delete()

            logger.info(f"Moved file to processed folder: {blob.name} -> {processed_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to move file to processed folder: {blob.name} - {str(e)}")
            return False

    def delete_gcs_file(self, blob: storage.Blob):
        """Delete a file from GCS"""
        blob.delete()
        logger.info(f"Deleted file: {blob.name}.")

    def download_file_content(self, blob: storage.Blob) -> Optional[bytes]:
        """Download file content from GCS"""
        try:
            content = blob.download_as_bytes()
            logger.info(f"Downloaded file: {blob.name} ({len(content)} bytes)")
            return content
        except GoogleCloudError as e:
            logger.error(f"Error downloading file {blob.name}: {str(e)}")
            return None

    async def process_file(self, content: bytes, file_path: str) -> bool:
        logger.info(f"GCSFileProcessor: Processing file: {file_path}")
        relative_path = self.object_path_from_gcs_url(file_path)
        logger.info(f"Processing file relative path: {relative_path}")
        processing_id = 0
        try:
            # Calculate file hash
            file_hash = calculate_file_hash(content)

            # Check processing status for concurrent access control
            action, existing_file_id = await self.check_file_processing_status(
                file_hash, file_path)
            file_blob = self.bucket.blob(relative_path)

            if action == 'skip':
                logger.info(f"File already processed, skipping and delete: {file_path} (hash: {file_hash[:8]}...)")
                self.delete_gcs_file(file_blob)
                return True
            elif action == 'processing':
                logger.info(f"File currently being processed by another instance, skipping: {file_path}")
                return True
            elif action == 'duplicate':
                # Mark as duplicate, move to processed
                await self.mark_file_as_duplicate(file_hash, file_path,
                                                  existing_file_id)
                # await self.move_file_to_processed(file_blob)
                logger.info(f"File marked as duplicate: {file_path} (original_id: {existing_file_id})")
                return True
            elif action == 'process':
                # Start processing - this creates the lock
                processing_id = await self.start_file_processing(file_hash,
                                                                 file_path)
                if processing_id == 0:
                    logger.error(f"Failed to start processing lock for: {file_path}")
                    return False
            else:
                logger.error(f"Unknown action from file status check: {action}")
                return False

            # Determine report source
            report_source = self.determine_report_source(file_blob.name,
                                                         content)

            # Validate file
            validation_result = self.validator.validate_file(content,
                                                             file_path)
            if not validation_result.is_valid:
                logger.error(f"File validation failed for {file_path}: {validation_result.errors}")
                await self.mark_file_as_error(processing_id)
                return False

            # Parse DMARC report (creates entries in dmarc_reports,
            # dmarc_report_details, dmarc_report_auth tables)
            dmarc_report_id = await self.parser.parse_and_store(content,
                                                                file_path,
                                                                report_source)
            if not dmarc_report_id:
                logger.error(f"Failed to parse DMARC report: {file_path}")
                await self.mark_file_as_error(processing_id)
                return False

            # Mark processing as complete
            await self.complete_file_processing(processing_id, dmarc_report_id)

            # Copy file to spoofing folder. At the time of writing this is used
            # as input by the spoofing ai agent
            self.copy_file_to(file_blob, "spoofing/")

            # Move file to processed folder
            if self.move_file_to_processed(file_blob):
                logger.info(f"Successfully processed and moved file: {file_path} (dmarc_report_id: {dmarc_report_id})")
            else:
                logger.warning(f"File processed but failed to move to processed folder: {file_path}")

            return True

        except Exception as e:
            logger.error(f"Error 2 processing file {file_path}: {str(e)}")
            # Mark as error if we have a processing lock
            if processing_id > 0:
                await self.mark_file_as_error(processing_id)
            return False

    async def process_gcs_file(self, blob: storage.Blob) -> bool:
        """Process a single DMARC report file"""
        file_path = f"gs://{self.bucket_name}/{blob.name}"
        logger.info(f"Processing gcs_file: {file_path}")
        try:
            content = self.download_file_content(blob)
            if content is None:
                return False
            return self.process_file(content, file_path=file_path)
        except Exception as e:
            logger.error(f"Error processing gcs file {file_path}: {str(e)}")
            return False

    async def process_all_files(self):
        """Process all DMARC report files in the bucket"""
        logger.info("Starting GCS bucket monitoring cycle")

        try:
            xml_files = self.get_xml_files()

            if not xml_files:
                logger.info("No XML files found in bucket")
                return

            processed_count = 0
            failed_count = 0

            for blob in xml_files:
                try:
                    res = await self.process_gcs_file(blob)
                    if res:
                        processed_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    logger.error(f"Unexpected error processing file {blob.name}: {str(e)}")
                    failed_count += 1

            logger.info(f"GCS monitoring cycle complete. Processed: {processed_count}, Failed: {failed_count}")

        except Exception as e:
            logger.error(f"Error in GCS monitoring cycle: {str(e)}")

    @staticmethod
    def object_path_from_gcs_url(gcs_url: str) -> str:
        """Extract the object path from a GCS URL like:
        gs://my-bucket/folder/file.xml  -> "folder/file.xml"
        gcs://my-bucket/file.xml        -> "file.xml"
        Raises ValueError on bad input.
        """
        p = urlparse(gcs_url.strip())
        if p.scheme.lower() not in ("gs", "gcs"):
            raise ValueError("URL must start with gs:// or gcs://")
        if not p.netloc:
            raise ValueError("Bucket name is missing in URL")
        obj = unquote(p.path.lstrip("/"))
        if not obj:
            raise ValueError("Object path is missing in URL")
        return obj


# Register GCS handler for gs:// and gcs://
def _gcs_ctor(**kw):
    return GCSFileProcessor(**kw)


def _local_ctor(**kw):
    return LocalFileProcessor(**kw)


FileProcessor.register_scheme("gs", _gcs_ctor)
FileProcessor.register_scheme("gcs", _gcs_ctor)
FileProcessor.register_scheme("file", _local_ctor)
FileProcessor.register_scheme("", _local_ctor)  # default to local
