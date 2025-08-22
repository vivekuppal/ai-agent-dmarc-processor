import os
import logging
from typing import List, Optional
from google.cloud import storage
from google.cloud.exceptions import GoogleCloudError
from models import ProcessedFile
from services.validators import ValidationFramework
from services.dmarc_parser import DMARCParser
from utils import calculate_file_hash
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)


class GCSMonitor:
    """Monitor Google Cloud Storage bucket for new DMARC report files"""

    def __init__(self, db):
        self.db = db
        self.bucket_name = os.environ.get("GOOGLE_BUCKET")
        self.client = None
        self.bucket = None
        self.validator = ValidationFramework()
        self.parser = DMARCParser(db)

        if not self.bucket_name:
            raise ValueError("GOOGLE_BUCKET environment variable is required")

        try:
            self.client = storage.Client()
            self._initialize_bucket()
        except Exception as e:
            logger.error(f"Failed to initialize Google Cloud Storage client: {str(e)}")
            logger.info("Make sure Google Cloud credentials are properly configured")
            raise

    def _initialize_bucket(self):
        """Initialize GCS bucket connection"""
        try:
            # Create bucket reference without validating bucket metadata
            self.bucket = self.client.bucket(self.bucket_name)
            logger.info(f"GCS bucket client initialized for: {self.bucket_name}")
        except Exception as e:
            logger.error(f"Failed to initialize GCS bucket client: {str(e)}")
            raise

    def get_xml_files(self) -> List[storage.Blob]:
        """Get all XML files from the GCS bucket (excluding processed folder)"""
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

    def check_file_processing_status(self, file_hash: str, file_path: str) -> tuple[str, int]:
        """
        Check file processing status and handle concurrent access

        Returns:
            tuple: (action, existing_file_id)
            action can be: 'skip', 'duplicate', 'process', 'processing'
        """
        try:
            logger.info("check_file_processing_status")
            Session = sessionmaker(bind=self.db.engine)
            session = Session()

            # Check if file hash exists
            existing_file = session.query(ProcessedFile).filter_by(file_hash=file_hash).first()

            if existing_file:
                # File hash exists - check filename and status
                if existing_file.report_file == file_path and existing_file.status == 'done':
                    # Same file name, skip
                    session.close()
                    return 'skip', existing_file.id
                elif existing_file.status == 'processing':
                    session.close()
                    return 'processing', existing_file.id
                elif existing_file.report_file != file_path:
                    # Same hash, different filename - mark as duplicate
                    session.close()
                    return 'duplicate', existing_file.id
                else:
                    # File exists but not done (error state)
                    session.close()
                    return 'skip', existing_file.id
            session.close()
            return 'process', 0

        except Exception as e:
            logger.error(f"Error checking file processing status: {str(e)}")
            return 'skip', 0

    def start_file_processing(self, file_hash: str, report_file: str) -> int:
        """Mark file as being processed to prevent concurrent processing"""
        try:
            Session = sessionmaker(bind=self.db.engine)
            session = Session()

            processed_file = ProcessedFile(
                file_hash=file_hash,
                report_file=report_file,
                status='processing',
                dmarc_report_id=None  # Will be set when processing completes
            )

            session.add(processed_file)
            session.commit()
            file_id = processed_file.id
            session.close()

            logger.info(f"Started processing file: {report_file} (processing_id={file_id})")
            return file_id

        except Exception as e:
            logger.error(f"Error starting file processing: {str(e)}")
            return 0

    def complete_file_processing(self, processing_id: int, dmarc_report_id: int):
        """Mark file processing as complete"""
        try:
            Session = sessionmaker(bind=self.db.engine)
            session = Session()

            processed_file = session.query(ProcessedFile).filter_by(id=processing_id).first()
            if processed_file:
                processed_file.status = 'done'
                processed_file.dmarc_report_id = dmarc_report_id
                session.commit()
                logger.info(f"Completed processing file: {processed_file.report_file} (dmarc_report_id={dmarc_report_id})")

            session.close()

        except Exception as e:
            logger.error(f"Error completing file processing: {str(e)}")

    def mark_file_as_error(self, processing_id: int, error_message: str = None):
        """Mark file processing as failed"""
        try:
            Session = sessionmaker(bind=self.db.engine)
            session = Session()

            processed_file = session.query(ProcessedFile).filter_by(id=processing_id).first()
            if processed_file:
                processed_file.status = 'error'
                session.commit()
                logger.error(f"Marked file as error: {processed_file.report_file}")

            session.close()

        except Exception as e:
            logger.error(f"Error marking file as error: {str(e)}")

    def delete_gcs_file(self, blob: storage.Blob):
        # Delete original file
        blob.delete()
        logger.info(f"Deleted file: {blob.name}.")

    def mark_file_as_duplicate(self, file_hash: str, report_file: str,
                               original_file_id: int):
        """Mark file as duplicate of existing file"""
        try:
            Session = sessionmaker(bind=self.db.engine)
            session = Session()

            duplicate_file = ProcessedFile(
                file_hash=file_hash,
                report_file=report_file,
                status='duplicate',
                duplicate_id=original_file_id,
                dmarc_report_id=None
            )

            session.add(duplicate_file)
            session.commit()
            session.close()

            logger.info(f"Marked file as duplicate: {report_file} (original_id={original_file_id})")

        except Exception as e:
            logger.error(f"Error marking file as duplicate: {str(e)}")

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

    def mark_file_as_processed(self, file_hash: str, dmarc_report_id: int, report_file: str, duplicate_id: int = None):
        """Mark a file as processed to avoid duplicate processing"""
        try:
            Session = sessionmaker(bind=self.db.engine)
            session = Session()

            processed_file = ProcessedFile(
                dmarc_report_id=dmarc_report_id,
                file_hash=file_hash,
                report_file=report_file,
                duplicate_id=duplicate_id
            )
            session.add(processed_file)
            session.commit()
            session.close()
            logger.info(f"Marked file as processed: {report_file} (hash={file_hash[:8]}... dmarc_report_id={dmarc_report_id})")
        except Exception as e:
            logger.error(f"Error marking file as processed: {str(e)}")
            raise

    def download_file_content(self, blob: storage.Blob) -> Optional[bytes]:
        """Download file content from GCS"""
        try:
            content = blob.download_as_bytes()
            logger.info(f"Downloaded file: {blob.name} ({len(content)} bytes)")
            return content
        except GoogleCloudError as e:
            logger.error(f"Error downloading file {blob.name}: {str(e)}")
            return None

    def determine_report_source(self, file_name: str, content: bytes) -> str:
        """Determine the report source based on file name or content"""
        file_name_lower = file_name.lower()

        # Simple heuristics based on file naming patterns
        if 'google' in file_name_lower:
            return 'Google'
        elif 'microsoft' in file_name_lower or 'outlook' in file_name_lower:
            return 'Microsoft'
        elif 'yahoo' in file_name_lower:
            return 'Yahoo'
        elif 'amazon' in file_name_lower:
            return 'Amazon'

        # Try to determine from XML content (basic check)
        try:
            content_str = content.decode('utf-8').lower()
            if 'google' in content_str:
                return 'Google'
            elif 'microsoft' in content_str or 'outlook' in content_str:
                return 'Microsoft'
            elif 'yahoo' in content_str:
                return 'Yahoo'
        except UnicodeDecodeError:
            pass

        # Default to 'Unknown' if we can't determine
        return 'Unknown'

    def process_file(self, blob: storage.Blob) -> bool:
        """Process a single DMARC report file with concurrent processing protection"""
        file_path = f"gs://{self.bucket_name}/{blob.name}"
        logger.info(f"Processing file: {file_path}")

        processing_id = 0
        try:
            # Download file content
            content = self.download_file_content(blob)
            if content is None:
                return False

            # Calculate file hash
            file_hash = calculate_file_hash(content)

            # Check processing status for concurrent access control
            action, existing_file_id = self.check_file_processing_status(file_hash, file_path)

            if action == 'skip':
                logger.info(f"File already processed, skipping and delete: {file_path} (hash: {file_hash[:8]}...)")
                self.delete_gcs_file(blob)
                return True
            elif action == 'processing':
                logger.info(f"File currently being processed by another instance, skipping: {file_path}")
                return True
            elif action == 'duplicate':
                # Mark as duplicate, move to processed
                self.mark_file_as_duplicate(file_hash, file_path, existing_file_id)
                self.move_file_to_processed(blob)
                logger.info(f"File marked as duplicate: {file_path} (original_id: {existing_file_id})")
                return True
            elif action == 'process':
                # Start processing - this creates the lock
                processing_id = self.start_file_processing(file_hash, file_path)
                if processing_id == 0:
                    logger.error(f"Failed to start processing lock for: {file_path}")
                    return False
            else:
                logger.error(f"Unknown action from file status check: {action}")
                return False

            # Determine report source
            report_source = self.determine_report_source(blob.name, content)

            # Validate file
            validation_result = self.validator.validate_file(content, file_path)
            if not validation_result.is_valid:
                logger.error(f"File validation failed for {file_path}: {validation_result.errors}")
                self.mark_file_as_error(processing_id, f"Validation failed: {validation_result.errors}")
                return False

            # Parse DMARC report (creates entries in dmarc_reports and dmarc_report_details tables)
            dmarc_report_id = self.parser.parse_and_store(content, file_path, report_source)
            if not dmarc_report_id:
                logger.error(f"Failed to parse DMARC report: {file_path}")
                self.mark_file_as_error(processing_id, "DMARC parsing failed")
                return False

            # Mark processing as complete
            self.complete_file_processing(processing_id, dmarc_report_id)

            # Move file to processed folder
            if self.move_file_to_processed(blob):
                logger.info(f"Successfully processed and moved file: {file_path} (dmarc_report_id: {dmarc_report_id})")
            else:
                logger.warning(f"File processed but failed to move to processed folder: {file_path}")

            return True

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")
            # Mark as error if we have a processing lock
            if processing_id > 0:
                self.mark_file_as_error(processing_id, str(e))
            return False

    def process_new_files(self):
        """Process all new DMARC report files in the bucket"""
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
                    if self.process_file(blob):
                        processed_count += 1
                    else:
                        failed_count += 1
                except Exception as e:
                    logger.error(f"Unexpected error processing file {blob.name}: {str(e)}")
                    failed_count += 1

            logger.info(f"GCS monitoring cycle complete. Processed: {processed_count}, Failed: {failed_count}")

        except Exception as e:
            logger.error(f"Error in GCS monitoring cycle: {str(e)}")
