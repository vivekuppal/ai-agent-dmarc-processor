import logging
import os
from typing import Optional, Dict, List, NamedTuple
from abc import ABC, abstractmethod
import hashlib
import xml.etree.ElementTree as ET
try:
    from lxml import etree
except ImportError:
    etree = None

logger = logging.getLogger(__name__)


class ValidationResult(NamedTuple):
    """Result of file validation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]


class BaseValidator(ABC):
    """Abstract base class for file validators"""

    @abstractmethod
    def validate(self, content: bytes, file_path: str) -> ValidationResult:
        """Validate file content"""
        pass

    @property
    @abstractmethod
    def validator_name(self) -> str:
        """Name of the validator"""
        pass


class XSDValidator(BaseValidator):
    """Validate DMARC XML files against XSD schema"""

    def __init__(self):
        self.xsd_path = os.path.join(os.path.dirname(__file__), '..', 'schemas', 'dmarc.xsd')
        self.schema = None
        self._load_schema()

    def _load_schema(self):
        """Load XSD schema for validation"""
        if etree is None:
            logger.warning("lxml not available, XSD validation disabled")
            return

        try:
            if os.path.exists(self.xsd_path):
                with open(self.xsd_path, 'r') as schema_file:
                    schema_doc = etree.parse(schema_file)
                    self.schema = etree.XMLSchema(schema_doc)
                    logger.info("XSD schema loaded successfully")
            else:
                logger.warning(f"XSD schema file not found: {self.xsd_path}")
        except Exception as e:
            logger.error(f"Error loading XSD schema: {str(e)}")

    def validate(self, content: bytes, file_path: str) -> ValidationResult:
        """Validate XML content against XSD schema"""
        errors = []
        warnings = []

        if etree is None:
            warnings.append("lxml not available, skipping XSD validation")
            return ValidationResult(True, errors, warnings)

        try:
            # Parse XML
            xml_doc = etree.fromstring(content)

            # Validate against schema if available
            if self.schema:
                if not self.schema.validate(xml_doc):
                    for error in self.schema.error_log:
                        error_msg = error.message.lower()
                        # Ignore namespace-related errors
                        if any(keyword in error_msg for keyword in ['namespace', 'global declaration', 'validation root']):
                            warnings.append(f"XSD namespace warning at line {error.line}: {error.message}")
                        else:
                            errors.append(f"XSD validation error at line {error.line}: {error.message}")
                else:
                    logger.debug(f"XSD validation passed for {file_path}")
            else:
                warnings.append("XSD schema not available, skipping schema validation")

        except etree.XMLSyntaxError as e:
            errors.append(f"XML syntax error: {str(e)}")
        except Exception as e:
            errors.append(f"Unexpected validation error: {str(e)}")

        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings)

    @property
    def validator_name(self) -> str:
        return "XSD Validator"


class DuplicateFileValidator(BaseValidator):
    """Validate files against duplicate processing"""

    def __init__(self, db):
        self.db = db

    def validate(self, content: bytes, file_path: str) -> ValidationResult:
        """Check if file has already been processed based on hash"""
        errors = []
        warnings = []

        try:
            # Calculate file hash
            file_hash = hashlib.sha256(content).hexdigest()

            # Import here to avoid circular imports
            from app.models import ProcessedFile
            from sqlalchemy.orm import sessionmaker

            # Check if file hash exists in database
            Session = sessionmaker(bind=self.db.engine)
            session = Session()
            existing_report = session.query(ProcessedFile).filter_by(file_hash=file_hash).first()
            session.close()

            if existing_report:
                errors.append(f"File already processed with hash: {file_hash[:16]}...")
            else:
                logger.debug(f"File hash validation passed for {file_path}")

        except Exception as e:
            errors.append(f"Error checking for duplicate file: {str(e)}")

        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings)

    @property
    def validator_name(self) -> str:
        return "Duplicate File Validator"


class XMLWellFormednessValidator(BaseValidator):
    """Validate XML well-formedness"""

    def validate(self, content: bytes, file_path: str) -> ValidationResult:
        """Check if XML is well-formed"""
        errors = []
        warnings = []

        try:
            # Try to parse XML
            ET.fromstring(content)
            logger.debug(f"XML well-formedness validation passed for {file_path}")
        except ET.ParseError as e:
            errors.append(f"XML is not well-formed: {str(e)}")
        except Exception as e:
            errors.append(f"Unexpected error validating XML: {str(e)}")

        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings)

    @property
    def validator_name(self) -> str:
        return "XML Well-formedness Validator"


class DMARCContentValidator(BaseValidator):
    """Validate DMARC-specific content requirements (namespace-safe)."""

    def _detect_ns(self, root: ET.Element) -> Dict[str, str]:
        """
        If the document uses a default namespace (e.g., urn:ietf:params:xml:ns:dmarc-2.0),
        return {'d': '<ns-uri>'}. Otherwise return {}.
        """
        tag = root.tag or ""
        if tag.startswith("{"):
            uri = tag[1:].split("}", 1)[0]
            return {"d": uri}
        return {}

    def _find_any(self, elem: ET.Element, local: str, ns: Dict[str, str]) -> Optional[ET.Element]:
        """
        Try to find an element named `local` under `elem` with and without namespace.
        Works whether the doc is namespaced or not.
        """
        if ns:
            hit = elem.find(f".//d:{local}", ns)
            if hit is not None:
                return hit
        return elem.find(f".//{local}")

    def validate(self, content: bytes, file_path: str) -> ValidationResult:
        errors: List[str] = []
        warnings: List[str] = []

        try:
            root = ET.fromstring(content)
            ns = self._detect_ns(root)

            # Required DMARC elements per aggregate schema
            required_elements = ["report_metadata", "policy_published", "record"]

            for name in required_elements:
                if self._find_any(root, name, ns) is None:
                    errors.append(f"Missing required DMARC element: {name}")

            # Check report metadata
            report_metadata = self._find_any(root, "report_metadata", ns)
            if report_metadata is not None:
                if self._find_any(report_metadata, "org_name", ns) is None:
                    warnings.append("Missing org_name in report_metadata")
                if self._find_any(report_metadata, "email", ns) is None:
                    warnings.append("Missing email in report_metadata")

            logger.debug(f"DMARC content validation completed for {file_path}")

        except ET.ParseError as e:
            errors.append(f"Cannot validate DMARC content due to XML parsing error: {str(e)}")
        except Exception as e:
            errors.append(f"Unexpected error validating DMARC content: {str(e)}")

        is_valid = len(errors) == 0
        return ValidationResult(is_valid, errors, warnings)

    @property
    def validator_name(self) -> str:
        return "DMARC Content Validator"


class ValidationFramework:
    """Extensible framework for file validation"""

    def __init__(self):
        self.validators = []
        self._setup_default_validators()

    def _setup_default_validators(self):
        """Setup default validators"""
        # Add default validators
        self.add_validator(XMLWellFormednessValidator())
        # XSD validation removed - real-world DMARC files don't conform to strict schema
        # self.add_validator(XSDValidator())
        self.add_validator(DMARCContentValidator())
        # Note: DuplicateFileValidator is added separately as it needs database access

    def add_validator(self, validator: BaseValidator):
        """Add a validator to the framework"""
        self.validators.append(validator)
        logger.info(f"Added validator: {validator.validator_name}")

    def remove_validator(self, validator_name: str):
        """Remove a validator by name"""
        self.validators = [v for v in self.validators if v.validator_name != validator_name]
        logger.info(f"Removed validator: {validator_name}")

    def validate_file(self, content: bytes, file_path: str) -> ValidationResult:
        """Run all validators on a file"""
        all_errors = []
        all_warnings = []

        logger.info(f"Running {len(self.validators)} validators on {file_path}")

        for validator in self.validators:
            try:
                result = validator.validate(content, file_path)
                all_errors.extend(result.errors)
                all_warnings.extend(result.warnings)

                if result.errors:
                    logger.warning(f"{validator.validator_name} found errors: {result.errors}")
                else:
                    logger.debug(f"{validator.validator_name} passed")

            except Exception as e:
                error_msg = f"Validator {validator.validator_name} failed with error: {str(e)}"
                all_errors.append(error_msg)
                logger.error(error_msg)

        is_valid = len(all_errors) == 0

        if all_warnings:
            logger.info(f"Validation warnings for {file_path}: {all_warnings}")

        return ValidationResult(is_valid, all_errors, all_warnings)

    def get_validator_names(self) -> List[str]:
        """Get names of all registered validators"""
        return [v.validator_name for v in self.validators]
