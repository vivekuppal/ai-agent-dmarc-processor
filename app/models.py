import enum
from sqlalchemy import (
    Column,
    Integer,
    BigInteger,
    String,
    DateTime,
    Text,
    Enum as SQLEnum,
    ForeignKey,
    func
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

# Create base class for models
Base = declarative_base()


class EmailStatus(enum.Enum):
    SUCCESS = "Success"
    FAILURE = "Failure"
    AUTH_FAILURE = "Auth Failure"


class EmailStatusReason(enum.Enum):
    SUCCESS = "Success"
    SPAM = "Spam"
    NOT_DELIVERED = "Not Delivered"
    SPF_FAILED = "SPF_FAILED"
    DKIM_FAILED = "DKIM_FAILED"
    SPF_AUTH_FAILED = "SPF_AUTH_FAILED"
    DKIM_AUTH_FAILED = "DKIM_AUTH_FAILED"
    SPF_AND_DKIM_FAILED = "SPF_AND_DKIM_FAILED"
    MIXED = "Mixed"


# ---------------------------
# ENUMS for type and result
# ---------------------------
class AuthType(enum.Enum):
    SPF = "spf"
    DKIM = "dkim"


class AuthResult(enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    POLICY = "policy"

    @classmethod
    def from_str(cls, value: str) -> "AuthResult":
        """
        Normalize any SPF/DKIM result string to AuthResult.
        Accepts mixed case and common variants (underscores, hyphens, spaces).
        Falls back to NONE for unknowns.
        """
        if not value:
            return cls.NONE
        k = value.strip().lower().replace("_", "").replace("-", "").replace(" ", "")

        # canonical map (all keys already normalized as above)
        mapping = {
            "pass": cls.PASS,
            "fail": cls.FAIL,
            "softfail": cls.SOFTFAIL,
            "neutral": cls.NEUTRAL,
            "none": cls.NONE,
            "temperror": cls.TEMPERROR,
            "temperr": cls.TEMPERROR,
            "temporaryerror": cls.TEMPERROR,
            "permerror": cls.PERMERROR,
            "permerr": cls.PERMERROR,
            "permanenterror": cls.PERMERROR,
            "policy": cls.POLICY,
            # common oddballs → reasonable defaults
            "unknown": cls.NONE,
        }
        return mapping.get(k, cls.NONE)


class Domain(Base):
    """Model for storing domain and customer relationships"""
    __tablename__ = 'domains'

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True),
                        server_default=func.now(),
                        nullable=False)
    modified_at = Column(DateTime(timezone=True),
                         server_default=func.now(),
                         onupdate=func.now(),
                         nullable=False)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    customer_id = Column(Integer, nullable=False, index=True)

    # Note: Relationship to DMARC reports handled manually via customer_id lookup

    def __repr__(self):
        return f"<Domain(id={self.id}, domain='{self.domain}', customer_id={self.customer_id})>"

    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'modified_at': self.modified_at.isoformat() if self.modified_at else None,
            'domain': self.domain,
            'customer_id': self.customer_id
        }


class DMARCReport(Base):
    """Model for storing DMARC report metadata"""
    __tablename__ = 'dmarc_reports'

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    modified_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    report_source = Column(String(255), nullable=False, index=True)  # E.g. Google, Microsoft, Yahoo
    report_start_date = Column(DateTime(timezone=True), nullable=False)
    report_end_date = Column(DateTime(timezone=True), nullable=False)
    report_id = Column(String(255), nullable=False, index=True)
    policy_domain = Column(String(255), nullable=False, index=True)
    customer_id = Column(Integer, nullable=True, index=True)  # FK reference to domains.customer_id
    adkim = Column(String(10), nullable=True)  # DKIM alignment mode
    aspf = Column(String(10), nullable=True)  # SPF alignment mode
    p = Column(String(20), nullable=True)  # Policy for domain
    sp = Column(String(20), nullable=True)  # Policy for subdomains
    pct = Column(Integer, nullable=True)  # Percentage of messages to which policy applies
    np = Column(String(20), nullable=True)  # Policy for non-existent subdomains
    report_file = Column(Text, nullable=False)  # Complete link to file in GCS bucket

    # Relationships
    details = relationship("DMARCReportDetail", back_populates="report", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<DMARCReport(id={self.id}, policy_domain='{self.policy_domain}', report_id='{self.report_id}')>"

    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'modified_at': self.modified_at.isoformat() if self.modified_at else None,
            'report_source': self.report_source,
            'report_start_date': self.report_start_date.isoformat() if self.report_start_date else None,
            'report_end_date': self.report_end_date.isoformat() if self.report_end_date else None,
            'report_id': self.report_id,
            'policy_domain': self.policy_domain,
            'customer_id': self.customer_id,
            'adkim': self.adkim,
            'aspf': self.aspf,
            'p': self.p,
            'sp': self.sp,
            'pct': self.pct,
            'np': self.np,
            'report_file': self.report_file
        }


class DMARCReportDetail(Base):
    """Model for storing individual DMARC report record details"""
    __tablename__ = 'dmarc_report_details'

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    modified_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    dmarc_report_id = Column(Integer, ForeignKey('dmarc_reports.id'), nullable=False, index=True)
    email_status = Column(SQLEnum(EmailStatus), nullable=False, index=True)
    email_status_reason = Column(SQLEnum(EmailStatusReason), nullable=False)
    email_count = Column(Integer, nullable=False, default=0)
    source_ip = Column(String(45), nullable=True)  # IPv4 (15) or IPv6 (39) + buffer
    hostname = Column(String(255), nullable=True)  # Hostname for the IP
    from_domain = Column(String(255), nullable=True)  # header_from domain
    classification = Column(String(64), nullable=True)  # classification e.g. based on known forwarders
    to_domain = Column(String(255), nullable=True)  # envelope_to domain

    # Relationship back to parent report
    report = relationship("DMARCReport", back_populates="details")

    def __repr__(self):
        return f"<DMARCReportDetail(id={self.id}, dmarc_report_id={self.dmarc_report_id}, email_status='{self.email_status}', email_count={self.email_count})>"

    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'modified_at': self.modified_at.isoformat() if self.modified_at else None,
            'dmarc_report_id': self.dmarc_report_id,
            'email_status': self.email_status.value if self.email_status else None,
            'email_status_reason': self.email_status_reason.value if self.email_status_reason else None,
            'email_count': self.email_count,
            'source_ip': self.source_ip,
            'hostname': self.hostname,
            'from_domain': self.from_domain,
            'classification': self.classification,
            'to_domain': self.to_domain
        }


class ProcessedFile(Base):
    """Model for tracking processed DMARC report files to prevent duplicates"""
    __tablename__ = 'processed_file'

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    modified_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    dmarc_report_id = Column(Integer, ForeignKey('dmarc_reports.id'), nullable=True, index=True)  # Nullable for processing/error states
    file_hash = Column(String(64), nullable=False, unique=True, index=True)  # SHA256 hash
    report_file = Column(Text, nullable=False)  # Complete path to processed file
    duplicate_id = Column(Integer, ForeignKey('processed_file.id'), nullable=True, index=True)  # Self reference
    status = Column(String(20), nullable=False, default='done', index=True)  # processing, done, error, duplicate

    # Relationships
    report = relationship("DMARCReport", backref="processed_file")
    duplicate_of = relationship("ProcessedFile", remote_side=[id], backref="duplicates")

    def __repr__(self):
        return f"<ProcessedFile(id={self.id}, dmarc_report_id={self.dmarc_report_id}, file_hash='{self.file_hash[:8]}...')>"

    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'modified_at': self.modified_at.isoformat() if self.modified_at else None,
            'dmarc_report_id': self.dmarc_report_id,
            'file_hash': self.file_hash,
            'report_file': self.report_file,
            'duplicate_id': self.duplicate_id,
            'status': self.status
        }


# ensure your AuthType also has lowercase .value (e.g., "spf", "dkim")
class DmarcReportAuthDetail(Base):
    __tablename__ = 'dmarc_report_auth_details'

    id = Column(BigInteger, primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    modified_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    dmarc_report_id = Column(BigInteger, ForeignKey('dmarc_reports.id', ondelete='CASCADE'), nullable=False)

    # Tell SQLAlchemy to use enum.value (not enum.name)
    type = Column(
        SQLEnum(
            AuthType,
            name="auth_type",
            values_callable=lambda enum_cls: [e.value for e in enum_cls],
            native_enum=True,          # default on PG, but explicit is fine
            validate_strings=True
        ),
        nullable=False
    )

    domain = Column(String(512))
    selector = Column(String(256))

    result = Column(
        SQLEnum(
            AuthResult,
            name="auth_result",
            values_callable=lambda enum_cls: [e.value for e in enum_cls],
            native_enum=True,
            validate_strings=True
        ),
        nullable=False
    )

    count = Column(Integer, nullable=False, default=1)

    def __repr__(self):
        return (
            f"<DmarcReportAuthDetail(id={self.id}, dmarc_report_id={self.dmarc_report_id}, "
            f"type='{self.type}', domain='{self.domain}', result='{self.result}', count={self.count})>"
        )

    def to_dict(self):
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'modified_at': self.modified_at.isoformat() if self.modified_at else None,
            'dmarc_report_id': self.dmarc_report_id,
            # use .value so you get 'spf'/'dkim' not AuthType.SPF, and 'pass' etc.
            'type': self.type.value if self.type else None,
            'domain': self.domain,
            'selector': self.selector,
            'result': self.result.value if self.result else None,
            'count': self.count
        }

