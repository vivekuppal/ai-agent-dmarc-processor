from sqlalchemy import (
    Column, Integer, String, Text, Boolean,
    DateTime, ForeignKey, UniqueConstraint, func
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class FeatureCatalog(Base):
    """Catalog of top-level features (e.g., EMAILS, ALERTS, DNS_MONITORING)."""
    __tablename__ = 'feature_catalog'

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True),
                        server_default=func.now(),
                        nullable=False)
    modified_at = Column(DateTime(timezone=True),
                         server_default=func.now(),
                         onupdate=func.now(),
                         nullable=False)

    key = Column(String(255), nullable=False, unique=True, index=True)  # e.g., 'EMAILS'
    name = Column(String(255), nullable=False)                          # e.g., 'Emails'
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, server_default='true')
    default_enabled = Column(Boolean, nullable=False, server_default='false')

    # Relationships
    subfeatures = relationship(
        "SubfeatureCatalog",
        back_populates="feature",
        cascade="all, delete-orphan"
    )
    customer_flags = relationship(
        "CustomerFeatureFlags",
        back_populates="feature",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        """ String representation of the FeatureCatalog instance."""
        return (f"<FeatureCatalog(id={self.id}, key='{self.key}', name='{self.name}', "
                f"is_active={self.is_active}, "
                f"default_enabled={self.default_enabled})>")

    def to_dict(self):
        """ Convert the FeatureCatalog instance to a dictionary."""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'modified_at': self.modified_at.isoformat() if self.modified_at else None,
            'key': self.key,
            'name': self.name,
            'description': self.description,
            'is_active': bool(self.is_active),
            'default_enabled': bool(self.default_enabled),
        }


class SubfeatureCatalog(Base):
    """Catalog of sub-features that belong to a feature (e.g., WEEKLY_DMARC_DIGEST under EMAILS)."""
    __tablename__ = 'subfeature_catalog'
    __table_args__ = (
        UniqueConstraint('feature_id', 'key', name='uq_subfeature_feature_key'),
    )

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True),
                        server_default=func.now(),
                        nullable=False)
    modified_at = Column(DateTime(timezone=True),
                         server_default=func.now(),
                         onupdate=func.now(),
                         nullable=False)

    feature_id = Column(Integer,
                        ForeignKey('feature_catalog.id', ondelete='CASCADE'),
                        nullable=False,
                        index=True)

    key = Column(String(255), nullable=False)   # unique within feature_id
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, server_default='true')
    default_enabled = Column(Boolean, nullable=False, server_default='false')

    # Relationships
    feature = relationship("FeatureCatalog", back_populates="subfeatures")
    customer_flags = relationship(
        "CustomerFeatureFlags",
        back_populates="sub_feature",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        """ String representation of the FeatureCatalog instance."""
        return (f"<SubfeatureCatalog(id={self.id}, feature_id={self.feature_id}, "
                f"key='{self.key}', name='{self.name}',"
                f"is_active={self.is_active}, "
                F"default_enabled={self.default_enabled})>")

    def to_dict(self):
        """ Convert the FeatureCatalog instance to a dictionary."""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'modified_at': self.modified_at.isoformat() if self.modified_at else None,
            'feature_id': self.feature_id,
            'key': self.key,
            'name': self.name,
            'description': self.description,
            'is_active': bool(self.is_active),
            'default_enabled': bool(self.default_enabled),
        }


class CustomerFeatureFlags(Base):
    """
    Per-customer feature flags.
    Use sub_feature_id = NULL to represent the 'ALL sub-features' row for a feature.
    Specific sub-feature rows override the ALL row. If no row exists, default is disabled.
    """
    __tablename__ = 'customer_feature_flags'
    __table_args__ = (
        UniqueConstraint('customer_id', 'feature_id', 'sub_feature_id',
                         name='uq_cff_customer_feature_sub'),
    )

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True),
                        server_default=func.now(),
                        nullable=False)
    modified_at = Column(DateTime(timezone=True),
                         server_default=func.now(),
                         onupdate=func.now(),
                         nullable=False)
    modified_by = Column(Integer, nullable=False)  # user ID who made the last change

    customer_id = Column(Integer,
                         ForeignKey('customers.id', ondelete='CASCADE'),
                         nullable=False,
                         index=True)

    feature_id = Column(Integer,
                        ForeignKey('feature_catalog.id', ondelete='CASCADE'),
                        nullable=False,
                        index=True)

    sub_feature_id = Column(Integer,
                            ForeignKey('subfeature_catalog.id', ondelete='CASCADE'),
                            nullable=True,
                            index=True)  # NULL => applies to ALL sub-features in the feature

    enabled = Column(Boolean, nullable=False)  # explicit TRUE/FALSE

    # Relationships
    feature = relationship("FeatureCatalog", back_populates="customer_flags")
    sub_feature = relationship("SubfeatureCatalog", back_populates="customer_flags")
    # NOTE: Add this on your Customer model:
    # feature_flags = relationship("CustomerFeatureFlags", back_populates="customer", cascade="all, delete-orphan")
    customer = relationship("Customer", back_populates="feature_flags")

    def __repr__(self):
        """ String representation of the FeatureCatalog instance."""
        return (f"<CustomerFeatureFlags(id={self.id}, customer_id={self.customer_id}, "
                f"feature_id={self.feature_id}, sub_feature_id={self.sub_feature_id}, "
                f"enabled={self.enabled})>")

    def to_dict(self):
        """ Convert the FeatureCatalog instance to a dictionary."""
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'modified_at': self.modified_at.isoformat() if self.modified_at else None,
            'customer_id': self.customer_id,
            'feature_id': self.feature_id,
            'sub_feature_id': self.sub_feature_id,
            'enabled': bool(self.enabled),
        }




