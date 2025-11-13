from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.model_features import FeatureCatalog, SubfeatureCatalog, CustomerFeatureFlags


async def is_feature_enabled_for_customer(
    session: AsyncSession,
    *,
    customer_id: int,
    feature_key: Optional[str] = None,
    feature_id: Optional[int] = None,
    respect_is_active: bool = True,
) -> bool:
    """
    Is a FEATURE enabled for this customer?

    Precedence:
      1) Customer feature-level flag with sub_feature_id IS NULL (ALL sub-features)
      2) FeatureCatalog.default_enabled
      3) False

    Notes:
      - This does NOT check specific sub-feature overrides.
      - If `respect_is_active=True`, inactive features are treated as disabled.
    """
    # Resolve feature
    if feature_id is not None:
        res = await session.execute(
            select(FeatureCatalog).where(FeatureCatalog.id == feature_id)
        )
    elif feature_key is not None:
        res = await session.execute(
            select(FeatureCatalog).where(FeatureCatalog.key == feature_key)
        )
    else:
        return False

    feature = res.scalar_one_or_none()
    if feature is None:
        return False

    if respect_is_active and not feature.is_active:
        return False

    # 1) Feature-level (ALL) flag
    res = await session.execute(
        select(CustomerFeatureFlags.enabled)
        .where(
            CustomerFeatureFlags.customer_id == customer_id,
            CustomerFeatureFlags.feature_id == feature.id,
            CustomerFeatureFlags.sub_feature_id.is_(None),
        )
        .limit(1)
    )
    all_row = res.scalar_one_or_none()
    if all_row is not None:
        return bool(all_row)

    # 2) Feature default
    if feature.default_enabled:
        return True

    # 3) Default disabled
    return False


async def is_subfeature_enabled_for_customer(
    session: AsyncSession,
    *,
    customer_id: int,
    # identify by key or id (id takes precedence if both provided)
    feature_key: Optional[str] = None,
    subfeature_key: Optional[str] = None,
    feature_id: Optional[int] = None,
    subfeature_id: Optional[int] = None,
    respect_is_active: bool = True,
) -> bool:
    """
    Is a SUB-FEATURE enabled for this customer?

    Precedence:
      1) Customer-specific sub-feature flag (customer, feature, subfeature)
      2) Customer feature-level flag with sub_feature_id IS NULL (ALL sub-features)
      3) Default fallbacks:
         - SubfeatureCatalog.default_enabled
         - FeatureCatalog.default_enabled
      4) False

    Notes:
      - If `respect_is_active=True`, inactive features/subfeatures are treated as disabled.
      - Ensures the given subfeature belongs to the resolved feature.
    """
    # Resolve feature
    if feature_id is not None:
        res = await session.execute(
            select(FeatureCatalog).where(FeatureCatalog.id == feature_id)
        )
    elif feature_key is not None:
        res = await session.execute(
            select(FeatureCatalog).where(FeatureCatalog.key == feature_key)
        )
    else:
        return False

    feature = res.scalar_one_or_none()
    if feature is None:
        return False

    # Resolve subfeature (and ensure it belongs to the feature)
    if subfeature_id is not None:
        res = await session.execute(
            select(SubfeatureCatalog).where(
                SubfeatureCatalog.id == subfeature_id,
                SubfeatureCatalog.feature_id == feature.id,
            )
        )
    elif subfeature_key is not None:
        res = await session.execute(
            select(SubfeatureCatalog).where(
                SubfeatureCatalog.feature_id == feature.id,
                SubfeatureCatalog.key == subfeature_key,
            )
        )
    else:
        # If no subfeature provided, delegate to feature-level check
        return await is_feature_enabled_for_customer(
            session,
            customer_id=customer_id,
            feature_id=feature.id,
            respect_is_active=respect_is_active,
        )

    subf = res.scalar_one_or_none()
    if subf is None:
        return False

    if respect_is_active:
        if not feature.is_active or not subf.is_active:
            return False

    # 1) Specific sub-feature flag
    res = await session.execute(
        select(CustomerFeatureFlags.enabled).where(
            CustomerFeatureFlags.customer_id == customer_id,
            CustomerFeatureFlags.feature_id == feature.id,
            CustomerFeatureFlags.sub_feature_id == subf.id,
        ).limit(1)
    )
    specific = res.scalar_one_or_none()
    if specific is not None:
        return bool(specific)

    # 2) Feature-level (ALL) flag
    res = await session.execute(
        select(CustomerFeatureFlags.enabled).where(
            CustomerFeatureFlags.customer_id == customer_id,
            CustomerFeatureFlags.feature_id == feature.id,
            CustomerFeatureFlags.sub_feature_id.is_(None),
        ).limit(1)
    )
    all_row = res.scalar_one_or_none()
    if all_row is not None:
        return bool(all_row)

    # 3) Defaults
    if subf.default_enabled:
        return True
    if feature.default_enabled:
        return True

    # 4) Default disabled
    return False
