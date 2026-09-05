from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulnops.assets.models import Asset, AssetAlias
from vulnops.assets.reconciliation import AssetService
from vulnops.db import Base


def _engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    # Import models to register
    import vulnops.assets.models
    import vulnops.sbom.models  # noqa: F401

    Base.metadata.create_all(bind=eng)
    return eng


def _session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


def test_same_hostname_from_two_live_assets_is_ambiguous():
    engine = _engine()
    Session = _session_factory(engine)
    session = Session()
    svc = AssetService(session)

    # Create two live assets with different IDs
    a1 = Asset(
        id="ast_01",
        name="api-01-a",
        type="host",
        status="active",
        criticality="high",
        organization_id="org1",
    )
    a2 = Asset(
        id="ast_02",
        name="api-01-b",
        type="host",
        status="active",
        criticality="high",
        organization_id="org1",
    )
    session.add_all([a1, a2])
    session.commit()

    # Add same hostname alias to both assets -> collision
    alias1 = AssetAlias(
        asset_id="ast_01", namespace="hostname", value="api-01", organization_id="org1"
    )
    alias2 = AssetAlias(
        asset_id="ast_02", namespace="hostname", value="api-01", organization_id="org1"
    )
    session.add_all([alias1, alias2])
    session.commit()

    result = svc.reconcile_alias("hostname", "api-01", organization_id="org1")
    assert result.status == "ambiguous"
    assert result.asset_id is None
    assert "collision" in result.reason.lower() or "ambiguous" in result.reason.lower()
    session.close()


def test_unique_alias_resolves_to_single_asset():
    engine = _engine()
    Session = _session_factory(engine)
    session = Session()
    svc = AssetService(session)

    a1 = Asset(
        id="ast_10",
        name="web-01",
        type="host",
        status="active",
        criticality="medium",
        organization_id="org1",
    )
    session.add(a1)
    session.commit()
    alias = AssetAlias(
        asset_id="ast_10", namespace="hostname", value="web-01", organization_id="org1"
    )
    session.add(alias)
    session.commit()

    result = svc.reconcile_alias("hostname", "web-01", organization_id="org1")
    assert result.status == "resolved"
    assert result.asset_id == "ast_10"
    session.close()


def test_ip_alias_is_not_long_lived_identity():
    # IP is observation/alias, not canonical ID - ambiguous if not strong identity
    engine = _engine()
    Session = _session_factory(engine)
    session = Session()
    svc = AssetService(session)

    result = svc.reconcile_alias("ip", "10.0.0.1", organization_id="org1")
    # When no strong identity, should be candidate/not_found, not auto-create
    assert result.status in ("not_found", "candidate", "ambiguous")
    assert result.asset_id is None
    session.close()


def test_strong_identity_arn_resolves_uniquely():
    engine = _engine()
    Session = _session_factory(engine)
    session = Session()
    svc = AssetService(session)

    a1 = Asset(
        id="ast_arn1",
        name="my-bucket",
        type="cloud_resource",
        status="active",
        criticality="high",
        organization_id="org1",
    )
    session.add(a1)
    session.commit()
    alias = AssetAlias(
        asset_id="ast_arn1", namespace="arn", value="arn:aws:s3:::my-bucket", organization_id="org1"
    )
    session.add(alias)
    session.commit()

    result = svc.reconcile_alias("arn", "arn:aws:s3:::my-bucket", organization_id="org1")
    assert result.status == "resolved"
    assert result.asset_id == "ast_arn1"
    session.close()
