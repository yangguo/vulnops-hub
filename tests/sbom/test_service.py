from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import vulnops.assets.models  # noqa: F401
import vulnops.sbom.models  # noqa: F401
from vulnops.assets.models import Asset, AssetAlias
from vulnops.db import Base
from vulnops.sbom.models import ComponentOccurrence
from vulnops.sbom.service import SBOMService


def _session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _bom(hostname: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "properties": [{"name": "vulnops:asset.hostname", "value": hostname}]
        },
        "components": [
            {
                "type": "library",
                "name": "jquery",
                "version": "3.3.9",
                "purl": "pkg:npm/jquery@3.3.9",
            }
        ],
    }


def test_ingest_binds_occurrence_to_declared_asset_hostname(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db = _session()
    db.add(
        Asset(
            id="ast_m2_vulnerable",
            name="m2-vulnerable-web-01",
            organization_id="org-m2",
            type="host",
        )
    )
    db.add(
        AssetAlias(
            id="alias_m2_vulnerable",
            asset_id="ast_m2_vulnerable",
            namespace="hostname",
            value="m2-vulnerable-web-01",
            organization_id="org-m2",
        )
    )
    db.commit()

    result = SBOMService(db).ingest(_bom("m2-vulnerable-web-01"), "org-m2")

    occurrence = db.query(ComponentOccurrence).filter_by(sbom_id=result["sbom_id"]).one()
    assert occurrence.asset_id == "ast_m2_vulnerable"


def test_ingest_does_not_create_or_guess_unknown_asset_hostname(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    db = _session()

    result = SBOMService(db).ingest(_bom("m2-unknown-web-01"), "org-m2")

    occurrence = db.query(ComponentOccurrence).filter_by(sbom_id=result["sbom_id"]).one()
    assert occurrence.asset_id is None
    assert db.query(Asset).count() == 0
