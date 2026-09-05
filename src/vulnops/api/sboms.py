from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy.orm import Session

from vulnops.api.deps import get_db
from vulnops.sbom.service import SBOMService

router = APIRouter(tags=["sboms"])


@router.post("/organizations/{org_id}/sboms", status_code=201)
async def submit_sbom(
    org_id: str,
    request: Request,
    db: Session = Depends(get_db),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    content_type: str | None = Header(default=None, alias="Content-Type"),
):
    # Read raw body as JSON - support both CycloneDX and SPDX, with correct content-type handling
    try:
        data: Any = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    if not isinstance(data, dict):
        raise HTTPException(status_code=422, detail="Invalid SBOM: expected JSON object")

    # Basic content-type check but allow vendors to send application/json etc.
    # The service will validate format

    correlation_id = request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID") or str(uuid.uuid4())

    svc = SBOMService(db)
    try:
        result = svc.ingest(
            data,
            organization_id=org_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
        )
    except ValueError as ve:
        # Validation failure -> 422 Problem Details compatible
        raise HTTPException(status_code=422, detail=str(ve))
    except Exception as e:
        # Unexpected
        raise HTTPException(status_code=500, detail="Failed to process SBOM")

    # Ensure headers for tracing
    return result


@router.get("/organizations/{org_id}/sboms/{sbom_id}")
async def get_sbom(org_id: str, sbom_id: str, db: Session = Depends(get_db)):
    from vulnops.sbom.models import SbomDocument
    from sqlalchemy import select

    doc = db.execute(select(SbomDocument).where(SbomDocument.id == sbom_id, SbomDocument.organization_id == org_id)).scalars().first()
    if not doc:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return {
        "id": doc.id,
        "organization_id": doc.organization_id,
        "format": doc.format,
        "spec_version": doc.spec_version,
        "content_sha256": doc.content_sha256,
        "object_uri": doc.object_uri,
        "created_at": doc.created_at.isoformat(),
    }
