from __future__ import annotations

import hashlib

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from vulnops.api.deps import get_db
from vulnops.api.schemas import ProblemDetails, SourceSnapshotResponse
from vulnops.auth.dependencies import (
    AuthorizationError,
    authorize_capability,
    get_principal,
    require_organization,
)
from vulnops.auth.models import Principal
from vulnops.db.models.source_snapshot import SourceSnapshot
from vulnops.evidence.raw_store import read_raw_bytes
from vulnops.sbom.models import SbomDocument

router = APIRouter(
    tags=["evidence"],
    responses={
        401: {"model": ProblemDetails, "description": "Authentication required"},
        403: {"model": ProblemDetails, "description": "Insufficient permission"},
    },
)


def _snapshot_metadata(snapshot: SourceSnapshot, *, include_object_uri: bool) -> dict:
    payload = {
        "id": snapshot.id,
        "organization_id": snapshot.organization_id,
        "source": snapshot.source,
        "source_record_id": snapshot.source_record_id,
        "content_sha256": snapshot.content_sha256,
        "content_size": snapshot.content_size,
        "validation_state": snapshot.validation_state,
        "retrieved_at": snapshot.retrieved_at.isoformat(),
        "created_at": snapshot.created_at.isoformat(),
    }
    if include_object_uri:
        payload["object_uri"] = snapshot.object_uri
    return payload


def _load_snapshot(db: Session, org_id: str, snapshot_id: str) -> SourceSnapshot:
    snapshot = (
        db.execute(
            select(SourceSnapshot).where(
                SourceSnapshot.id == snapshot_id,
                SourceSnapshot.organization_id == org_id,
            )
        )
        .scalars()
        .first()
    )
    if not snapshot:
        raise AuthorizationError("resource_not_found")
    return snapshot


def _load_sbom(db: Session, org_id: str, sbom_id: str) -> SbomDocument:
    doc = (
        db.execute(
            select(SbomDocument).where(
                SbomDocument.id == sbom_id,
                SbomDocument.organization_id == org_id,
            )
        )
        .scalars()
        .first()
    )
    if not doc:
        raise AuthorizationError("resource_not_found")
    return doc


def _raw_response(raw_bytes: bytes, digest: str) -> Response:
    if hashlib.sha256(raw_bytes).hexdigest() != digest:
        raise AuthorizationError("resource_not_found")
    return Response(
        content=raw_bytes,
        media_type="application/json",
        headers={
            "Cache-Control": "private, no-store",
            "Content-Disposition": f'attachment; filename="{digest}.json"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get(
    "/organizations/{org_id}/source-snapshots/{snapshot_id}",
    response_model=SourceSnapshotResponse,
    response_model_exclude_none=True,
    dependencies=[Depends(require_organization)],
)
async def get_source_snapshot(
    org_id: str,
    snapshot_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    snapshot = _load_snapshot(db, org_id, snapshot_id)
    authorize_capability(request, principal, "provenance:read")
    include_uri = principal.has_capability("evidence:raw:read")
    return _snapshot_metadata(snapshot, include_object_uri=include_uri)


@router.get(
    "/organizations/{org_id}/source-snapshots/{snapshot_id}/raw",
    dependencies=[Depends(require_organization)],
)
async def get_source_snapshot_raw(
    org_id: str,
    snapshot_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    snapshot = _load_snapshot(db, org_id, snapshot_id)
    authorize_capability(request, principal, "evidence:raw:read")
    raw_bytes = read_raw_bytes(org_id, snapshot.content_sha256, snapshot.object_uri)
    if raw_bytes is None:
        raise AuthorizationError("resource_not_found")
    return _raw_response(raw_bytes, snapshot.content_sha256)


@router.get(
    "/organizations/{org_id}/sboms/{sbom_id}/raw",
    dependencies=[Depends(require_organization)],
)
async def get_sbom_raw(
    org_id: str,
    sbom_id: str,
    request: Request,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    doc = _load_sbom(db, org_id, sbom_id)
    authorize_capability(request, principal, "evidence:raw:read")
    raw_bytes = read_raw_bytes(org_id, doc.content_sha256, doc.object_uri)
    if raw_bytes is None:
        raise AuthorizationError("resource_not_found")
    return _raw_response(raw_bytes, doc.content_sha256)
