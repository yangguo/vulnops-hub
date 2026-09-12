# Raw evidence access

Raw payloads (SBOM JSON, adapter snapshot bytes) are stored separately from case
workflow metadata. Authorization uses explicit capabilities and organization
scope; the API never serves raw bytes from unauthenticated routes or from
metadata endpoints that only require `sbom:read` / `provenance:read`.

## Endpoints

| Method and path | Capability | Notes |
| --- | --- | --- |
| `GET /api/v1/organizations/{org_id}/sboms/{sbom_id}` | `sbom:read` | Metadata only; `object_uri` is omitted unless the caller also has `evidence:raw:read`. |
| `GET /api/v1/organizations/{org_id}/sboms/{sbom_id}/raw` | `evidence:raw:read` | Returns the immutable JSON bytes; cross-org IDs return `404 resource_not_found`. |
| `GET /api/v1/organizations/{org_id}/source-snapshots/{snapshot_id}` | `provenance:read` | Provenance metadata; `object_uri` requires `evidence:raw:read`. |
| `GET /api/v1/organizations/{org_id}/source-snapshots/{snapshot_id}/raw` | `evidence:raw:read` | Bytes from the local/object backing store keyed by `content_sha256`. |

`evidence:raw:read` is granted through a dedicated permission claim for humans
or a named service scope. It is not implied by `viewer`, `owner`, `auditor`, or
`admin` roles.

## Storage paths

Logical URIs on `source_snapshots` and `sbom_documents` point at object storage
(`s3://…`). Development and CI mirror bytes under `./storage/sbom/…` and
`./storage/evidence/…`. Direct filesystem or bucket access must remain network-
isolated; product authorization is enforced only on the API routes above.

## Residual exposure

- Operators with raw object-store credentials bypass API policy; restrict keys
  and audit object access separately.
- Historical snapshots ingested before local persistence was enabled may return
  `404` on `/raw` even when metadata exists; re-import or restore from backup.
