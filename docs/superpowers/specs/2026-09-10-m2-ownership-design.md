# M2 ownership slice

## Scope

Business services are organization-scoped inventory records with a stable ID,
name, owner team, optional criticality, and creation/update timestamps. They
are exposed at `/api/v1/organizations/{org_id}/services` with create, list,
and get operations. Service creation accepts `asset:write` or `case:write`
(so the existing admin and owner roles can manage inventory); reads use
`case:read` and remain organization-scoped.

CSV asset imports accept `business_service_id`, `service`, and `service_name`.
They resolve only existing services in the import organization and preserve an
existing owner/service link when an update row omits it. Unknown service values
are ignored rather than creating inventory implicitly.

## Case ownership

Case creation resolves the owner in this order:

1. nonblank `Asset.owner` for the exposure's linked asset;
2. nonblank `BusinessService.owner_team` for that asset's linked service;
3. `settings.default_case_owner_team`.

The lookup is organization-scoped. The small
`resolve_case_owner_team(session, organization_id, asset_id)` helper is shared
by orchestration and domain-level case creation, with an injectable default for
worker settings and tests.

For P0/P1 cases that still resolve to the configured default (normally
`unassigned`), the case stores `ownership_escalated=true` and writes the
append-only `case.ownership.unassigned_high_priority` audit event in the same
transaction as `case.created`. The existing `owner_team` case filter remains
the operator query for unassigned work.

This slice deliberately does not add a full service/CMDB UI, external ticket
projection, or a foreign key from `assets.business_service_id`; the string link
keeps SQLite test/dev metadata and staged imports compatible while the
organization-scoped API provides the authoritative service IDs.
