# Backend Case Read Endpoints Implementation Plan

> **Execution status:** Completed on 2026-09-05. Implemented by commits
> `fce23ce` through `87eaf08`; follow-up fixes added deterministic pagination,
> preserved nullable `exposures`, isolated fixtures, and typed response models.
> The unchecked boxes below preserve the original execution sequence and are
> not the current project backlog.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the three read-only case endpoints the frontend console needs: paginated/filtered case list, per-case risk-decision history, per-case verification history.

**Architecture:** Extend `CaseService` with list/query methods (SQLAlchemy select + count), expose them through `src/vulnops/api/cases.py` following the existing org-scoped router style, and share one case serializer between GET-detail and GET-list. Spec: `docs/superpowers/specs/2026-09-05-frontend-console-design.md` §6.

**Tech Stack:** FastAPI, SQLAlchemy 2.0, pytest + TestClient (patterns copied from `tests/api/test_case_transitions.py`).

## Global Constraints

- All endpoints live under `/api/v1/organizations/{org_id}/...` and enforce org isolation: cross-org access returns `404 {"detail": "Case not found"}` (same as existing GET case).
- List response shape is the project's first pagination standard: `{"items": [...], "total": int, "page": int, "page_size": int}`.
- New endpoints are additive only — never change existing request/response contracts except adding fields.
- Tests run against the default SQLite DB via `TestClient(create_app())` — no fixtures; use unique org ids per test to avoid cross-test interference (rows are never deleted).
- Lint with `uv run ruff check src tests` (line length 100, see pyproject `[tool.ruff]`).
- Commit after every task; message style follows `git log` (`feat: ...`).

---

### Task 1: Shared case serializer + paginated case list endpoint

**Files:**
- Modify: `src/vulnops/api/cases.py` (add serializer + list endpoint; refactor `get_case` to use it)
- Modify: `src/vulnops/cases/service.py` (add `CaseService.list_cases`)
- Test: `tests/api/test_list_cases.py` (create)

**Interfaces:**
- Consumes: `CaseService.get_case(case_id) -> RemediationCase` (exists), `RemediationCase` columns (all exist in `src/vulnops/cases/models.py:50`).
- Produces: `_serialize_case(case) -> dict` used by list + detail endpoints; `CaseService.list_cases(organization_id: str, *, status, priority, owner_team, assignee, sla_breached, page: int, page_size: int, sort: str) -> tuple[list[RemediationCase], int]`; `GET /api/v1/organizations/{org_id}/cases` returning `{"items", "total", "page", "page_size"}`. The frontend plan (Task 2+) consumes these exact shapes; `created_at`/`updated_at`/`policy_version`/`closure_reason` are newly added to case payloads.

- [ ] **Step 1: Write the failing tests**

Create `tests/api/test_list_cases.py`:

```python
from fastapi.testclient import TestClient

from vulnops.main import create_app


def _create_case(client, org, title, priority="P2", owner_team="platform", **extra):
    payload = {"title": title, "priority": priority, "owner_team": owner_team, **extra}
    resp = client.post(f"/api/v1/organizations/{org}/cases", json=payload)
    assert resp.status_code in (200, 201), resp.text
    return resp.json()


def test_list_cases_returns_paged_shape():
    client = TestClient(create_app())
    created = [_create_case(client, "listorg", f"case {i}", priority="P1") for i in range(3)]
    resp = client.get("/api/v1/organizations/listorg/cases")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] >= 3
    assert body["page"] == 1
    assert body["page_size"] == 20
    ids = {item["id"] for item in body["items"]}
    assert {c["id"] for c in created} <= ids
    item = next(i for i in body["items"] if i["id"] == created[0]["id"])
    assert item["status"] == "new"
    assert item["priority"] == "P1"
    assert item["created_at"]
    assert item["updated_at"]
    assert item["etag"] == f'"{item["version"]}"'


def test_list_cases_filter_status_and_priority():
    client = TestClient(create_app())
    c1 = _create_case(client, "filterorg", "triage me", priority="P1")
    _create_case(client, "filterorg", "other", priority="P2")
    client.post(
        f"/api/v1/organizations/filterorg/cases/{c1['id']}/transitions",
        json={"target": "triage", "actor": "t"},
    )
    resp = client.get("/api/v1/organizations/filterorg/cases?status=triage")
    assert resp.status_code == 200
    assert {i["id"] for i in resp.json()["items"]} == {c1["id"]}

    resp = client.get("/api/v1/organizations/filterorg/cases?priority=P2")
    items = resp.json()["items"]
    assert items
    assert all(i["priority"] == "P2" for i in items)


def test_list_cases_pagination_disjoint_pages():
    client = TestClient(create_app())
    for i in range(3):
        _create_case(client, "pageorg", f"p-{i}", priority="P3")
    page1 = client.get("/api/v1/organizations/pageorg/cases?page=1&page_size=2").json()
    page2 = client.get("/api/v1/organizations/pageorg/cases?page=2&page_size=2").json()
    assert len(page1["items"]) == 2
    assert page1["total"] >= 3
    assert {i["id"] for i in page1["items"]}.isdisjoint(i["id"] for i in page2["items"])


def test_list_cases_org_isolation():
    client = TestClient(create_app())
    _create_case(client, "iso-org-a", "secret case")
    resp = client.get("/api/v1/organizations/iso-org-b/cases")
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["total"] == 0


def test_list_cases_sla_breached_filter_accepts_bool():
    client = TestClient(create_app())
    _create_case(client, "slaorg", "fresh case")
    resp = client.get("/api/v1/organizations/slaorg/cases?sla_breached=false")
    assert resp.status_code == 200
    assert all(i["sla_breached"] is False for i in resp.json()["items"])


def test_list_cases_rejects_bad_params():
    client = TestClient(create_app())
    assert client.get("/api/v1/organizations/anyorg/cases?page_size=1000").status_code == 422
    assert client.get("/api/v1/organizations/anyorg/cases?page=0").status_code == 422
    assert client.get("/api/v1/organizations/anyorg/cases?sort=title").status_code == 422
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/api/test_list_cases.py -v`
Expected: FAIL — list endpoint returns 404/405 (route does not exist yet).

- [ ] **Step 3: Implement `CaseService.list_cases`**

In `src/vulnops/cases/service.py`:

1. Extend the sqlalchemy import (line 5) to: `from sqlalchemy import func, select, update`
2. Add this method to `CaseService` (after `get_case`):

```python
    def list_cases(
        self,
        organization_id: str,
        *,
        status: str | None = None,
        priority: str | None = None,
        owner_team: str | None = None,
        assignee: str | None = None,
        sla_breached: bool | None = None,
        page: int = 1,
        page_size: int = 20,
        sort: str = "-created_at",
    ) -> tuple[list[RemediationCase], int]:
        stmt = select(RemediationCase).where(
            RemediationCase.organization_id == organization_id
        )
        if status:
            stmt = stmt.where(RemediationCase.status == status)
        if priority:
            stmt = stmt.where(RemediationCase.priority == priority)
        if owner_team:
            stmt = stmt.where(RemediationCase.owner_team == owner_team)
        if assignee:
            stmt = stmt.where(RemediationCase.assignee == assignee)
        if sla_breached is not None:
            stmt = stmt.where(RemediationCase.sla_breached == sla_breached)

        total = self.session.scalar(select(func.count()).select_from(stmt.subquery())) or 0

        desc = sort.startswith("-")
        order_col = getattr(RemediationCase, sort.lstrip("-"))
        stmt = stmt.order_by(order_col.desc() if desc else order_col.asc())
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        items = list(self.session.scalars(stmt).all())
        return items, total
```

(`sort` validation is enforced by the API layer's `Query(pattern=...)` in Step 4, so the service only ever receives whitelisted fields.)

- [ ] **Step 4: Implement serializer + list endpoint in the API layer**

In `src/vulnops/api/cases.py`:

1. Extend the models import (line 9) to: `from vulnops.cases.models import ALLOWED_TRANSITIONS, RemediationCase`
2. Add the `Query` import: change `from fastapi import APIRouter, Depends, Header, HTTPException, Request` to `from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request`
3. Add the serializer above the router and refactor `get_case` to use it (replaces the inline dict at lines 82-96):

```python
def _serialize_case(case: RemediationCase) -> dict:
    return {
        "id": case.id,
        "case_key": case.case_key,
        "title": case.title,
        "status": case.status,
        "priority": case.priority,
        "owner_team": case.owner_team,
        "assignee": case.assignee,
        "organization_id": case.organization_id,
        "policy_version": case.policy_version,
        "version": case.version,
        "etag": f'"{case.version}"',
        "due_at": case.due_at.isoformat() if case.due_at else None,
        "exposures": case.exposures or [],
        "sla_breached": case.sla_breached,
        "closure_reason": case.closure_reason,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
    }
```

`get_case` return becomes:

```python
    return _serialize_case(case)
```

4. Add the list endpoint after the `create_case` endpoint (before `get_case`):

```python
@router.get("/organizations/{org_id}/cases")
async def list_cases(
    org_id: str,
    status: str | None = None,
    priority: str | None = None,
    owner_team: str | None = None,
    assignee: str | None = None,
    sla_breached: bool | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort: str = Query(
        default="-created_at", pattern=r"^-?(created_at|updated_at|due_at|priority)$"
    ),
    db: Session = Depends(get_db),
):
    svc = CaseService(db)
    items, total = svc.list_cases(
        organization_id=org_id,
        status=status,
        priority=priority,
        owner_team=owner_team,
        assignee=assignee,
        sla_breached=sla_breached,
        page=page,
        page_size=page_size,
        sort=sort,
    )
    return {
        "items": [_serialize_case(c) for c in items],
        "total": total,
        "page": page,
        "page_size": page_size,
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/api/test_list_cases.py tests/api/test_case_transitions.py -v`
Expected: all PASS (existing transition tests must stay green — they cover `get_case`).

- [ ] **Step 6: Lint and commit**

```bash
uv run ruff check src tests
git add src/vulnops/api/cases.py src/vulnops/cases/service.py tests/api/test_list_cases.py
git commit -m "feat: paginated filtered case list endpoint"
```

---

### Task 2: Risk-decision history endpoint

**Files:**
- Modify: `src/vulnops/api/cases.py`
- Modify: `src/vulnops/cases/service.py` (add `CaseService.list_risk_decisions`)
- Test: `tests/api/test_case_histories.py` (create)

**Interfaces:**
- Consumes: `RiskDecision` model (`src/vulnops/cases/models.py:114`), `CaseService.get_case`.
- Produces: `GET /api/v1/organizations/{org_id}/cases/{case_id}/risk-decisions` → `{"items": [decision...]}` newest-first, each item `{id, case_id, type, status, scope_exposure_ids, reason, compensating_controls, evidence_ids, requested_by, approver, approver_role, expires_at, created_at}`; `CaseService.list_risk_decisions(case_id: str) -> list[RiskDecision]`. Frontend Task 5 consumes this exact shape.

- [ ] **Step 1: Write the failing tests**

Create `tests/api/test_case_histories.py`:

```python
from fastapi.testclient import TestClient

from vulnops.main import create_app


def _create_case(client, org, title, priority="P2"):
    resp = client.post(
        f"/api/v1/organizations/{org}/cases",
        json={"title": title, "priority": priority, "owner_team": "platform"},
    )
    assert resp.status_code in (200, 201), resp.text
    return resp.json()


def test_list_risk_decisions_returns_history():
    client = TestClient(create_app())
    org = "rd-org"
    case = _create_case(client, org, "accept this")
    cid = case["id"]
    client.post(
        f"/api/v1/organizations/{org}/cases/{cid}/transitions",
        json={"target": "triage", "actor": "t"},
    )
    resp = client.post(
        f"/api/v1/organizations/{org}/cases/{cid}/risk-decisions",
        json={
            "type": "risk_accepted",
            "reason": "waiver until Q4",
            "evidence_ids": ["e1"],
            "requested_by": "alice",
            "approver": "bob",
            "approver_role": "security_lead",
        },
    )
    assert resp.status_code in (200, 201), resp.text

    resp = client.get(f"/api/v1/organizations/{org}/cases/{cid}/risk-decisions")
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["type"] == "risk_accepted"
    assert items[0]["status"] == "approved"
    assert items[0]["case_id"] == cid
    assert items[0]["approver"] == "bob"
    assert items[0]["created_at"]


def test_list_risk_decisions_unknown_case_404():
    client = TestClient(create_app())
    resp = client.get("/api/v1/organizations/rd-org/cases/case_nope/risk-decisions")
    assert resp.status_code == 404


def test_list_risk_decisions_cross_org_404():
    client = TestClient(create_app())
    case = _create_case(client, "rd-org-a", "mine")
    resp = client.get(
        f"/api/v1/organizations/rd-org-b/cases/{case['id']}/risk-decisions"
    )
    assert resp.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/api/test_case_histories.py -v`
Expected: FAIL with 404 on the GET (route missing).

- [ ] **Step 3: Implement service method + endpoint**

In `src/vulnops/cases/service.py`, add to `CaseService`:

```python
    def list_risk_decisions(self, case_id: str) -> list[RiskDecision]:
        stmt = (
            select(RiskDecision)
            .where(RiskDecision.case_id == case_id)
            .order_by(RiskDecision.created_at.desc())
        )
        return list(self.session.scalars(stmt).all())
```

In `src/vulnops/api/cases.py`, add the serializer next to `_serialize_case`:

```python
def _serialize_risk_decision(d) -> dict:
    return {
        "id": d.id,
        "case_id": d.case_id,
        "type": d.type,
        "status": d.status,
        "scope_exposure_ids": d.scope_exposure_ids or [],
        "reason": d.reason,
        "compensating_controls": d.compensating_controls or [],
        "evidence_ids": d.evidence_ids or [],
        "requested_by": d.requested_by,
        "approver": d.approver,
        "approver_role": d.approver_role,
        "expires_at": d.expires_at.isoformat() if d.expires_at else None,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }
```

and the endpoint after the `create_risk_decision` endpoint:

```python
@router.get("/organizations/{org_id}/cases/{case_id}/risk-decisions")
async def list_risk_decisions(
    org_id: str, case_id: str, db: Session = Depends(get_db)
):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Case not found")
    if case.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Case not found")
    decisions = svc.list_risk_decisions(case_id)
    return {"items": [_serialize_risk_decision(d) for d in decisions]}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/api/test_case_histories.py -v`
Expected: PASS

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src tests
git add src/vulnops/api/cases.py src/vulnops/cases/service.py tests/api/test_case_histories.py
git commit -m "feat: risk decision history endpoint"
```

---

### Task 3: Verification history endpoint

**Files:**
- Modify: `src/vulnops/api/cases.py`
- Modify: `src/vulnops/cases/service.py` (add `CaseService.list_verifications`)
- Test: `tests/api/test_case_histories.py` (append)

**Interfaces:**
- Consumes: `Verification` model (`src/vulnops/cases/models.py:148`).
- Produces: `GET /api/v1/organizations/{org_id}/cases/{case_id}/verifications` → `{"items": [...]}` newest-first, each `{id, case_id, method, asserted_result, evidence_ids, coverage, status, created_at}`; `CaseService.list_verifications(case_id: str) -> list[Verification]`. Frontend Task 5 consumes this shape.

- [ ] **Step 1: Append the failing tests**

Add to `tests/api/test_case_histories.py`:

```python
def test_list_verifications_returns_history():
    client = TestClient(create_app())
    org = "ver-org"
    case = _create_case(client, org, "prove it")
    cid = case["id"]
    for target in ["triage", "assigned", "in_progress", "awaiting_verification"]:
        client.post(
            f"/api/v1/organizations/{org}/cases/{cid}/transitions",
            json={"target": target, "actor": "t"},
        )
    resp = client.post(
        f"/api/v1/organizations/{org}/cases/{cid}/verifications",
        json={
            "method": "scanner",
            "evidence_ids": ["ev1"],
            "coverage": {"status": "complete", "scope_version": "v2"},
        },
    )
    assert resp.status_code in (200, 201), resp.text

    resp = client.get(f"/api/v1/organizations/{org}/cases/{cid}/verifications")
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["method"] == "scanner"
    assert items[0]["status"] == "closed"
    assert items[0]["coverage"] == {"status": "complete", "scope_version": "v2"}
    assert items[0]["created_at"]


def test_list_verifications_unknown_case_404():
    client = TestClient(create_app())
    resp = client.get("/api/v1/organizations/ver-org/cases/case_nope/verifications")
    assert resp.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/api/test_case_histories.py -v`
Expected: the two new tests FAIL (404), the Task 2 tests stay green.

- [ ] **Step 3: Implement service method + endpoint**

In `src/vulnops/cases/service.py`, add to `CaseService`:

```python
    def list_verifications(self, case_id: str) -> list[Verification]:
        stmt = (
            select(Verification)
            .where(Verification.case_id == case_id)
            .order_by(Verification.created_at.desc())
        )
        return list(self.session.scalars(stmt).all())
```

In `src/vulnops/api/cases.py`, add the serializer:

```python
def _serialize_verification(v) -> dict:
    return {
        "id": v.id,
        "case_id": v.case_id,
        "method": v.method,
        "asserted_result": v.asserted_result,
        "evidence_ids": v.evidence_ids or [],
        "coverage": v.coverage or {},
        "status": v.status,
        "created_at": v.created_at.isoformat() if v.created_at else None,
    }
```

and the endpoint after `list_risk_decisions`:

```python
@router.get("/organizations/{org_id}/cases/{case_id}/verifications")
async def list_verifications(
    org_id: str, case_id: str, db: Session = Depends(get_db)
):
    svc = CaseService(db)
    try:
        case = svc.get_case(case_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Case not found")
    if case.organization_id != org_id:
        raise HTTPException(status_code=404, detail="Case not found")
    verifications = svc.list_verifications(case_id)
    return {"items": [_serialize_verification(v) for v in verifications]}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/api/test_case_histories.py -v`
Expected: PASS

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check src tests
git add src/vulnops/api/cases.py src/vulnops/cases/service.py tests/api/test_case_histories.py
git commit -m "feat: verification history endpoint"
```

---

### Task 4: Regenerate OpenAPI spec + full-suite gate

**Files:**
- Modify: `openapi/openapi.yaml` (regenerated)

**Interfaces:**
- Consumes: all endpoints from Tasks 1–3.
- Produces: `openapi/openapi.yaml` containing the three new paths — the frontend plan's `pnpm openapi` generation (its Task 2) consumes this file.

- [ ] **Step 1: Regenerate openapi.yaml from the app**

```bash
uv run python -c "
import yaml
from vulnops.main import create_app
spec = create_app().openapi()
with open('openapi/openapi.yaml', 'w') as f:
    yaml.safe_dump(spec, f, sort_keys=False)
print('paths:', len(spec['paths']))
"
grep -c "risk-decisions\|verifications\|cases'" openapi/openapi.yaml
```

Expected: paths count grows (was 12); grep finds the new GET paths.

- [ ] **Step 2: Full suite + lint gate**

```bash
uv run pytest -q
uv run ruff check src tests
uv run python -c "from vulnops.main import create_app; app = create_app(); print(app.openapi()['openapi'])"
```

Expected: all tests pass, lint clean, OpenAPI builds.

- [ ] **Step 3: Commit**

```bash
git add openapi/openapi.yaml
git commit -m "chore: regenerate openapi spec with case read endpoints"
```
