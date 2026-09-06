from uuid import uuid4

import pytest
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
    org = f"filterorg-{uuid4().hex[:8]}"
    c1 = _create_case(client, org, "triage me", priority="P1")
    _create_case(client, org, "other", priority="P2")
    client.post(
        f"/api/v1/organizations/{org}/cases/{c1['id']}/transitions",
        json={"target": "triage"},
    )
    resp = client.get(f"/api/v1/organizations/{org}/cases?status=triage")
    assert resp.status_code == 200
    assert {i["id"] for i in resp.json()["items"]} == {c1["id"]}

    resp = client.get(f"/api/v1/organizations/{org}/cases?priority=P2")
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


@pytest.mark.parametrize(
    ("invalid_field", "value"),
    [
        ("exposures", {"bad": "shape"}),
        ("unexpected", "must be rejected"),
        ("priority", "P9"),
        ("owner_team", ""),
    ],
)
def test_create_case_rejects_invalid_body_without_mutating_cases(invalid_field, value):
    client = TestClient(create_app())
    org = f"create-contract-{uuid4().hex[:8]}"
    before = client.get(f"/api/v1/organizations/{org}/cases").json()["total"]

    payload = {
        "title": "strict create",
        "owner_team": "platform",
        "priority": "P2",
        invalid_field: value,
    }
    response = client.post(f"/api/v1/organizations/{org}/cases", json=payload)

    assert response.status_code == 422, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "invalid_request_body"
    assert detail["fields"] == [invalid_field]
    after = client.get(f"/api/v1/organizations/{org}/cases").json()["total"]
    assert after == before


def test_create_case_valid_exposures_round_trip_as_typed_detail():
    client = TestClient(create_app())
    org = f"create-contract-valid-{uuid4().hex[:8]}"
    response = client.post(
        f"/api/v1/organizations/{org}/cases",
        json={
            "title": "strict create",
            "owner_team": "platform",
            "priority": "P2",
            "exposures": ["exp-1", "exp-2"],
        },
    )
    assert response.status_code == 200, response.text

    detail = client.get(f"/api/v1/organizations/{org}/cases/{response.json()['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["exposures"] == ["exp-1", "exp-2"]
