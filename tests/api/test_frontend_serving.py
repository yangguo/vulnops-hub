from fastapi.testclient import TestClient

from vulnops.main import create_app


def test_root_returns_json_when_no_dist(monkeypatch):
    monkeypatch.setattr("vulnops.api.frontend.DIST", None, raising=False)
    client = TestClient(create_app())
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["service"] == "vulnops-hub"


def test_unknown_html_path_gets_404_json_when_no_dist(monkeypatch):
    monkeypatch.setattr("vulnops.api.frontend.DIST", None, raising=False)
    client = TestClient(create_app())
    resp = client.get("/some/spa/route")
    assert resp.status_code == 404
