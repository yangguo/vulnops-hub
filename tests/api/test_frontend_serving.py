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


def _fake_dist(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text('<html><body><div id="app"></div></body></html>')
    (dist / "assets" / "app.js").write_text("// js")
    return dist


def test_spa_fallback_serves_built_app(monkeypatch, tmp_path):
    monkeypatch.setattr("vulnops.api.frontend.DIST", _fake_dist(tmp_path))
    client = TestClient(create_app())
    root = client.get("/")
    assert root.status_code == 200
    assert 'id="app"' in root.text
    deep = client.get("/cases")
    assert deep.status_code == 200 and 'id="app"' in deep.text
    asset = client.get("/assets/app.js")
    assert asset.status_code == 200
    assert "javascript" in asset.headers["content-type"]
    assert client.get("/api/unknown").status_code == 404
    assert client.get("/health/live").status_code == 200
    assert client.get("/docs").status_code == 200


def test_spa_fallback_does_not_leak_outside_dist(monkeypatch, tmp_path):
    dist = _fake_dist(tmp_path)
    (tmp_path / "secret.txt").write_text("SECRET")
    monkeypatch.setattr("vulnops.api.frontend.DIST", dist)
    client = TestClient(create_app())
    resp = client.get("/..%2fsecret.txt")
    assert resp.status_code == 200  # falls back to index.html
    assert "SECRET" not in resp.text
