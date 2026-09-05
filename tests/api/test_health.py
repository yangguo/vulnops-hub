from fastapi.testclient import TestClient

from vulnops.main import create_app


def test_liveness_returns_service_identity():
    app = create_app()
    client = TestClient(app)
    response = client.get("/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "vulnops-hub"
    assert data["status"] == "ok"
    assert "version" in data
    assert "X-Request-ID" in response.headers


def test_readiness_returns_ok_when_db_reachable():
    app = create_app()
    client = TestClient(app)
    response = client.get("/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "vulnops-hub"
    # ready must include checks without leaking credentials
    assert "checks" in data
    assert "database" in data["checks"]
    # must not expose exception details / credentials
    body = response.text.lower()
    assert "password" not in body
    assert "psycopg2" not in body
