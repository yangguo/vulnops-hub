from pathlib import Path

import yaml

COMPOSE_PATH = Path(__file__).parents[2] / "docker-compose.yml"
DOCKERFILE_PATH = Path(__file__).parents[2] / "Dockerfile"


def test_compose_gates_application_services_on_completed_migrations():
    compose = yaml.safe_load(COMPOSE_PATH.read_text())
    services = compose["services"]

    assert services["migrate"]["command"] == "alembic -c /app/alembic.ini upgrade head"
    for service in ("api", "worker", "orchestrator", "poller"):
        assert services[service]["depends_on"]["migrate"] == {
            "condition": "service_completed_successfully"
        }


def test_runtime_image_includes_the_alembic_configuration():
    assert "COPY pyproject.toml README.md alembic.ini ./" in DOCKERFILE_PATH.read_text()
