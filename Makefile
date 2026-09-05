.PHONY: install dev test lint fmt migrate up down clean health frontend-install frontend-dev frontend-build frontend-test

install:
	uv sync --extra dev

dev:
	uv run uvicorn vulnops.main:app --host 0.0.0.0 --port 8000 --reload

test:
	uv run pytest -q

test-verbose:
	uv run pytest -v

lint:
	uv run ruff check src tests

fmt:
	uv run ruff format src tests

health:
	curl -s http://localhost:8000/health/live | jq .
	curl -s http://localhost:8000/health/ready | jq .

migrate:
	uv run alembic upgrade head

migrate-new:
	@read -p "message: " msg; uv run alembic revision --autogenerate -m "$$msg"

up:
	docker compose up --build

down:
	docker compose down -v

clean:
	rm -f vulnops.db vulnops-test.db
	rm -rf .venv .pytest_cache .ruff_cache

frontend-install:
	cd frontend && pnpm install

frontend-dev:
	cd frontend && pnpm dev

frontend-build:
	cd frontend && pnpm build

frontend-test:
	cd frontend && pnpm test
