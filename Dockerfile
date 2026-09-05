FROM node:22-alpine AS frontend
WORKDIR /app
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml /app/
RUN pnpm install --frozen-lockfile
COPY frontend/ /app/
RUN pnpm build

FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY --from=frontend /app/dist ./frontend/dist

RUN pip install --upgrade pip && pip install -e . && pip install uvicorn[standard]

EXPOSE 8000
CMD ["uvicorn", "vulnops.main:app", "--host", "0.0.0.0", "--port", "8000"]
