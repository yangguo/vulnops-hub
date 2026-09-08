"""Fetch sandbox records and push them onto the VulnOps ingestion queue.

Bridge-level stopgap for integrated-staging evidence collection: the product
worker consumes JSON jobs from the Valkey ``vulnops:ingest`` queue, but the
DefectDojo and Wazuh HTTP polling adapters are a future slice. Until then
this script pulls raw records from the sandbox APIs and enqueues them
unchanged as payloads, mirroring what a polling adapter would produce.

Examples::

    uv run python scripts/sandbox_fetch.py defectdojo \
        --base-url http://localhost:8081 --token <dojo-api-token> \
        --org org-demo --limit 10

    uv run python scripts/sandbox_fetch.py wazuh \
        --base-url https://localhost:55000 --user wazuh-wui \
        --password 'MyS3cr3tP4ss?*' --org org-demo

Add ``--dry-run`` to print the jobs instead of enqueueing them. Only
stdlib plus the project's existing ``redis`` dependency is used.
"""

from __future__ import annotations

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any

QUEUE_KEY = "vulnops:ingest"


def _http_json(url: str, *, headers: dict[str, str] | None = None, insecure_tls: bool = False) -> Any:
    request = urllib.request.Request(url, headers={"accept": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=30, context=_ssl_context(insecure_tls)) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise SystemExit(f"HTTP {exc.code} from {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"cannot reach {url}: {exc.reason}") from exc


def _ssl_context(insecure: bool) -> ssl.SSLContext | None:
    if not insecure:
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _basic_auth(user: str, password: str) -> str:
    encoded = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {encoded}"


def fetch_defectdojo(base_url: str, token: str, limit: int) -> list[dict[str, Any]]:
    """Pull the most recent findings raw from the DefectDojo v2 API."""

    data = _http_json(
        f"{base_url.rstrip('/')}/api/v2/findings/?limit={limit}&ordering=-id",
        headers={"authorization": f"Token {token}"},
    )
    return list(data.get("results", []))


def _wazuh_token(base_url: str, basic_header: str) -> str:
    """Exchange basic credentials for a Wazuh API JWT (raw body)."""

    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/security/user/authenticate?raw=true",
        headers={"authorization": basic_header},
    )
    try:
        with urllib.request.urlopen(request, timeout=30, context=_ssl_context(True)) as resp:
            return resp.read().decode("utf-8").strip()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"Wazuh authentication failed: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"cannot reach {base_url}: {exc.reason}") from exc


def fetch_wazuh_events(base_url: str, auth_header: str, limit: int) -> list[dict[str, Any]]:
    """Pull agent package inventories from the Wazuh manager API.

    Each (agent, package) pair becomes one event payload shaped the way
    :class:`vulnops.integrations.wazuh.WazuhBridge` expects it.
    """

    base = base_url.rstrip("/")
    token = _wazuh_token(base, auth_header)
    bearer = {"authorization": f"Bearer {token}"}
    agents_page = _http_json(
        f"{base}/agents?limit={limit}", headers=bearer, insecure_tls=True
    )
    events: list[dict[str, Any]] = []
    for agent in agents_page.get("data", {}).get("affected_items", []):
        agent_id = agent.get("id")
        if agent_id is None:
            continue
        try:
            packages = _http_json(
                f"{base}/syscollector/{agent_id}/packages?limit=200",
                headers=bearer,
                insecure_tls=True,
            )
        except SystemExit:
            print(f"warning: no package inventory for agent {agent_id}", file=sys.stderr)
            continue
        for package in packages.get("data", {}).get("affected_items", []):
            events.append({"agent": agent, "package": package})
    return events


def build_jobs(source: str, payloads: list[dict[str, Any]], org: str) -> list[dict[str, Any]]:
    jobs = []
    for payload in payloads:
        natural_id = payload.get("id") or payload.get("agent", {}).get("id")
        jobs.append(
            {
                "source": source,
                "payload": payload,
                "organization_id": org,
                "idempotency_key": f"{source}:{natural_id}",
            }
        )
    return jobs


def enqueue(jobs: list[dict[str, Any]], redis_url: str) -> None:
    import redis  # project dependency, resolved via uv run

    client = redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=5)
    client.ping()
    pipeline = client.pipeline()
    for job in jobs:
        pipeline.lpush(QUEUE_KEY, json.dumps(job))
    pipeline.execute()
    print(f"enqueued {len(jobs)} job(s) on {QUEUE_KEY} via {redis_url}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="source", required=True)

    dojo = sub.add_parser("defectdojo", help="fetch findings from a DefectDojo sandbox")
    dojo.add_argument("--base-url", required=True, help="e.g. http://localhost:8081")
    dojo.add_argument("--token", required=True, help="DefectDojo REST API token (user API key)")
    dojo.add_argument("--org", default="org-demo")
    dojo.add_argument("--limit", type=int, default=20)

    wazuh = sub.add_parser("wazuh", help="fetch agent packages from a Wazuh manager sandbox")
    wazuh.add_argument("--base-url", required=True, help="e.g. https://localhost:55000")
    wazuh.add_argument("--user", default="wazuh-wui")
    wazuh.add_argument("--password", required=True)
    wazuh.add_argument("--org", default="org-demo")
    wazuh.add_argument("--limit", type=int, default=20)

    for sub_parser in (dojo, wazuh):
        sub_parser.add_argument("--redis-url", default=None, help="default: REDIS_URL env or redis://localhost:6379/0")
        sub_parser.add_argument("--dry-run", action="store_true", help="print jobs instead of enqueueing")

    args = parser.parse_args()

    if args.source == "defectdojo":
        payloads = fetch_defectdojo(args.base_url, args.token, args.limit)
        jobs = build_jobs("defectdojo", payloads, args.org)
    else:
        auth = _basic_auth(args.user, args.password)
        payloads = fetch_wazuh_events(args.base_url, auth, args.limit)
        jobs = build_jobs("wazuh", payloads, args.org)

    if args.dry_run:
        print(json.dumps(jobs, indent=2)[:4000])
        print(f"... {len(jobs)} job(s) total")
        return

    redis_url = args.redis_url
    if redis_url is None:
        import os

        redis_url = os.getenv("REDIS_URL") or os.getenv("VALKEY_URL") or "redis://localhost:6379/0"
    enqueue(jobs, redis_url)


if __name__ == "__main__":
    main()
