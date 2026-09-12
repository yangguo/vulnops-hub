import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts/simulated_defectdojo_acceptance.py"
SPEC = importlib.util.spec_from_file_location("simulated_defectdojo_acceptance", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

build_job = MODULE.build_job
load_fixture = MODULE.load_fixture


def test_simulated_finding_job_is_explicit_and_replay_stable():
    fixture = load_fixture()

    job = build_job(fixture, organization_id="org-demo", run_id="m2-simulated-openvas-001")

    payload = job["payload"]
    assert payload["id"] == "simulated-m2-simulated-openvas-001"
    assert payload["title"].startswith("[SIMULATED ACCEPTANCE]")
    assert payload["host"] == "payments-api-3"
    assert payload["purl"] == "pkg:deb/debian/openssl@3.0.2"
    assert payload["component_version"] == "3.0.2"
    assert payload["cve"] == "CVE-2026-12345"
    assert payload["verified"] is True
    assert payload["related_fields"]["jira"]["key"] == "VULN-77"
    assert job == build_job(fixture, organization_id="org-demo", run_id="m2-simulated-openvas-001")
    assert job["idempotency_key"] == "defectdojo:simulated-m2-simulated-openvas-001"
