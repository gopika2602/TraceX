"""API workflow tests with an isolated Mongo-compatible test double.

These tests cover FastAPI contracts and authorization. They do not replace a
real MongoDB smoke test for deployment readiness.
"""

from __future__ import annotations

import os
from uuid import uuid4

os.environ.setdefault("APP_ENV", "testing")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-tracex-secret-key-32-bytes-minimum")
os.environ.setdefault("TRACEX_BOOTSTRAP_ADMIN_EMAILS", "admin@example.test")

import mongomock
import pytest
from fastapi.testclient import TestClient

from backend.app.db import ensure_indexes, get_database
from backend.app.main import app


@pytest.fixture
def api():
    database = mongomock.MongoClient(tz_aware=True)[f"tracex-test-{uuid4().hex}"]
    ensure_indexes(database)
    app.dependency_overrides[get_database] = lambda: database
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


def register(client: TestClient, email: str, password: str = "Test-password-123", name: str = "TraceX Test"):
    return client.post("/auth/register", json={"email": email, "password": password, "display_name": name})


def test_authentication_validation_logout_and_protected_routes(api: TestClient):
    assert api.get("/cases").status_code == 401
    registered = register(api, "analyst@example.test")
    assert registered.status_code == 201
    assert registered.json()["user"]["role"] == "analyst"
    assert "httponly" in registered.headers["set-cookie"].lower()
    assert api.post("/auth/logout").status_code == 204
    assert api.get("/cases").status_code == 401

    assert api.post("/auth/login", json={"email": "analyst@example.test", "password": "Wrong-password-1"}).status_code == 401
    assert api.post("/auth/login", json={"email": "missing@example.test", "password": "Test-password-123"}).status_code == 401
    assert api.post("/auth/login", json={"email": "", "password": ""}).status_code == 422
    assert api.post("/auth/login", json={"email": "analyst@example.test", "password": ""}).status_code == 422
    assert api.post("/auth/login", json={"email": "analyst@example.test", "password": "Test-password-123"}).status_code == 200
    assert api.get("/auth/session").status_code == 200


def test_analysis_persistence_remediation_authorization_and_verification(api: TestClient):
    admin = register(api, "admin@example.test", name="TraceX Admin")
    assert admin.status_code == 201
    assert admin.json()["user"]["role"] == "admin"
    dataset = api.post("/datasets/load-demo")
    assert dataset.status_code == 201, dataset.text
    assert dataset.json()["synthetic"] is True

    analyst_client = TestClient(app)
    analyst = register(analyst_client, "analyst2@example.test", name="TraceX Analyst")
    assert analyst.status_code == 201
    created = analyst_client.post("/cases", json={"dataset_id": "demo-nimbus"})
    assert created.status_code == 201, created.text
    case_id = created.json()["case"]["id"]
    assert created.json()["synthetic"] is True
    assert created.json()["case"]["synthetic"] is True

    case = analyst_client.get(f"/cases/{case_id}")
    events = analyst_client.get(f"/cases/{case_id}/events")
    path = analyst_client.get(f"/cases/{case_id}/attack-path")
    root = analyst_client.get(f"/cases/{case_id}/root-cause")
    blast = analyst_client.get(f"/cases/{case_id}/blast-radius")
    origin = analyst_client.get(f"/cases/{case_id}/attack-origin")
    remediations = analyst_client.get(f"/cases/{case_id}/remediations")
    assert all(response.status_code == 200 for response in (case, events, path, root, blast, origin, remediations))
    assert len(events.json()) == dataset.json()["event_count"]
    assert path.json()["steps"]
    assert root.json()["initial_compromise"]
    assert root.json()["related_event_ids"]
    assert blast.json()["reachable_resources"] > 0
    assert blast.json()["synthetic"] is True
    assert origin.json()["attribution_confirmed"] is False
    assert remediations.json()

    candidate = origin.json().get("suspect")
    if candidate:
        trace = analyst_client.get(f"/cases/{case_id}/attack-origin/trace", params={"suspect_id": candidate["id"]})
        assert trace.status_code == 200, trace.text

    remediation_id = remediations.json()[0]["id"]
    denied = analyst_client.post(f"/cases/{case_id}/remediations/{remediation_id}/apply")
    assert denied.status_code == 403
    applied = api.post(f"/cases/{case_id}/remediations/{remediation_id}/apply")
    assert applied.status_code == 200, applied.text
    assert api.get(f"/cases/{case_id}/remediations").json()[0]["status"] == "applied"
    verified = api.post(f"/cases/{case_id}/verify", params={"remediation_id": remediation_id})
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "PATH_BROKEN"
    assert verified.json()["before_allowed_steps"]
    assert verified.json()["normal_access_preserved"] is True
    assert api.post("/reset-demo").status_code == 200
    assert api.post("/auth/logout").status_code == 204
    assert api.get("/cases").status_code == 401
    analyst_client.close()


def test_case_intake_persists_evidence_and_analyzes_submitted_records(api: TestClient):
    assert register(api, "intake@example.test").status_code == 201
    payload = {
        "case_id": "CASE-INTAKE-1",
        "case_name": "Investigator submitted case",
        "organization": "Example Org",
        "incident_at": "2026-10-09T08:00:00Z",
        "description": "Observed logins from different devices.",
        "investigator_name": "Analyst One",
        "investigator_notes": "Initial notes remain separate from generated analysis.",
        "evidence": [
            {"evidence_type": "new_device_login", "timestamp": "2026-10-09T08:05:00Z", "identity": "person@example.test", "device_id": "device-a", "source_ip": "198.51.100.7", "api_service": "mail", "description": "First observed login."},
            {"evidence_type": "new_device_login", "timestamp": "2026-10-09T08:15:00Z", "identity": "person@example.test", "device_id": "device-b", "source_ip": "203.0.113.9", "session_id": "session-2", "token_id": "token-2", "api_service": "mail", "description": "Second device login."},
        ],
    }
    created = api.post("/cases/intake", json=payload)
    assert created.status_code == 201, created.text
    result = created.json()
    assert result["case_id"] == "CASE-INTAKE-1"
    assert result["evidence_count"] == 2
    assert result["synthetic"] is False
    assert result["status"] == "Draft"
    stored_case = api.get("/cases/CASE-INTAKE-1")
    assert stored_case.status_code == 200
    assert stored_case.json()["case_information"]["investigator_notes"] == payload["investigator_notes"]
    submitted = api.get("/cases/CASE-INTAKE-1/collected-evidence")
    assert submitted.status_code == 200
    assert len(submitted.json()) == 2
    assert submitted.json()[0]["device_id"] == "device-a"
    events = api.get("/cases/CASE-INTAKE-1/events").json()
    assert len(events) == 2
    assert {event["identity"] for event in events} == {"person@example.test"}
    assert all(event["severity"] == "unknown" for event in events)
    assert api.get("/cases/CASE-INTAKE-1/attack-path").status_code == 404
    analyzed = api.post("/cases/CASE-INTAKE-1/analyze")
    assert analyzed.status_code == 200, analyzed.text
    assert analyzed.json()["event_count"] == 2
    path = api.get("/cases/CASE-INTAKE-1/attack-path").json()
    assert path["steps"]
    assert {event_id for step in path["steps"] for event_id in step["event_ids"]} <= {event["event_id"] for event in events}
    saved_note = api.patch("/cases/CASE-INTAKE-1/notes", json={"notes": "Follow up with identity team."})
    assert saved_note.status_code == 200
    assert api.get("/cases/CASE-INTAKE-1").json()["case_information"]["investigator_notes"] == "Follow up with identity team."
