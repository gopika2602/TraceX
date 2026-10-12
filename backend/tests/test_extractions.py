"""Security and workflow tests for reviewed evidence extraction."""
from uuid import uuid4

import mongomock
import pytest
from fastapi.testclient import TestClient

from backend.tests import test_api_workflow as workflow
from backend.app.db import ensure_indexes, get_database
from backend.app.main import app


@pytest.fixture
def api(monkeypatch):
    database = mongomock.MongoClient(tz_aware=True)[f"tracex-extraction-test-{uuid4().hex}"]
    ensure_indexes(database)
    from backend.app import main as main_module

    monkeypatch.setattr(main_module, "get_database", lambda: database)
    monkeypatch.setattr(main_module, "close_client", lambda: None)
    monkeypatch.delenv("ADMIN_EMAIL", raising=False)
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    app.dependency_overrides[get_database] = lambda: database
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.dependency_overrides.clear()


register = workflow.register


def test_story_extraction_review_import_and_analysis(api: TestClient):
    assert register(api, "agent@example.test").status_code == 201
    response = api.post("/cases/extractions/preview", data={"story": "2026-10-11T10:05:00+05:30 suspicious login for analyst@example.test from 203.0.113.8\n2026-10-11T10:07:00+05:30 token issued to analyst@example.test"})
    assert response.status_code == 201, response.text
    preview = response.json()
    assert preview["extraction_method"] == "deterministic_rules"
    assert preview["ai_provider"] is None
    assert len(preview["events"]) == 2
    assert preview["events"][0]["timestamp"] == "2026-10-11T04:35:00Z"
    assert preview["events"][0]["raw_event_reference"] == "story:line:1"
    assert preview["events"][0]["identity"] == "analyst@example.test"
    assert preview["events"][0]["verification_status"] == "unreviewed"

    reviewed_events = []
    for event in preview["events"]:
        reviewed_events.append({"event_id": event["event_id"], "status": "approved", "fields": {}})
    reviewed = api.put(f"/cases/extractions/{preview['id']}/review", json={"events": reviewed_events})
    assert reviewed.status_code == 200, reviewed.text
    imported = api.post(f"/cases/extractions/{preview['id']}/import", data={"case_name": "Reviewed narrative"})
    assert imported.status_code == 201, imported.text
    assert imported.json()["analysis_status"] == "analyzed"
    case_id = imported.json()["case_id"]
    assert imported.json()["evidence_count"] == 2
    evidence = api.get(f"/cases/{case_id}/collected-evidence")
    assert evidence.status_code == 200
    assert all(row["extraction_method"] == "deterministic_rules" for row in evidence.json())
    assert api.get(f"/cases/{case_id}/attack-path").status_code == 200
    assert api.get(f"/cases/{case_id}/root-cause").status_code == 200
    assert api.get(f"/cases/{case_id}/events").json()
    duplicate_import = api.post(f"/cases/extractions/{preview['id']}/import", data={"case_name": "Ignored duplicate"})
    assert duplicate_import.status_code == 201
    assert duplicate_import.json()["status"] == "already_imported"
    assert duplicate_import.json()["case_id"] == case_id


def test_csv_preview_duplicate_idempotency_malformed_and_unsupported(api: TestClient):
    assert register(api, "csv@example.test").status_code == 201
    csv_text = "timestamp,event_type,identity,source_ip,description\n2026-10-11T10:05:00Z,login,person@example.test,203.0.113.4,Observed sign-in"
    first = api.post("/cases/extractions/preview", data={"story": ""}, files={"files": ("auth.csv", csv_text, "text/csv")})
    second = api.post("/cases/extractions/preview", data={"story": ""}, files={"files": ("auth.csv", csv_text, "text/csv")})
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["events"][0]["timestamp"] == "2026-10-11T10:05:00Z"
    assert first.json()["sources"][0]["name"] == "auth.csv"
    malformed = api.post("/cases/extractions/preview", files={"files": ("events.json", "{broken", "application/json")})
    assert malformed.status_code == 422
    unsupported = api.post("/cases/extractions/preview", files={"files": ("report.pdf", b"%PDF-", "application/pdf")})
    assert unsupported.status_code == 415


def test_review_requires_timezone_aware_timestamp_and_owner_scope(api: TestClient):
    assert register(api, "owner@example.test").status_code == 201
    preview = api.post("/cases/extractions/preview", data={"story": "At 10:05, unusual activity from 203.0.113.9"})
    extraction_id = preview.json()["id"]
    event = preview.json()["events"][0]
    rejected_approval = api.put(f"/cases/extractions/{extraction_id}/review", json={"events": [{"event_id": event["event_id"], "status": "approved", "fields": {}}]})
    assert rejected_approval.status_code == 422
    assert "timestamp" in rejected_approval.text.lower()
    no_approval = api.post(f"/cases/extractions/{extraction_id}/import", data={"case_name": "Should not import"})
    assert no_approval.status_code == 409

    other = TestClient(app)
    assert register(other, "other@example.test").status_code == 201
    assert other.get(f"/cases/extractions/{extraction_id}").status_code == 404
    assert other.put(f"/cases/extractions/{extraction_id}/review", json={"events": [{"event_id": event["event_id"], "status": "rejected", "fields": {}}]}).status_code == 404
    other.close()
