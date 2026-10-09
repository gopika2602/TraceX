"""Generate the deterministic 40-event Nimbus demo fixture."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


OUTPUT_DIR = Path(__file__).resolve().parent


def build_environment() -> dict:
    return {
        "environment_id": "nimbus-prod-v1",
        "version": 1,
        "nodes": [
            {"id": "priya.s", "type": "identity"},
            {"id": "tok-9f2", "type": "token", "owner": "priya.s"},
            {"id": "helpdeskpro", "type": "application"},
            {"id": "oauth-77", "type": "token", "sensitivity": "high"},
            {"id": "orders-api", "type": "api", "sensitivity": "medium"},
            {"id": "payments-svc", "type": "service", "sensitivity": "high", "tags": ["financial", "critical"]},
            {"id": "customers-db", "type": "database", "sensitivity": "high", "tags": ["pii"]},
            {"id": "crm", "type": "application"},
            {"id": "email", "type": "application"},
        ],
        "edges": [
            {"from": "priya.s", "to": "tok-9f2", "permission": "owns"},
            {"from": "tok-9f2", "to": "helpdeskpro", "permission": "app:access"},
            {"from": "helpdeskpro", "to": "oauth-77", "permission": "oauth:issue"},
            {"from": "oauth-77", "to": "orders-api", "permission": "orders:*"},
            {"from": "oauth-77", "to": "payments-svc", "permission": "payments:admin"},
            {"from": "payments-svc", "to": "customers-db", "permission": "db:read"},
            {"from": "priya.s", "to": "crm", "permission": "crm:read"},
            {"from": "priya.s", "to": "email", "permission": "email:read"},
        ],
    }


def build_events() -> list[dict]:
    random.seed(42)
    start = datetime(2026, 10, 6, 9, 42, tzinfo=timezone.utc)
    attack_specs = [
        ("evt-0004", "session_reuse", "tok-9f2", "helpdeskpro", "session:use", "medium", "IN"),
        ("evt-0005", "token_use", "tok-9f2", "helpdeskpro", "app:access", "high", "US"),
        ("evt-0006", "application_access", "tok-9f2", "helpdeskpro", "app:access", "high", "US"),
        ("evt-0007", "oauth_create", "oauth-77", "helpdeskpro", "oauth:issue", "high", "US"),
        ("evt-0008", "api_call", "oauth-77", "orders-api", "orders:*", "high", "US"),
        ("evt-0009", "privilege_escalation", "oauth-77", "payments-svc", "payments:admin", "critical", "US"),
        ("evt-0010", "db_query", "oauth-77", "customers-db", "db:read", "critical", "US"),
    ]
    events: list[dict] = [{
        "event_id": "evt-0003", "timestamp": (start - timedelta(seconds=18)).isoformat().replace("+00:00", "Z"),
        "event_type": "malicious_external_connection", "identity": "external-unknown", "token_id": "external-session-token",
        "session_id": "external-session", "device_id": "egress-host", "source": {"ip": "198.51.100.8", "device_id": "egress-host"},
        "destination": {"ip": "203.0.113.77", "device_id": "device-new", "application": "Identity Provider", "resource": "session endpoint"},
        "summary": "Threat-intelligence matched external connection", "indicators": ["known_bad_ip", "command_and_control"],
        "severity": "high",
    }]
    for index, (event_id, event_type, token, destination, permission, severity, country) in enumerate(attack_specs):
        metadata = {}
        if event_type == "oauth_create":
            metadata = {"issued_by_session": "sess-41", "issued_by_token": "tok-9f2", "scopes": ["payments:admin"]}
        events.append({
            "event_id": event_id,
            "timestamp": (start + timedelta(seconds=18 + index * 60)).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "identity": "priya.s",
            "token_id": token,
            "session_id": "sess-41",
            "device_id": "device-new",
            "source": {"ip": "203.0.113.77", "device_id": "device-new", "country": country},
            "destination": {"application": destination, "resource": destination},
            "permission": permission,
            "metadata": metadata,
            "severity": severity,
            "summary": f"Observed {event_type.replace('_', ' ')} at {destination}",
        })

    event_types = ["interactive_sign_in", "file_read", "mailbox_access", "service_health_check", "directory_lookup"]
    applications = ["CRM", "Mail", "Directory", "Reporting", "Helpdesk"]
    for index in range(32):
        identity = random.choice(["ravi.k", "anita.m"])
        device_id = "device-ravi" if identity == "ravi.k" else "device-anita"
        token_id = "tok-ravi-demo" if identity == "ravi.k" else "tok-anita-demo"
        application = random.choice(applications)
        event_type = random.choice(event_types)
        minute = 20 + index
        events.append({
            "event_id": f"evt-bg-{index + 1:03d}",
            "timestamp": (start + timedelta(minutes=minute, seconds=random.randrange(60))).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "identity": identity,
            "token_id": token_id,
            "session_id": f"sess-{identity.replace('.', '-')}-demo",
            "device_id": device_id,
            "source": {"ip": "10.20.0.41" if identity == "ravi.k" else "10.20.0.52", "device_id": device_id, "country": "IN"},
            "destination": {"application": application, "resource": f"{application.lower()}-workspace"},
            "permission": "read",
            "metadata": {"background": True},
            "severity": random.choice(["low", "low", "medium"]),
            "summary": f"Routine {event_type.replace('_', ' ')} by {identity}",
        })
    return events


def main() -> None:
    events = build_events()
    environment = build_environment()
    expected = {
        "scenario_id": "nimbus-v1",
        "synthetic": True,
        "event_count": 40,
        "attack_event_count": 8,
        "grouped_attack_events": 7,
        "expected_attack_event_ids": [f"evt-{index:04d}" for index in range(4, 11)],
        "root_cause": {"identity": "priya.s", "credential": "tok-9f2"},
        "blast_radius": {"reachable_resources": 7, "sensitive_assets": 3},
        "verification": {"remediation_id": "rem-1", "status": "PATH_BROKEN", "broken_at_step": 2},
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in (("events.json", events), ("environment.json", environment), ("expected_results.json", expected)):
        (OUTPUT_DIR / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {len(events)} synthetic events and the Nimbus environment in {OUTPUT_DIR}.")


if __name__ == "__main__":
    main()
