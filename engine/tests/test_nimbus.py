from copy import deepcopy

from attackpath import analyze, apply_remediation, explain, verify
from attackpath.loader import index_events, load_environment, load_events
from attackpath.policy import can_reach


def environment():
    nodes = [
        {"id": "priya.s", "type": "identity"},
        {"id": "tok-9f2", "type": "token", "owner": "priya.s"},
        {"id": "helpdeskpro", "type": "application"},
        {"id": "oauth-77", "type": "token", "sensitivity": "high"},
        {"id": "orders-api", "type": "api", "sensitivity": "medium"},
        {"id": "payments-svc", "type": "service", "sensitivity": "high", "tags": ["financial", "critical"]},
        {"id": "customers-db", "type": "database", "sensitivity": "high", "tags": ["pii"]},
        {"id": "crm", "type": "application"}, {"id": "email", "type": "application"},
    ]
    edges = [
        {"from": "priya.s", "to": "tok-9f2", "permission": "owns"},
        {"from": "tok-9f2", "to": "helpdeskpro", "permission": "app:access"},
        {"from": "helpdeskpro", "to": "oauth-77", "permission": "oauth:issue"},
        {"from": "oauth-77", "to": "orders-api", "permission": "orders:*"},
        {"from": "oauth-77", "to": "payments-svc", "permission": "payments:admin"},
        {"from": "payments-svc", "to": "customers-db", "permission": "db:read"},
        {"from": "priya.s", "to": "crm", "permission": "crm:read"},
        {"from": "priya.s", "to": "email", "permission": "email:read"},
    ]
    return {"nodes": nodes, "edges": edges}


def events():
    specs = [
        ("evt-0004", "session_reuse", "tok-9f2", "sess-41", "priya.s", "device-new", "helpdeskpro", "session:use"),
        ("evt-0005", "token_use", "tok-9f2", "sess-41", "priya.s", "device-new", "helpdeskpro", "app:access"),
        ("evt-0006", "application_access", "tok-9f2", "sess-41", "priya.s", "device-new", "helpdeskpro", "app:access"),
        ("evt-0007", "oauth_create", "oauth-77", "sess-41", "priya.s", "device-new", "helpdeskpro", "oauth:issue"),
        ("evt-0008", "api_call", "oauth-77", "sess-41", "priya.s", "device-new", "orders-api", "orders:*"),
        ("evt-0009", "privilege_escalation", "oauth-77", "sess-41", "priya.s", "device-new", "payments-svc", "payments:admin"),
        ("evt-0010", "db_query", "oauth-77", "sess-41", "priya.s", "device-new", "customers-db", "db:read"),
    ]
    result = []
    for i, (event_id, kind, token, session, identity, device, app, permission) in enumerate(specs):
        result.append({"event_id": event_id, "timestamp": f"2026-01-01T00:{i:02d}:00Z",
                       "event_type": kind, "identity": identity, "token_id": token,
                       "session_id": session, "device_id": device,
                       "destination": {"application": app, "resource": app},
                       "permission": permission,
                       "metadata": ({"issued_by_session": "sess-41", "issued_by_token": "tok-9f2", "scopes": ["payments:admin"]}
                                   if kind == "oauth_create" else {})})
    result[0]["country"] = "IN"
    result[1]["country"] = "US"
    return result


def test_loaders_and_indexes_accept_json_objects():
    sample_events = events()
    loaded_events = load_events(sample_events)
    loaded_environment = load_environment(environment())
    assert len(loaded_events) == 7
    assert len(index_events(loaded_events)["token_id"]["tok-9f2"]) >= 2
    assert len(loaded_environment["edges"]) == 8


def test_policy_exact_permission_and_revocation():
    env = environment()
    assert can_reach(env, "tok-9f2", "helpdeskpro", "app:access")["allowed"]
    assert can_reach(env, "tok-9f2", "helpdeskpro", "wrong")["reason"] == "SCOPE_INSUFFICIENT"
    revoked = apply_remediation(env, {"action": "revoke_token", "target": "tok-9f2"})
    assert can_reach(revoked, "tok-9f2", "helpdeskpro", "app:access", "tok-9f2")["reason"] == "TOKEN_REVOKED"
    assert "revoked" not in env["nodes"][1]


def test_analysis_remediation_and_replay():
    env = environment()
    original = deepcopy(env)
    result = analyze(events(), env)
    assert len(result["attack_path"]["steps"]) == 7
    assert [step["stage"] for step in result["attack_path"]["steps"]] == [
        "initial_compromise", "token_abuse", "application_access", "token_created",
        "api_access", "privilege_escalation", "data_access"]
    assert result["root_cause"]["abused_credential"] == "tok-9f2"
    assert result["correlation"][0]["event_ids"] == [f"evt-{i:04d}" for i in range(4, 11)]
    assert result["blast_radius"]["summary"]["reachable_resources"] == 7
    assert result["blast_radius"]["summary"]["sensitive_assets"] == 3
    after = apply_remediation(env, result["remediations"][0])
    replay = verify(result["attack_path"], env, after)
    assert replay["result"] == "PATH_BROKEN"
    assert replay["first_denied_step"] == 2
    assert env == original
    scoped = apply_remediation(env, result["remediations"][1])
    assert verify(result["attack_path"], env, scoped)["first_denied_step"] == 6
    assert "seven" not in explain(result).lower() or "7 steps" in explain(result)
