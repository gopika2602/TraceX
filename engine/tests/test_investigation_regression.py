from attackpath.blast import calculate_blast_radius
from attackpath.origin import analyze_attack_origin
from attackpath.reconstruct import reconstruct
from attackpath.remediate import apply_remediation
from attackpath.rootcause import analyze_root_cause
from attackpath.verify import verify


def sample_events():
    chronology = [
        ("suspicious_login", "2026-10-01T10:05:00Z", None, None, None),
        ("session_token_issued", "2026-10-01T10:07:00Z", "session-token", None, None),
        ("session_reuse", "2026-10-01T10:11:00Z", "session-token", None, None),
        ("oauth_token_issued", "2026-10-01T10:14:00Z", "oauth-token", "identity-api", None),
        ("api_access", "2026-10-01T10:17:00Z", "oauth-token", "orders-api", "orders-api"),
        ("service_access", "2026-10-01T10:20:00Z", "oauth-token", "payment-service", "payment-service"),
        ("bulk_data_read", "2026-10-01T10:24:00Z", "oauth-token", "customer-db", "customer-db"),
        ("privileged_action_attempt", "2026-10-01T10:29:00Z", "oauth-token", "payment-service", "payment-service"),
    ]
    events = [{"event_id": f"e{i}", "event_type": kind, "timestamp": timestamp,
               "identity": "support-identity", "device_id": "support-device",
               "token_id": token, "permission": "read",
               "destination": ({"application": app, "resource": resource} if app else {})}
              for i, (kind, timestamp, token, app, resource) in enumerate(chronology, 1)]
    return [events[index] for index in (7, 3, 5, 0, 6, 2, 1, 4)]


def graph_environment():
    return {
        "nodes": [
            {"id": "session-token", "type": "token"},
            {"id": "normal-token", "type": "token"},
            {"id": "oauth-token", "type": "token"},
            {"id": "orders-api", "type": "api", "sensitivity": "medium"},
            {"id": "payment-service", "type": "service", "sensitivity": "high", "tags": ["financial", "critical"]},
            {"id": "customer-db", "type": "database", "sensitivity": "high", "tags": ["customer-data"]},
            {"id": "normal-service", "type": "service"},
        ],
        "edges": [
            {"from": "session-token", "to": "oauth-token", "permission": "issue"},
            {"from": "oauth-token", "to": "orders-api", "permission": "read"},
            {"from": "orders-api", "to": "payment-service", "permission": "read"},
            {"from": "payment-service", "to": "customer-db", "permission": "read"},
            {"from": "normal-token", "to": "normal-service", "permission": "read"},
        ],
    }


def test_tracex_001_preserves_supplied_timestamp_order_and_origin_chain():
    events = sample_events()
    group = {"event_ids": [event["event_id"] for event in events]}
    path = reconstruct(events, group)
    assert [step["timestamp"] for step in path["steps"]] == sorted(event["timestamp"] for event in events)
    assert [step["event_ids"][0] for step in path["steps"]] == [f"e{i}" for i in range(1, 9)]

    origin = analyze_attack_origin(events, path)
    assert origin["backward_links"]
    assert any(item["type"] == "unusual_login" for candidate in origin["candidate_origins"]
               for item in candidate["supporting_evidence"])
    assert origin["likely_origin"] is None  # A login indicator alone does not attribute an attacker.


def test_absent_mfa_telemetry_is_reported_as_unknown_not_a_root_cause():
    events = sample_events()
    path = reconstruct(events, {"event_ids": [event["event_id"] for event in events]})
    root = analyze_root_cause(path, events, graph_environment())
    assert "NO_STEP_UP_AUTH" not in {item["code"] for item in root["contributing_factors"]}
    assert any("MFA status" in item for item in root["limitations"])
    assert root["compromised_identity"] == "support-identity"
    assert root["abused_credential"] == "session-token"


def test_administrative_scope_needs_a_policy_baseline_before_calling_it_excessive():
    events = sample_events()
    path = reconstruct(events, {"event_ids": [event["event_id"] for event in events]})
    environment = graph_environment()
    environment["edges"].append({"from": "oauth-token", "to": "payment-service", "permission": "admin"})
    root = analyze_root_cause(path, events, environment)
    factor = next(item for item in root["contributing_factors"] if item["code"] == "ADMIN_PERMISSION_CONFIGURED")
    assert "excessiveness is unverified" in factor["description"]


def test_blast_radius_separates_observed_destinations_from_policy_and_tags():
    events = sample_events()
    radius = calculate_blast_radius(graph_environment(), "session-token", events)
    assert {item["node_id"] for item in radius["observed_targets"]} == {
        "identity-api", "orders-api", "payment-service", "customer-db"
    }
    assert radius["summary"]["reachable_resources"] == 4
    assert radius["summary"]["sensitive_assets"] == 2
    assert radius["summary"]["financial_apis"] == 1
    assert radius["summary"]["customer_data_systems"] == 1

    # Names alone cannot manufacture sensitivity or business classification.
    untagged = {"nodes": [{"id": "token"}, {"id": "payment-api"}, {"id": "customer-db"}],
                "edges": [{"from": "token", "to": "payment-api", "permission": "read"},
                          {"from": "payment-api", "to": "customer-db", "permission": "read"}]}
    result = calculate_blast_radius(untagged, "token")
    assert result["summary"]["sensitive_assets"] == 0
    assert result["summary"]["financial_apis"] == 0
    assert result["summary"]["customer_data_systems"] == 0
    assert all(item["sensitivity"] == "unknown" for item in result["reachable_nodes"])


def test_remediation_verification_blocks_observed_path_and_preserves_normal_access():
    environment = graph_environment()
    events = sample_events()
    path = reconstruct(events, {"event_ids": [event["event_id"] for event in events]})
    remediation = {"action": "revoke_token", "target": "session-token"}
    after = apply_remediation(environment, remediation)
    result = verify(path, environment, after, "session-token")
    assert result["result"] == "PATH_BROKEN"
    assert result["transition_count"] > 0
    assert result["steps_before"] and all(item["allowed"] for item in result["steps_before"])
    assert result["steps_after"] and result["steps_after"][0]["reason"] == "TOKEN_REVOKED"
    assert result["normal_access_preserved"] is True
