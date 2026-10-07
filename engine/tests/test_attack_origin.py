from attackpath.origin import analyze_attack_origin, score_origin_candidate, trace_backward


def test_clear_origin_ranks_earlier_malicious_entity_higher():
    events = [
        {"event_id": "origin", "timestamp": "2026-01-01T00:00:00Z", "event_type": "malicious_external_connection",
         "source": {"ip": "198.51.100.8", "device_id": "device-b"},
         "destination": {"device_id": "device-a"}, "indicators": ["known_bad_ip", "command_and_control"]},
        {"event_id": "incident", "timestamp": "2026-01-01T00:10:00Z", "event_type": "token_theft",
         "source": {"ip": "10.0.0.4", "device_id": "device-a"}, "identity": "alice", "token_id": "tok-a"},
    ]
    result = analyze_attack_origin(events, suspicious_event_ids=["incident"])
    by_entity = {(item["entity_type"], item["entity_id"]): item for item in result["candidate_origins"]}
    assert by_entity[("device", "device-b")]["confidence_score"] > by_entity[("device", "device-a")]["confidence_score"]
    assert result["likely_origin"]["entity_id"] == "device-b"
    assert result["likely_origin"]["status"] == "likely_attack_origin"


def test_compromised_suspicious_device_is_classified_as_victim():
    events = [
        {"event_id": "compromise", "timestamp": "2026-01-01T00:00:00Z", "event_type": "malware_execution",
         "device_id": "device-a", "process_name": "suspicious_process"},
        {"event_id": "incident", "timestamp": "2026-01-01T00:10:00Z", "event_type": "token_theft",
         "device_id": "device-a", "identity": "alice", "token_id": "tok-a"},
    ]
    result = analyze_attack_origin(events, suspicious_event_ids=["incident"])
    device = next(item for item in result["candidate_origins"] if item["entity_id"] == "device-a" and item["entity_type"] == "device")
    assert device["status"] == "suspected_compromised_device"
    assert device["counter_evidence"]
    assert result["likely_origin"]["entity_id"] != "device-a"


def test_insufficient_evidence_is_unknown_and_inconclusive():
    events = [{"event_id": "incident", "timestamp": "2026-01-01T00:00:00Z", "event_type": "unusual_event", "device_id": "device-x"}]
    result = analyze_attack_origin(events, suspicious_event_ids=["incident"])
    assert result["likely_origin"] is None
    assert any("inconclusive" in item for item in result["limitations"])
    assert next(item for item in result["candidate_origins"] if item["entity_id"] == "device-x")["confidence_level"] == "UNKNOWN"


def test_multiple_candidates_are_ranked_independently():
    events = [
        {"event_id": "origin-1", "timestamp": "2026-01-01T00:00:00Z", "event_type": "malware_execution",
         "device_id": "device-b", "process_name": "malware"},
        {"event_id": "origin-2", "timestamp": "2026-01-01T00:01:00Z", "event_type": "credential_theft",
         "device_id": "device-c", "indicators": ["credential_dump"]},
        {"event_id": "incident", "timestamp": "2026-01-01T00:10:00Z", "event_type": "token_theft",
         "source": {"device_id": "device-b"}, "destination": {"device_id": "device-c"}, "token_id": "tok-a"},
    ]
    result = analyze_attack_origin(events, suspicious_event_ids=["incident"])
    candidates = [item for item in result["candidate_origins"] if item["entity_type"] == "device" and item["entity_id"] in {"device-b", "device-c"}]
    assert len(candidates) == 2
    assert candidates[0]["confidence_score"] >= candidates[1]["confidence_score"]
    assert candidates[0]["confidence_score"] != candidates[1]["confidence_score"]


def test_conflicting_timestamps_reduce_confidence_and_are_reported():
    events = [
        {"event_id": "linked-but-later", "timestamp": "2026-01-01T00:20:00Z", "event_type": "malware_execution",
         "device_id": "device-x", "process_name": "malware"},
        {"event_id": "incident", "timestamp": "2026-01-01T00:10:00Z", "event_type": "malware_execution",
         "device_id": "device-x", "process_name": "malware"},
    ]
    raw = score_origin_candidate("device-x", "device", events, events)
    adjusted = analyze_attack_origin(events, suspicious_event_ids=["incident"])
    device = next(item for item in adjusted["candidate_origins"] if item["entity_id"] == "device-x")
    assert device["confidence_score"] < raw["confidence_score"]
    assert any(item["type"] == "timestamp_conflict" for item in device["counter_evidence"])
    assert any("Timestamp order conflicts" in item for item in adjusted["limitations"])


def test_normal_noise_near_incident_is_not_a_candidate():
    events = [
        {"event_id": "incident", "timestamp": "2026-01-01T00:00:00Z", "event_type": "token_theft", "device_id": "device-a"},
        {"event_id": "noise", "timestamp": "2026-01-01T00:00:01Z", "event_type": "normal_file_read",
         "device_id": "unrelated-device", "identity": "bob", "source": {"ip": "203.0.113.5"}},
    ]
    result = analyze_attack_origin(events, suspicious_event_ids=["incident"])
    assert all(item["entity_id"] != "unrelated-device" for item in result["candidate_origins"])
    assert "noise" not in {link["from_event_id"] for link in result["backward_links"]}


def test_trace_walks_only_causally_linked_earlier_events():
    events = [
        {"event_id": "prior", "timestamp": "2026-01-01T00:00:00Z", "device_id": "device-b",
         "destination": {"ip": "10.0.0.7"}, "event_type": "suspicious_network_activity"},
        {"event_id": "incident", "timestamp": "2026-01-01T00:01:00Z", "source": {"ip": "10.0.0.7"}, "device_id": "device-a"},
    ]
    trace = trace_backward(events, ["incident"])
    assert [events[i]["event_id"] for i in trace["event_indices"]] == ["prior", "incident"]
    assert trace["links"][0]["relationship"] == ["connection_continuity_ip"]
