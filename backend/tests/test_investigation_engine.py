from datetime import timedelta

from app.engine import correlate
from app.synthetic import generate_demo_events
from app.intel import extract_indicators
from app.mitre import map_techniques


def test_demo_correlates_to_high_risk_chain():
    inv = correlate(generate_demo_events())[0]
    assert inv.risk_score == 100
    assert inv.classification == "likely_malicious"
    assert "PowerShell execution" in inv.attack_chain
    assert "Encoded PowerShell command" in inv.attack_chain
    assert "Office application spawned PowerShell" in inv.attack_chain
    assert "Scheduled task creation" in inv.attack_chain
    assert {hit.rule_id for hit in inv.rule_hits} >= {"DET-001", "DET-002", "DET-003", "DET-004", "DET-005"}


def test_rule_hits_link_back_to_evidence():
    inv = correlate(generate_demo_events())[0]
    event_ids = {event.event_id for event in inv.events}
    assert inv.rule_hits
    assert all(set(hit.evidence_refs) <= event_ids for hit in inv.rule_hits)


def test_correlation_window_splits_unrelated_activity():
    events = generate_demo_events()
    events[-1] = events[-1].model_copy(update={"timestamp": events[0].timestamp + timedelta(minutes=30)})
    investigations = correlate(events)
    assert len(investigations) == 2
    assert all(inv.events for inv in investigations)


def test_mitre_mappings_are_evidence_linked():
    events = generate_demo_events()
    mappings = map_techniques(events)
    assert any(m["technique_id"] == "T1059.001" and m["evidence_refs"] for m in mappings)


def test_indicator_extraction():
    indicators = extract_indicators(generate_demo_events())
    assert any(
        item["indicator"] == "203.0.113.50"
        and item["type"] == "ip"
        and "demo-network-001" in item["evidence_refs"]
        for item in indicators
    )
