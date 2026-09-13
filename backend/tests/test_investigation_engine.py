from app.engine import correlate
from app.synthetic import generate_demo_events
from app.intel import extract_indicators
from app.mitre import map_techniques


def test_demo_correlates_to_high_risk_chain():
    inv = correlate(generate_demo_events())[0]
    assert inv.risk_score >= 80
    assert inv.classification == "likely_malicious"
    assert "PowerShell execution" in inv.attack_chain
    assert "Scheduled task creation" in inv.attack_chain


def test_mitre_mappings_are_evidence_linked():
    events = generate_demo_events()
    mappings = map_techniques(events)
    assert any(m["technique_id"] == "T1059.001" and m["evidence_refs"] for m in mappings)


def test_indicator_extraction():
    assert "203.0.113.50" in extract_indicators(generate_demo_events())
