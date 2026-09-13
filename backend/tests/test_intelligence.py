from datetime import datetime, timezone

from app.intel import enrich, extract_indicators, intelligence_summary
from app.schemas.event import EventType, Host, Process, SecurityEvent, Severity, Source
from app.schemas.network import NetworkEventData


def event(event_id: str = "evt-1") -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.NETWORK_CONNECTION,
        severity=Severity.HIGH,
        host=Host(hostname="ws-01"),
        process=Process(name="powershell.exe", command_line="curl 203.0.113.10"),
        network=NetworkEventData(destination_ip="203.0.113.10", destination_domain="malicious.example"),
        source=Source(vendor="synthetic", product="test"),
    )


def test_extract_indicators_preserves_evidence_refs() -> None:
    indicators = extract_indicators([event("evt-42")])
    by_value = {item["indicator"]: item for item in indicators}
    assert by_value["203.0.113.10"]["type"] == "ip"
    assert by_value["203.0.113.10"]["evidence_refs"] == ["evt-42"]
    assert by_value["malicious.example"]["type"] == "domain"


def test_enrich_marks_synthetic_malicious_indicators() -> None:
    results = enrich([{"indicator": "203.0.113.10", "type": "ip", "evidence_refs": ["evt-1"]}])
    assert results[0]["reputation"] == "malicious"
    assert results[0]["provider"] == "synthetic"
    assert results[0]["confidence"] >= 0.9
    assert results[0]["evidence_refs"] == ["evt-1"]


def test_private_ip_is_internal_and_summary_counts_indicators() -> None:
    private_event = event("evt-private")
    private_event.network.destination_ip = "10.10.10.10"
    private_event.process.command_line = "connect 10.10.10.10"
    summary = intelligence_summary([private_event])
    assert summary["indicator_count"] >= 1
    assert any(item["reputation"] == "internal" for item in summary["indicators"])
