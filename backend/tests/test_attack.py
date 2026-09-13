from datetime import datetime, timezone

from app.attack import attack_summary, map_investigation
from app.engine import Investigation, RuleHit
from app.schemas.event import EventType, Host, SecurityEvent, Severity, Source, Process


def _event(event_id: str, name: str, command: str | None = None) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        event_type=EventType.PROCESS_CREATION,
        severity=Severity.HIGH,
        host=Host(hostname="host-01"),
        process=Process(name=name, command_line=command),
        source=Source(vendor="test", product="test"),
    )


def test_powershell_mapping_preserves_evidence():
    event = _event("evt-1", "powershell.exe", "powershell -enc AAA")
    investigation = Investigation(
        "INV-00001", 80, 0.9, "likely_malicious", [event], [], [], [],
        [RuleHit("DET-001", "PowerShell execution", 25, ["evt-1"])],
    )
    mappings = map_investigation(investigation)
    assert mappings[0]["technique_id"] == "T1059.001"
    assert mappings[0]["evidence_refs"] == ["evt-1"]
    assert mappings[0]["detection_rule_refs"] == ["DET-001"]


def test_unknown_detection_rule_is_not_invented_as_attack_mapping():
    event = _event("evt-2", "cmd.exe")
    investigation = Investigation(
        "INV-00002", 20, 0.6, "needs_review", [event], [], [], [],
        [RuleHit("DET-003", "External network connection", 20, ["evt-2"])],
    )
    assert map_investigation(investigation) == []


def test_attack_summary_is_stable():
    event = _event("evt-3", "powershell.exe")
    investigation = Investigation(
        "INV-00003", 40, 0.7, "suspicious", [event], [], [], [],
        [RuleHit("DET-001", "PowerShell execution", 25, ["evt-3"])],
    )
    summary = attack_summary([investigation])
    assert summary["framework"] == "MITRE ATT&CK"
    assert summary["mappings"][0]["investigation_id"] == "INV-00003"
