from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.event import EventType, SecurityEvent, Severity


def sample_event() -> dict:
    return {
        "event_id": "evt-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "process_creation",
        "severity": "medium",
        "host": {"hostname": "WS-001", "ip": "10.10.10.25"},
        "user": {"username": "jdoe"},
        "process": {"name": "powershell.exe", "pid": 4212, "command_line": "powershell.exe -enc ..."},
        "parent_process": {"name": "winword.exe", "pid": 3120},
        "source": {"product": "EDR", "vendor": "synthetic"},
    }


def test_security_event_validates():
    event = SecurityEvent.model_validate(sample_event())
    assert event.event_type is EventType.PROCESS_CREATION
    assert event.severity is Severity.MEDIUM
    assert event.host.hostname == "WS-001"


def test_security_event_rejects_missing_required_fields():
    payload = sample_event()
    del payload["host"]
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(payload)


def test_security_event_rejects_unknown_top_level_fields():
    payload = sample_event()
    payload["unexpected"] = True
    with pytest.raises(ValidationError):
        SecurityEvent.model_validate(payload)
