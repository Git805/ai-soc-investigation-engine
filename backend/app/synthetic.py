from datetime import datetime, timedelta, timezone

from app.schemas.event import EventType, SecurityEvent, Severity


def generate_demo_events() -> list[SecurityEvent]:
    base = datetime.now(timezone.utc).replace(microsecond=0)
    return [
        SecurityEvent(event_id="demo-login-001", timestamp=base, event_type=EventType.LOGON, severity=Severity.LOW, host={"hostname":"WS-001","ip":"10.10.10.25"}, user={"username":"jdoe"}, source={"product":"SIEM","vendor":"synthetic"}, data={"result":"success"}),
        SecurityEvent(event_id="demo-process-001", timestamp=base+timedelta(minutes=2), event_type=EventType.PROCESS_CREATION, severity=Severity.MEDIUM, host={"hostname":"WS-001","ip":"10.10.10.25"}, user={"username":"jdoe"}, process={"name":"powershell.exe","pid":4212,"command_line":"powershell.exe -enc <synthetic>"}, parent_process={"name":"winword.exe","pid":3120}, source={"product":"EDR","vendor":"synthetic"}),
        SecurityEvent(event_id="demo-network-001", timestamp=base+timedelta(minutes=3), event_type=EventType.NETWORK_CONNECTION, severity=Severity.HIGH, host={"hostname":"WS-001","ip":"10.10.10.25"}, user={"username":"jdoe"}, network={"destination_ip":"203.0.113.50","destination_port":443,"protocol":"tcp"}, source={"product":"EDR","vendor":"synthetic"}),
        SecurityEvent(event_id="demo-task-001", timestamp=base+timedelta(minutes=4), event_type=EventType.PROCESS_CREATION, severity=Severity.HIGH, host={"hostname":"WS-001","ip":"10.10.10.25"}, user={"username":"jdoe"}, process={"name":"schtasks.exe","pid":4300,"command_line":"schtasks /create /tn Update /tr powershell.exe"}, source={"product":"EDR","vendor":"synthetic"}),
    ]
