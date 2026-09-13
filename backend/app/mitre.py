from app.schemas.event import SecurityEvent


def map_techniques(events: list[SecurityEvent]) -> list[dict]:
    mappings = []
    for event in events:
        if event.event_type.value == "process_creation" and event.process:
            name = event.process.name.lower()
            cmd = (event.process.command_line or "").lower()
            if name in {"powershell.exe", "pwsh.exe"}:
                mappings.append({"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution", "evidence_refs": [event.event_id]})
            if "schtasks" in cmd:
                mappings.append({"technique_id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task", "tactic": "Persistence", "evidence_refs": [event.event_id]})
            if "-enc" in cmd:
                mappings.append({"technique_id": "T1027", "name": "Obfuscated/Compressed Files and Information", "tactic": "Defense Evasion", "evidence_refs": [event.event_id]})
    return mappings
