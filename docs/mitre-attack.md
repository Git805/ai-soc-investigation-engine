# MITRE ATT&CK Mapping

Phase 7 maps deterministic detection rules to MITRE ATT&CK techniques without inventing mappings when evidence is insufficient.

| Detection | Technique | Tactic | Evidence basis |
|---|---|---|---|
| DET-001 PowerShell execution | T1059.001 PowerShell | Execution | PowerShell process event |
| DET-002 Encoded PowerShell | T1059.001 PowerShell | Execution | Encoded PowerShell command line |
| DET-004 Scheduled task creation | T1053.005 Scheduled Task/Job: Scheduled Task | Persistence | schtasks process event |
| DET-005 Office → PowerShell | T1204.002 User Execution: Malicious File | Execution | Office parent + PowerShell child |

The API exposes mappings through `GET /api/v1/attack`.

Every mapping retains investigation, detection-rule and event evidence references. The mapping layer is advisory and does not authorize containment or other response actions.
