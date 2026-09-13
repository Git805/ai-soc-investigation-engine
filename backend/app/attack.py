from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.engine import Investigation


@dataclass(frozen=True)
class AttackMapping:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence_refs: list[str]
    rationale: str


RULE_TO_ATTACK = {
    "DET-001": AttackMapping("T1059.001", "PowerShell", "Execution", 0.98, [], "PowerShell execution was observed."),
    "DET-002": AttackMapping("T1059.001", "PowerShell", "Execution", 0.99, [], "Encoded PowerShell arguments were observed."),
    "DET-004": AttackMapping("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence", 0.95, [], "schtasks execution indicates scheduled-task activity."),
    "DET-005": AttackMapping("T1204.002", "User Execution: Malicious File", "Execution", 0.72, [], "Office spawning PowerShell is treated as a suspicious user-execution pattern."),
}


def map_investigation(investigation: Investigation) -> list[dict[str, Any]]:
    mappings: dict[str, dict[str, Any]] = {}
    for hit in investigation.rule_hits:
        template = RULE_TO_ATTACK.get(hit.rule_id)
        if not template:
            continue
        item = mappings.setdefault(template.technique_id, {
            "technique_id": template.technique_id,
            "technique_name": template.technique_name,
            "tactic": template.tactic,
            "confidence": template.confidence,
            "evidence_refs": [],
            "detection_rule_refs": [],
            "rationale": template.rationale,
        })
        item["evidence_refs"] = sorted(set(item["evidence_refs"]) | set(hit.evidence_refs))
        item["detection_rule_refs"].append(hit.rule_id)
        item["confidence"] = max(item["confidence"], template.confidence)
    return sorted(mappings.values(), key=lambda item: item["technique_id"])


def attack_summary(investigations: list[Investigation]) -> dict[str, Any]:
    mappings = []
    for investigation in investigations:
        for mapping in map_investigation(investigation):
            mappings.append({"investigation_id": investigation.investigation_id, **mapping})
    return {"framework": "MITRE ATT&CK", "version": "enterprise", "mappings": mappings}
