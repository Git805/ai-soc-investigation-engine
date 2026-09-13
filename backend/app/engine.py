from __future__ import annotations

from datetime import datetime, timedelta, timezone
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from app.schemas.event import SecurityEvent


@dataclass
class Investigation:
    investigation_id: str
    risk_score: int
    confidence: float
    classification: str
    events: list[SecurityEvent]
    evidence: list[dict[str, Any]]
    attack_chain: list[str]
    missing_evidence: list[str]


def correlate(events: list[SecurityEvent]) -> list[Investigation]:
    groups: dict[tuple[str, str | None], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        groups[(event.host.hostname, event.user.username if event.user else None)].append(event)

    investigations: list[Investigation] = []
    for idx, (_, group) in enumerate(groups.items(), start=1):
        group.sort(key=lambda e: e.timestamp)
        evidence: list[dict[str, Any]] = []
        chain: list[str] = []
        score = 10
        has_powershell = any(e.event_type.value == "process_creation" and e.process and e.process.name.lower() in {"powershell.exe", "pwsh.exe"} for e in group)
        has_encoded = any(e.process and "-enc" in (e.process.command_line or "").lower() for e in group)
        has_network = any(e.event_type.value == "network_connection" for e in group)
        has_schtask = any(e.process and "schtasks" in (e.process.command_line or "").lower() for e in group)
        for event in group:
            evidence.append({"event_id": event.event_id, "type": event.event_type.value, "timestamp": event.timestamp.isoformat()})
        if has_powershell:
            chain.append("PowerShell execution"); score += 25
        if has_encoded:
            chain.append("Encoded command"); score += 25
        if has_network:
            chain.append("External network connection"); score += 20
        if has_schtask:
            chain.append("Scheduled task creation"); score += 15
        classification = "likely_malicious" if score >= 60 else "needs_review"
        confidence = min(0.99, 0.55 + max(0, len(chain) - 1) * 0.1)
        missing = [] if has_network else ["network telemetry"]
        investigations.append(Investigation(f"INV-{idx:05d}", min(score, 100), confidence, classification, group, evidence, chain, missing))
    return investigations


def timeline(investigation: Investigation) -> list[dict[str, Any]]:
    return [{"timestamp": e.timestamp.isoformat(), "event_id": e.event_id, "event_type": e.event_type.value, "evidence_ref": e.event_id} for e in sorted(investigation.events, key=lambda x: x.timestamp)]


def risk_summary(investigation: Investigation) -> dict[str, Any]:
    return {"investigation_id": investigation.investigation_id, "risk_score": investigation.risk_score, "confidence": investigation.confidence, "classification": investigation.classification, "attack_chain": investigation.attack_chain, "evidence": investigation.evidence, "missing_evidence": investigation.missing_evidence, "timeline": timeline(investigation)}
