from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable

from app.schemas.event import SecurityEvent

CORRELATION_WINDOW = timedelta(minutes=15)


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    name: str
    score: int
    evidence_refs: list[str]


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
    rule_hits: list[RuleHit]


def _process_name(event: SecurityEvent) -> str:
    if not event.process or not event.process.name:
        return ""
    return event.process.name.lower()


def _command(event: SecurityEvent) -> str:
    if not event.process or not event.process.command_line:
        return ""
    return event.process.command_line.lower()


def _parent_process_name(event: SecurityEvent) -> str:
    if not event.parent_process or not event.parent_process.name:
        return ""
    return event.parent_process.name.lower()


def _within_window(events: list[SecurityEvent]) -> list[list[SecurityEvent]]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    windows: list[list[SecurityEvent]] = []
    current: list[SecurityEvent] = []
    anchor = None

    for event in ordered:
        if anchor is None or event.timestamp - anchor <= CORRELATION_WINDOW:
            current.append(event)
            anchor = anchor or event.timestamp
        else:
            windows.append(current)
            current = [event]
            anchor = event.timestamp
    if current:
        windows.append(current)
    return windows


def _evaluate_rules(events: list[SecurityEvent]) -> list[RuleHit]:
    hits: list[RuleHit] = []

    def refs(predicate: Callable[[SecurityEvent], bool]) -> list[str]:
        return [event.event_id for event in events if predicate(event)]

    ps = refs(lambda e: e.event_type.value == "process_creation" and _process_name(e) in {"powershell.exe", "pwsh.exe"})
    if ps:
        hits.append(RuleHit("DET-001", "PowerShell execution", 25, ps))

    encoded = refs(
        lambda e: e.event_type.value == "process_creation"
        and any(token in _command(e) for token in ("-enc", "-encodedcommand"))
    )
    if encoded:
        hits.append(RuleHit("DET-002", "Encoded PowerShell command", 25, encoded))

    network = refs(lambda e: e.event_type.value == "network_connection")
    if network:
        hits.append(RuleHit("DET-003", "External network connection", 20, network))

    scheduled = refs(lambda e: e.event_type.value == "process_creation" and "schtasks" in _command(e))
    if scheduled:
        hits.append(RuleHit("DET-004", "Scheduled task creation", 15, scheduled))

    office_child = refs(
        lambda e: e.event_type.value == "process_creation"
        and _process_name(e) in {"powershell.exe", "pwsh.exe"}
        and _parent_process_name(e) in {"winword.exe", "excel.exe", "outlook.exe"}
    )
    if office_child:
        hits.append(RuleHit("DET-005", "Office application spawned PowerShell", 20, office_child))

    failed_auth = refs(
        lambda e: e.event_type.value in {"authentication", "logon"}
        and str(e.data.get("result", "")).lower() in {"failure", "failed", "denied"}
    )
    if len(failed_auth) >= 5:
        hits.append(RuleHit("DET-006", "Repeated authentication failures", 20, failed_auth))

    return hits


def correlate(events: list[SecurityEvent]) -> list[Investigation]:
    grouped: dict[tuple[str, str | None], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        grouped[(event.host.hostname, event.user.username if event.user else None)].append(event)

    investigations: list[Investigation] = []
    counter = 1
    for _, host_events in grouped.items():
        for group in _within_window(host_events):
            hits = _evaluate_rules(group)
            chain = [hit.name for hit in hits]
            score = min(100, 10 + sum(hit.score for hit in hits))
            evidence = [
                {
                    "event_id": event.event_id,
                    "type": event.event_type.value,
                    "timestamp": event.timestamp.isoformat(),
                }
                for event in group
            ]
            covered = {ref for hit in hits for ref in hit.evidence_refs}
            missing = []
            if not any(event.event_type.value == "network_connection" for event in group):
                missing.append("network telemetry")
            if not any(event.event_type.value in {"authentication", "logon"} for event in group):
                missing.append("authentication telemetry")

            if score >= 70:
                classification = "likely_malicious"
            elif score >= 40:
                classification = "suspicious"
            else:
                classification = "needs_review"

            confidence = min(0.99, 0.50 + 0.08 * len(hits) + (0.08 if len(covered) >= 3 else 0))
            investigations.append(
                Investigation(
                    f"INV-{counter:05d}",
                    score,
                    round(confidence, 2),
                    classification,
                    group,
                    evidence,
                    chain,
                    missing,
                    hits,
                )
            )
            counter += 1
    return investigations


def timeline(investigation: Investigation) -> list[dict[str, Any]]:
    return [
        {
            "timestamp": event.timestamp.isoformat(),
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "evidence_ref": event.event_id,
        }
        for event in sorted(investigation.events, key=lambda event: event.timestamp)
    ]


def risk_summary(investigation: Investigation) -> dict[str, Any]:
    return {
        "investigation_id": investigation.investigation_id,
        "risk_score": investigation.risk_score,
        "confidence": investigation.confidence,
        "classification": investigation.classification,
        "attack_chain": investigation.attack_chain,
        "evidence": investigation.evidence,
        "missing_evidence": investigation.missing_evidence,
        "timeline": timeline(investigation),
        "rule_hits": [
            {
                "rule_id": hit.rule_id,
                "name": hit.name,
                "score": hit.score,
                "evidence_refs": hit.evidence_refs,
            }
            for hit in investigation.rule_hits
        ],
    }
