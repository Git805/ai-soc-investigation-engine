import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.engine import correlate
from app.models import EventRecord
from app.schemas.event import SecurityEvent
from app.schemas.evidence import EvidenceItem, EvidenceLedger, EvidenceType

router = APIRouter(prefix="/api/v1/investigations", tags=["evidence"])


def _events(db: Session) -> list[SecurityEvent]:
    records = db.scalars(select(EventRecord).order_by(EventRecord.timestamp.asc())).all()
    return [SecurityEvent.model_validate(json.loads(record.payload)) for record in records]


def _find(db: Session, investigation_id: str):
    return next((item for item in correlate(_events(db)) if item.investigation_id == investigation_id), None)


def _ledger(investigation) -> EvidenceLedger:
    items: list[EvidenceItem] = []
    confidence = investigation.confidence

    for event in investigation.events:
        items.append(EvidenceItem(
            evidence_id=f"EV-{event.event_id}",
            evidence_type=EvidenceType.EVENT,
            timestamp=event.timestamp,
            source=f"{event.source.vendor}/{event.source.product}",
            reference_id=event.event_id,
            description=f"{event.event_type.value} telemetry on {event.host.hostname}",
            provenance="canonical security event telemetry",
            confidence=confidence,
            investigation_id=investigation.investigation_id,
        ))

    for hit in investigation.rule_hits:
        timestamp = min(
            (event.timestamp for event in investigation.events if event.event_id in hit.evidence_refs),
            default=min(event.timestamp for event in investigation.events),
        )
        items.append(EvidenceItem(
            evidence_id=f"RH-{hit.rule_id}-{investigation.investigation_id}",
            evidence_type=EvidenceType.RULE_HIT,
            timestamp=timestamp,
            source="deterministic-detection-engine",
            reference_id=hit.rule_id,
            description=hit.name,
            provenance=f"rule {hit.rule_id}; evidence_refs={','.join(hit.evidence_refs)}",
            confidence=confidence,
            investigation_id=investigation.investigation_id,
        ))

    items.sort(key=lambda item: (item.timestamp, item.evidence_id))
    return EvidenceLedger(
        investigation_id=investigation.investigation_id,
        generated_at=datetime.now(timezone.utc),
        items=items,
        item_count=len(items),
    )


@router.get("/{investigation_id}/evidence", response_model=EvidenceLedger)
def get_evidence(investigation_id: str, db: Session = Depends(get_db)):
    investigation = _find(db, investigation_id)
    if not investigation:
        raise HTTPException(404, "investigation not found")
    return _ledger(investigation)


@router.get("/{investigation_id}/timeline")
def get_timeline(investigation_id: str, db: Session = Depends(get_db)):
    investigation = _find(db, investigation_id)
    if not investigation:
        raise HTTPException(404, "investigation not found")
    return {
        "investigation_id": investigation.investigation_id,
        "start": investigation.events[0].timestamp.isoformat(),
        "end": investigation.events[-1].timestamp.isoformat(),
        "duration_seconds": (investigation.events[-1].timestamp - investigation.events[0].timestamp).total_seconds(),
        "events": [
            {
                "timestamp": event.timestamp.isoformat(),
                "event_id": event.event_id,
                "event_type": event.event_type.value,
                "host": event.host.hostname,
                "user": event.user.username if event.user else None,
                "source": f"{event.source.vendor}/{event.source.product}",
            }
            for event in sorted(investigation.events, key=lambda event: event.timestamp)
        ],
    }
