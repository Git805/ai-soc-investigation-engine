import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import EventRecord
from app.schemas.event import SecurityEvent

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("", response_model=SecurityEvent, status_code=status.HTTP_201_CREATED)
def create_event(event: SecurityEvent, db: Session = Depends(get_db)) -> SecurityEvent:
    if db.get(EventRecord, event.event_id):
        raise HTTPException(status_code=409, detail="event_id already exists")

    record = EventRecord(
        event_id=event.event_id,
        timestamp=event.timestamp,
        event_type=event.event_type.value,
        severity=event.severity.value,
        hostname=event.host.hostname,
        username=event.user.username if event.user else None,
        source_vendor=event.source.vendor,
        source_product=event.source.product,
        payload=json.dumps(event.model_dump(mode="json")),
    )
    db.add(record)
    db.commit()
    return event


@router.get("", response_model=list[SecurityEvent])
def list_events(limit: int = 100, db: Session = Depends(get_db)) -> list[SecurityEvent]:
    if not 1 <= limit <= 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")
    records = db.scalars(select(EventRecord).order_by(EventRecord.timestamp.desc()).limit(limit)).all()
    return [SecurityEvent.model_validate(json.loads(record.payload)) for record in records]


@router.get("/{event_id}", response_model=SecurityEvent)
def get_event(event_id: str, db: Session = Depends(get_db)) -> SecurityEvent:
    record = db.get(EventRecord, event_id)
    if not record:
        raise HTTPException(status_code=404, detail="event not found")
    return SecurityEvent.model_validate(json.loads(record.payload))
