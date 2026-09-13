from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta

from app.db import get_db
from app.models import EventRecord
from app.schemas.event import SecurityEvent
from app.synthetic import generate_demo_events

router = APIRouter(prefix="/api/v1/demo", tags=["demo"])


@router.post("/seed")
def seed(db: Session = Depends(get_db)):
    events = generate_demo_events()
    created = 0
    for event in events:
        if db.get(EventRecord, event.event_id):
            continue
        import json
        db.add(EventRecord(event_id=event.event_id, timestamp=event.timestamp, event_type=event.event_type.value, severity=event.severity.value, hostname=event.host.hostname, username=event.user.username if event.user else None, source_vendor=event.source.vendor, source_product=event.source.product, payload=json.dumps(event.model_dump(mode="json"))))
        created += 1
    db.commit()
    return {"created": created, "total_demo_events": len(events), "next": "/api/v1/investigations"}
