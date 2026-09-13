import json

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.attack import attack_summary
from app.db import get_db
from app.engine import correlate
from app.models import EventRecord
from app.schemas.event import SecurityEvent

router = APIRouter(prefix="/api/v1/attack", tags=["mitre-attack"])


def _investigations(db: Session):
    records = db.scalars(select(EventRecord).order_by(EventRecord.timestamp.asc())).all()
    events = [SecurityEvent.model_validate(json.loads(record.payload)) for record in records]
    return correlate(events)


@router.get("")
def get_attack_mappings(db: Session = Depends(get_db)) -> dict:
    return attack_summary(_investigations(db))
