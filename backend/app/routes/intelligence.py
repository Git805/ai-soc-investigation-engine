from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session
import json

from app.db import get_db
from app.models import EventRecord
from app.intel import intelligence_summary
from app.schemas.event import SecurityEvent

router = APIRouter(prefix="/api/v1/intelligence", tags=["threat-intelligence"])


def _events(db: Session) -> list[SecurityEvent]:
    records = db.scalars(select(EventRecord).order_by(EventRecord.timestamp.asc())).all()
    return [SecurityEvent.model_validate(json.loads(record.payload)) for record in records]


@router.get("")
def get_intelligence(db: Session = Depends(get_db)) -> dict:
    return intelligence_summary(_events(db))
