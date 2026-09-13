from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
import json

from app.db import get_db
from app.models import EventRecord
from app.engine import correlate, risk_summary
from app.intel import extract_indicators, enrich
from app.mitre import map_techniques
from app.ai import investigate

router = APIRouter(prefix="/api/v1/investigations", tags=["investigations"])


def _events(db):
    records = db.scalars(select(EventRecord).order_by(EventRecord.timestamp.asc())).all()
    from app.schemas.event import SecurityEvent
    return [SecurityEvent.model_validate(json.loads(r.payload)) for r in records]


def _build(db):
    investigations = []
    for inv in correlate(_events(db)):
        data = risk_summary(inv)
        data["indicators"] = enrich(extract_indicators(inv.events))
        data["mitre_attack"] = map_techniques(inv.events)
        data["ai_assessment"] = investigate(data)
        investigations.append(data)
    return investigations


@router.get("")
def list_investigations(db: Session = Depends(get_db)):
    return _build(db)


@router.get("/{investigation_id}")
def get_investigation(investigation_id: str, db: Session = Depends(get_db)):
    item = next((x for x in _build(db) if x["investigation_id"] == investigation_id), None)
    if not item: raise HTTPException(404, "investigation not found")
    return item


@router.post("/{investigation_id}/decision")
def analyst_decision(investigation_id: str, decision: str, analyst: str = "analyst"):
    if decision not in {"approve", "decline", "escalate"}:
        raise HTTPException(400, "decision must be approve, decline, or escalate")
    return {"investigation_id": investigation_id, "decision": decision, "analyst": analyst, "authorized": True, "actions_executed": []}
