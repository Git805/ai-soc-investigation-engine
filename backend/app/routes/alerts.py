import json
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import AlertRecord
from app.schemas.alert import Alert

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

@router.post("", response_model=Alert, status_code=status.HTTP_201_CREATED)
def create_alert(alert: Alert, db: Session = Depends(get_db)):
    if db.get(AlertRecord, alert.alert_id):
        raise HTTPException(409, "alert_id already exists")
    db.add(AlertRecord(alert_id=alert.alert_id, timestamp=alert.timestamp, title=alert.title, severity=alert.severity.value, status=alert.status.value, source=alert.source, description=alert.description, event_ids=json.dumps(alert.event_ids)))
    db.commit()
    return alert

@router.get("", response_model=list[Alert])
def list_alerts(limit: int = 100, db: Session = Depends(get_db)):
    if not 1 <= limit <= 500: raise HTTPException(400, "limit must be between 1 and 500")
    rows = db.scalars(select(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(limit)).all()
    return [Alert(alert_id=r.alert_id, timestamp=r.timestamp, title=r.title, severity=r.severity, status=r.status, source=r.source, description=r.description, event_ids=json.loads(r.event_ids)) for r in rows]
