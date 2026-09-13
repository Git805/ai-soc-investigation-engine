from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from app.schemas.event import Severity


class AlertStatus(StrEnum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"


class Alert(BaseModel):
    alert_id: str = Field(min_length=1)
    timestamp: datetime
    title: str = Field(min_length=1)
    severity: Severity
    status: AlertStatus = AlertStatus.NEW
    source: str = Field(min_length=1)
    description: str | None = None
    event_ids: list[str] = Field(default_factory=list)
