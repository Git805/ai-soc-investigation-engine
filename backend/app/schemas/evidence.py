from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class EvidenceType(StrEnum):
    EVENT = "event"
    RULE_HIT = "rule_hit"
    ALERT = "alert"
    IOC = "ioc"
    ATTACK_TECHNIQUE = "attack_technique"


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1)
    evidence_type: EvidenceType
    timestamp: datetime
    source: str = Field(min_length=1)
    reference_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    provenance: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    investigation_id: str = Field(min_length=1)


class EvidenceLedger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    generated_at: datetime
    items: list[EvidenceItem]
    item_count: int = Field(ge=0)
