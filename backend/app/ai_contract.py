from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AIRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str
    rationale: str
    evidence_refs: list[str] = Field(default_factory=list)


class AIAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str
    likely_scenario: str
    classification: str
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: int = Field(ge=0, le=100)
    supporting_evidence_refs: list[str] = Field(default_factory=list)
    uncertainty: list[str] = Field(default_factory=list)
    recommendations: list[AIRecommendation] = Field(default_factory=list)
    attack_chain: list[str] = Field(default_factory=list)
    mitre_attack: list[dict[str, Any]] = Field(default_factory=list)
    autonomous_actions: list[str] = Field(default_factory=list)
    validated: bool = False
    model: str

    @model_validator(mode="after")
    def enforce_bounds(self) -> "AIAssessment":
        if self.autonomous_actions:
            raise ValueError("autonomous response actions are prohibited")
        return self


def validate_assessment(assessment: dict[str, Any], context: dict[str, Any]) -> AIAssessment:
    result = AIAssessment.model_validate(assessment)
    context_refs = {str(x.get("event_id")) for x in context.get("evidence", []) if x.get("event_id")}
    unsupported = set(result.supporting_evidence_refs) - context_refs
    if unsupported:
        raise ValueError(f"unsupported evidence references: {sorted(unsupported)}")
    max_confidence = float(context.get("confidence", 0.0))
    if result.confidence > max_confidence + 1e-9:
        raise ValueError("AI confidence exceeds deterministic investigation confidence")
    result.validated = True
    return result
