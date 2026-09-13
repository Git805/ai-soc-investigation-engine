import pytest
from pydantic import ValidationError

from app.ai_contract import AIAssessment, validate_assessment


def _context():
    return {"risk_score": 80, "confidence": 0.74, "evidence": [{"event_id": "evt-1"}], "missing_evidence": []}


def _assessment(**overrides):
    value = {
        "summary": "test",
        "likely_scenario": "test scenario",
        "classification": "likely_malicious",
        "confidence": 0.70,
        "risk_score": 80,
        "supporting_evidence_refs": ["evt-1"],
        "uncertainty": [],
        "recommendations": [],
        "attack_chain": [],
        "mitre_attack": [],
        "autonomous_actions": [],
        "validated": False,
        "model": "test",
    }
    value.update(overrides)
    return value


def test_validation_accepts_supported_evidence():
    result = validate_assessment(_assessment(), _context())
    assert result.validated is True


def test_validation_rejects_unknown_evidence():
    with pytest.raises(ValueError, match="unsupported evidence"):
        validate_assessment(_assessment(supporting_evidence_refs=["evt-nope"]), _context())


def test_validation_rejects_confidence_above_deterministic_confidence():
    with pytest.raises(ValueError, match="confidence"):
        validate_assessment(_assessment(confidence=0.90), _context())


def test_autonomous_actions_are_prohibited():
    with pytest.raises(ValidationError, match="autonomous response actions"):
        AIAssessment.model_validate(_assessment(autonomous_actions=["isolate host"]))
