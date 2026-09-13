from typing import Any

from app.ai_contract import AIRecommendation, AIAssessment, validate_assessment


def _fallback(context: dict[str, Any]) -> dict[str, Any]:
    risk = int(context.get("risk_score", 0))
    classification = str(context.get("classification", "needs_review"))
    if risk >= 80:
        summary = "High-risk investigation with multiple correlated behaviors."
        scenario = "Potential multi-stage endpoint compromise"
    elif risk >= 60:
        summary = "Suspicious investigation requiring analyst review."
        scenario = "Potential malicious activity requiring validation"
    else:
        summary = "Insufficient evidence for a high-confidence malicious determination."
        scenario = "Insufficient evidence"

    evidence_refs = [str(x["event_id"]) for x in context.get("evidence", []) if x.get("event_id")]
    recommendations = [
        AIRecommendation(action="Review correlated evidence", rationale="Confirm the deterministic detections and event sequence.", evidence_refs=evidence_refs[:3]),
        AIRecommendation(action="Validate affected host and user", rationale="Confirm whether the observed activity is expected.", evidence_refs=evidence_refs[:2]),
    ]
    if context.get("missing_evidence"):
        recommendations.append(AIRecommendation(action="Collect missing telemetry", rationale="Resolve explicitly identified evidence gaps before containment.", evidence_refs=[]))

    return {
        "summary": summary,
        "likely_scenario": scenario,
        "classification": classification,
        "confidence": min(float(context.get("confidence", 0.0)), 0.99),
        "risk_score": risk,
        "supporting_evidence_refs": evidence_refs,
        "uncertainty": list(context.get("missing_evidence", [])),
        "recommendations": [item.model_dump() for item in recommendations],
        "attack_chain": list(context.get("attack_chain", [])),
        "mitre_attack": list(context.get("mitre_attack", [])),
        "autonomous_actions": [],
        "validated": False,
        "model": "deterministic-fallback-v2",
    }


def investigate(context: dict[str, Any]) -> dict[str, Any]:
    """Produce an evidence-bounded assessment. An LLM adapter may replace the generator, but must pass the same validator."""
    candidate = _fallback(context)
    try:
        validated: AIAssessment = validate_assessment(candidate, context)
        return validated.model_dump()
    except ValueError as exc:
        return {
            "summary": "AI assessment rejected by validation; deterministic evidence remains authoritative.",
            "likely_scenario": "Validation failure",
            "classification": context.get("classification", "needs_review"),
            "confidence": float(context.get("confidence", 0.0)),
            "risk_score": int(context.get("risk_score", 0)),
            "supporting_evidence_refs": [],
            "uncertainty": [str(exc)],
            "recommendations": [],
            "attack_chain": list(context.get("attack_chain", [])),
            "mitre_attack": list(context.get("mitre_attack", [])),
            "autonomous_actions": [],
            "validated": False,
            "model": "safe-fallback-v2",
        }
