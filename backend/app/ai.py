from typing import Any


def investigate(context: dict[str, Any]) -> dict[str, Any]:
    """Deterministic fallback investigator; LLM adapters can replace this without changing the contract."""
    risk = int(context.get("risk_score", 0))
    classification = context.get("classification", "needs_review")
    chain = context.get("attack_chain", [])
    if risk >= 80: summary = "High-risk investigation with multiple correlated behaviors."
    elif risk >= 60: summary = "Suspicious investigation requiring analyst review."
    else: summary = "Insufficient evidence for a high-confidence malicious determination."
    return {
        "summary": summary,
        "assessment": {"classification": classification, "confidence": context.get("confidence", 0.0), "risk": risk},
        "attack_chain": chain,
        "mitre_attack": context.get("mitre_attack", []),
        "evidence": context.get("evidence", []),
        "missing_evidence": context.get("missing_evidence", []),
        "recommended_next_steps": ["Review correlated evidence", "Validate affected host and user", "Collect missing telemetry before containment"],
        "model": "deterministic-fallback-v1",
        "validated": True,
        "autonomous_actions": [],
    }
