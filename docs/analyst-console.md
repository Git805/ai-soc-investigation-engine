# Phase 9 — Analyst Console

The web console is a thin analyst-facing view over the existing investigation API.

## Workflow

1. Load investigations from `/api/v1/investigations`.
2. Filter by classification.
3. Select an investigation.
4. Review risk, confidence, attack chain, event evidence/timeline, IOC/TI results, ATT&CK mappings and AI assessment.
5. Review AI recommendations.
6. Record an analyst decision: approve, escalate or decline.

The console does not execute containment or remediation. Decision responses explicitly report an empty `actions_executed` list.

## Deployment

The FastAPI `/` route serves `frontend/index.html`, so the same container exposes both the API and analyst console.
