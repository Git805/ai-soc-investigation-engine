# Phase 8 — Bounded AI Investigation

The AI layer is advisory. Deterministic correlation, risk scoring, evidence, threat intelligence, and ATT&CK mapping remain authoritative.

## Contract

Every assessment contains:

- summary and likely scenario
- classification, risk score, and confidence
- supporting evidence references
- explicit uncertainty/evidence gaps
- recommended analyst next steps
- ATT&CK context supplied by deterministic mapping
- zero autonomous response actions

## Validation

The validator rejects:

1. evidence references that are not present in the investigation context;
2. AI confidence above deterministic investigation confidence;
3. any autonomous response action.

Rejected assessments fall back to a safe, non-actionable response. An LLM adapter can be added later behind the same contract; the adapter cannot bypass validation.
