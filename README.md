# AI-Powered SOC Triage & Investigation Engine

Phase 1 — architecture and secure engineering foundation.

An AI-assisted SOC investigation platform for alert ingestion, telemetry normalization, evidence correlation, enrichment, MITRE ATT&CK mapping, and bounded AI-assisted investigation.

## Phase 1

- Architecture and component boundaries
- Threat model and trust boundaries
- Functional and non-functional requirements
- Investigation state model
- Security model
- Repository structure and development foundation
- CI baseline

## Design principle

Deterministic security logic remains authoritative. The LLM is an assistive reasoning component and must not independently make containment or detection decisions.

## Planned pipeline

`Ingestion → Normalization → Correlation → Evidence → Enrichment → ATT&CK → AI Investigation → Validation → Analyst Decision`

## Status

Phase 1 complete. Phase 2 will implement the common event schema and synthetic security telemetry.
