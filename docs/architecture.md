# Architecture

## Goal
Build an AI-assisted SOC investigation platform that ingests security alerts, normalizes telemetry, correlates evidence, enriches indicators, maps activity to MITRE ATT&CK, and provides bounded AI-assisted investigation.

## Trust boundaries
1. External security telemetry → ingestion boundary.
2. Ingestion → normalized internal events.
3. Internal evidence → AI context boundary.
4. LLM output → validation boundary.
5. Analyst → response decision boundary.

## Core flow
`Ingestion → Normalization → Correlation → Evidence → Enrichment → ATT&CK → AI Investigation → Validation → Analyst Decision`

## Components
- FastAPI ingestion/API layer
- Event normalization service
- Deterministic correlation engine
- PostgreSQL evidence store
- Threat-intelligence enrichment adapters
- MITRE ATT&CK mapping engine
- AI investigation orchestrator
- Output validator
- Analyst UI
- Audit logging

## AI boundary
The LLM receives structured, explicitly labelled evidence. It does not receive arbitrary SQL, shell, filesystem, or unrestricted network capabilities. Deterministic security logic remains authoritative.