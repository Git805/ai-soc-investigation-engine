# AI-Powered SOC Triage & Investigation Engine

A production-oriented SOC investigation platform that turns security alerts and telemetry into structured, evidence-backed investigations.

## Roadmap

The implementation follows the master project plan from Phase 1 Foundation through Phase 12 Release. The core pipeline is:

`Ingestion → Normalization → Correlation → Evidence → Enrichment → ATT&CK → AI Investigation → Validation → Analyst Decision → Audit`

## Current status

**Phase 2 — Common Event Schema / persistence in progress**

Implemented:
- FastAPI service and `/health` endpoint
- Versioned, vendor-neutral security event schema using Pydantic
- Process, network and authentication event data models
- Canonical alert model
- PostgreSQL-compatible SQLAlchemy persistence (`DATABASE_URL`)
- REST event ingestion and retrieval
- Synthetic SOC telemetry fixtures
- Automated schema and API tests
- GitHub Actions CI
- Railway deployment foundation

## API

- `GET /health`
- `POST /api/v1/events`
- `GET /api/v1/events`
- `GET /api/v1/events/{event_id}`

## Architecture principles

Deterministic security logic, evidence and explicit analyst/policy controls remain authoritative. AI is an assistive reasoning component and cannot independently execute containment actions.

## Development

```bash
cd backend
python -m pip install -e '.[test]'
pytest -q
uvicorn app.main:app --reload
```

Set `DATABASE_URL` to a PostgreSQL connection string in deployed environments. Local development falls back to SQLite so the API and tests remain runnable without external infrastructure.

## Repository strategy

- `main` — stable release baseline
- `develop` — integration branch
- `feature/*` — phase/workstream implementation branches

See `docs/` for architecture, security and project planning material.
