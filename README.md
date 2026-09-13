# AI-Powered SOC Triage & Investigation Engine

A production-oriented SOC investigation platform that turns security alerts and telemetry into structured, evidence-backed investigations.

## End-to-end MVP

The repository now contains an executable portfolio demonstrator spanning the roadmap pipeline:

`Ingestion → Normalization → Correlation → Evidence → Enrichment → ATT&CK → AI Investigation → Validation → Analyst Decision → Audit`

### Implemented capabilities

- Versioned vendor-neutral Pydantic security events
- PostgreSQL-compatible persistence with local SQLite fallback
- REST event and alert ingestion/retrieval
- Synthetic EDR/SIEM attack-chain telemetry
- Deterministic host/user correlation and risk scoring
- Evidence-linked investigation timeline
- Synthetic IOC extraction/enrichment adapter boundary
- Evidence-linked MITRE ATT&CK mapping
- Bounded deterministic AI investigator contract
- Analyst decision endpoint with explicit authorization boundary
- Lightweight analyst console at `/`
- Automated unit/API/e2e-oriented tests
- GitHub Actions CI and Railway Docker deployment
- Operations runbook and security architecture documentation

## Quick start

```bash
cd backend
python -m pip install -e '.[test]'
pytest -q
uvicorn app.main:app --reload
```

Open `http://localhost:8000/` for the console or `/docs` for OpenAPI.

### Run the demonstration

```text
POST /api/v1/demo/seed
GET  /api/v1/investigations
POST /api/v1/investigations/{investigation_id}/decision?decision=escalate&analyst=analyst
```

The synthetic scenario models login → Word/PowerShell → encoded command → external connection → scheduled task. No real malicious payloads are used.

## Safety boundary

AI output is advisory and validated. It cannot independently isolate hosts, terminate processes, delete files, disable accounts, block IPs, or perform other containment actions. Response requires explicit analyst/policy authorization.

## Production configuration

Set `DATABASE_URL` to managed PostgreSQL in Railway. Secrets/API keys must be stored as platform secrets and never committed. Real threat-intelligence and LLM providers should implement adapters behind the existing normalized contracts.

## Roadmap status

- [x] Phase 1 — Foundation & Deployment
- [x] Phase 2 — Common Event Schema
- [x] Phase 3 — Alert Ingestion
- [x] Phase 4 — Detection & Correlation
- [x] Phase 5 — Investigation Timeline
- [x] Phase 6 — Threat Intelligence adapter
- [x] Phase 7 — MITRE ATT&CK mapping
- [x] Phase 8 — Bounded AI investigation contract
- [x] Phase 9 — Analyst Console MVP
- [x] Phase 10 — Evaluation baseline
- [x] Phase 11 — Production deployment foundation
- [x] Phase 12 — Portfolio Demonstrator MVP

See `docs/operations.md` and the project issue for implementation tracking.
