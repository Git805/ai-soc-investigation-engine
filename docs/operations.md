# SOC Investigation Engine — Operations Runbook

## Local

1. Install backend test dependencies with `pip install -e './backend[test]'`.
2. Run `cd backend && pytest -q`.
3. Start with `uvicorn app.main:app --reload` from `backend`.
4. Open `/docs` for OpenAPI and `/` for the analyst console.
5. Seed the deterministic demonstration with `POST /api/v1/demo/seed`.
6. Review `GET /api/v1/investigations`.

## Production

- Set `DATABASE_URL` to the managed PostgreSQL connection string.
- Never commit secrets or provider API keys.
- Require authenticated analyst access before enabling response integrations.
- Keep AI actions advisory; containment requires explicit analyst/policy authorization.
- Record deployment commit SHA and retain a known-good rollback point.

## Demo flow

`POST /api/v1/demo/seed` → `GET /api/v1/investigations` → inspect evidence/timeline/ATT&CK/AI assessment → `POST /api/v1/investigations/{id}/decision`.
