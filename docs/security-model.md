# Security Model

## Principles
1. Zero trust for telemetry and external enrichment responses.
2. Least privilege for service accounts and AI tools.
3. Deterministic controls before probabilistic reasoning.
4. Structured data crossing trust boundaries.
5. Complete auditability of AI and analyst decisions.

## AI controls
- System instructions are separated from untrusted telemetry.
- Tool access is allowlisted.
- Model output is parsed and schema-validated.
- Confidence is not treated as proof.
- No autonomous destructive response actions.
- Sensitive evidence should be minimized before model submission.

## Application controls
- Validate all API payloads with Pydantic.
- Keep secrets out of source control.
- Apply authentication and RBAC before production exposure.
- Log security-relevant actions without leaking secrets.
