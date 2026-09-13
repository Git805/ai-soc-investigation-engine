# Threat Model

## Assets
- Security telemetry
- Investigation evidence
- Analyst decisions
- Credentials and API keys
- Threat-intelligence data
- LLM prompts and outputs

## Primary threats
- T01 Prompt injection through telemetry
- T02 Malicious or poisoned telemetry
- T03 LLM hallucination
- T04 Tool abuse
- T05 Unauthorized investigation access
- T06 Credential exposure
- T07 Data exfiltration through model context
- T08 SSRF through enrichment tooling
- T09 Output schema manipulation
- T10 Evidence tampering
- T11 Supply-chain compromise
- T12 Denial of service

## Mitigations
- Treat all telemetry as untrusted data.
- Strict tool allowlisting.
- Structured model outputs with schema validation.
- No autonomous containment actions.
- RBAC and authenticated APIs.
- Secret injection through environment/secret managers.
- Audit all analyst and AI decisions.
- Network egress controls for enrichment services.
- Immutable event identifiers and timestamps.

## Security principle
AI output is advisory until validated and reviewed by deterministic controls and/or an analyst.