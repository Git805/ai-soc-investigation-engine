# Investigation Model

## Lifecycle
`NEW → TRIAGING → COLLECTING → CORRELATING → ENRICHING → ANALYZING → REVIEW → CLOSED`

## Core entities
- Alert
- Event
- Host
- User
- Process
- File
- Hash
- IP
- Domain
- URL
- Technique
- Investigation
- Evidence
- AnalystDecision

## Evidence relationship examples
- Host EXECUTED Process
- Process CREATED File
- Process CONNECTED_TO IP
- Domain RESOLVED_TO IP
- User AUTHENTICATED_TO Host
- Alert REFERENCES Event
- Evidence SUPPORTS Hypothesis

## AI result requirements
Every hypothesis must contain confidence, supporting evidence references, contradictory evidence when available, mapped techniques, missing evidence, and recommended next investigative steps.