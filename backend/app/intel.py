from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Protocol

from app.schemas.event import SecurityEvent

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b")
NON_DOMAIN_SUFFIXES = {"exe", "dll", "sys", "bat", "cmd", "ps1", "com"}


@dataclass(frozen=True)
class IOCResult:
    indicator: str
    type: str
    reputation: str
    provider: str
    confidence: float
    first_seen: str | None
    evidence_refs: list[str]


class ThreatIntelProvider(Protocol):
    name: str

    def lookup(self, indicator: str, indicator_type: str) -> dict[str, Any]: ...


class SyntheticThreatIntelProvider:
    name = "synthetic"

    def lookup(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        value = indicator.lower()
        if value in {"8.8.8.8", "1.1.1.1"}:
            return {"reputation": "benign", "confidence": 0.95}
        if value in {"203.0.113.10", "198.51.100.25", "malicious.example"}:
            return {"reputation": "malicious", "confidence": 0.92}
        if indicator_type == "ip" and _is_private_ip(value):
            return {"reputation": "internal", "confidence": 0.99}
        return {"reputation": "unknown", "confidence": 0.40}


PROVIDER = SyntheticThreatIntelProvider()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _indicator_type(value: str) -> str:
    return "ip" if _is_ip(value) else "domain"


def _is_domain_candidate(value: str) -> bool:
    suffix = value.rsplit(".", 1)[-1].lower()
    return suffix not in NON_DOMAIN_SUFFIXES


def extract_indicators(events: list[SecurityEvent]) -> list[dict[str, Any]]:
    found: dict[str, set[str]] = {}
    for event in events:
        values: list[str] = []
        if event.network:
            values.extend(
                value
                for value in (
                    event.network.source_ip,
                    event.network.destination_ip,
                    event.network.destination_domain,
                )
                if value
            )
        if event.process and event.process.command_line:
            values.extend(IP_RE.findall(event.process.command_line))
            values.extend(
                value
                for value in DOMAIN_RE.findall(event.process.command_line)
                if _is_domain_candidate(value)
            )
        for value in values:
            normalized = value.strip().lower()
            if normalized:
                found.setdefault(normalized, set()).add(event.event_id)

    return [
        {"indicator": value, "type": _indicator_type(value), "evidence_refs": sorted(refs)}
        for value, refs in sorted(found.items())
    ]


@lru_cache(maxsize=1024)
def _lookup(indicator: str, indicator_type: str) -> dict[str, Any]:
    return PROVIDER.lookup(indicator, indicator_type)


def enrich(indicators: list[dict[str, Any]] | list[str]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in indicators:
        if isinstance(item, str):
            normalized.append({"indicator": item, "type": _indicator_type(item), "evidence_refs": []})
        else:
            normalized.append(item)

    results = []
    for item in normalized:
        value = item["indicator"]
        indicator_type = item.get("type") or _indicator_type(value)
        result = _lookup(value, indicator_type)
        results.append(
            IOCResult(
                indicator=value,
                type=indicator_type,
                reputation=result["reputation"],
                provider=PROVIDER.name,
                confidence=float(result["confidence"]),
                first_seen=None,
                evidence_refs=sorted(set(item.get("evidence_refs", []))),
            ).__dict__
        )
    return results


def enrich_events(events: list[SecurityEvent]) -> list[dict[str, Any]]:
    return enrich(extract_indicators(events))


def intelligence_summary(events: list[SecurityEvent]) -> dict[str, Any]:
    results = enrich_events(events)
    malicious = [item for item in results if item["reputation"] == "malicious"]
    return {
        "provider": PROVIDER.name,
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "indicator_count": len(results),
        "malicious_count": len(malicious),
        "indicators": results,
    }
