import ipaddress
import re


def extract_indicators(events):
    indicators = set()
    for event in events:
        if event.network:
            for value in (event.network.source_ip, event.network.destination_ip, event.network.domain):
                if value: indicators.add(value)
        if event.process and event.process.command_line:
            indicators.update(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", event.process.command_line))
    return sorted(indicators)


def enrich(indicators):
    results = []
    for value in indicators:
        kind = "ip" if _is_ip(value) else "domain"
        reputation = "unknown" if kind == "ip" else "unclassified"
        results.append({"indicator": value, "type": kind, "reputation": reputation, "provider": "synthetic", "evidence_refs": []})
    return results


def _is_ip(value):
    try:
        ipaddress.ip_address(value); return True
    except ValueError:
        return False
