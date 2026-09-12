"""Simple detection-as-code layer for a simulated multi-stage intrusion."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        by_user[event.get("user", "-")].append(event)
        by_src[event.get("source_ip", "-")].append(event)

    for event in events:
        etype = event.get("event_type")
        command = (event.get("command") or "").lower()

        if etype == "failed_login":
            findings.append({
                "rule_id": "DET-001",
                "title": "Repeated authentication failures",
                "severity": "Medium",
                "evidence": f"{event.get('user')} from {event.get('source_ip')}",
                "event_timestamp": event.get("timestamp"),
            })

        if etype == "successful_login" and event.get("source_ip") in by_src:
            failures = sum(1 for e in by_src[event.get("source_ip")] if e.get("event_type") == "failed_login")
            if failures >= 3:
                findings.append({
                    "rule_id": "DET-002",
                    "title": "Password spraying / brute-force success",
                    "severity": "High",
                    "evidence": f"Successful login after {failures} failures from {event.get('source_ip')}",
                    "event_timestamp": event.get("timestamp"),
                })

        if "powershell" in command and ("-enc" in command or "downloadstring" in command):
            findings.append({
                "rule_id": "DET-003",
                "title": "Suspicious PowerShell execution",
                "severity": "High",
                "evidence": event.get("command"),
                "event_timestamp": event.get("timestamp"),
            })

        if etype == "credential_access":
            findings.append({
                "rule_id": "DET-004",
                "title": "Credential access activity",
                "severity": "Critical",
                "evidence": event.get("details", "Credential material accessed"),
                "event_timestamp": event.get("timestamp"),
            })

        if etype == "lateral_movement":
            findings.append({
                "rule_id": "DET-005",
                "title": "Lateral movement to internal host",
                "severity": "High",
                "evidence": f"{event.get('source_host')} → {event.get('destination_host')}",
                "event_timestamp": event.get("timestamp"),
            })

        if etype == "persistence":
            findings.append({
                "rule_id": "DET-006",
                "title": "Persistence mechanism created",
                "severity": "Critical",
                "evidence": event.get("details", "Persistence created"),
                "event_timestamp": event.get("timestamp"),
            })

    return findings
