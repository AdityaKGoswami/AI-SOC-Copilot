"""Deterministic incident-investigation pipeline for the demo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ai_analyst import build_assessment
from .detector import detect


def load_events(path: str | Path) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("Event file must contain a JSON array")
    return data


def investigate_incident(path: str | Path) -> dict[str, Any]:
    events = load_events(path)
    if not events:
        raise ValueError("No events supplied")

    findings = detect(events)
    ai_assessment = build_assessment(events, findings)

    timeline = []
    for event in events:
        timeline.append(
            {
                "timestamp": event["timestamp"],
                "host": event.get("host", "-"),
                "user": event.get("user", "-"),
                "event_type": event.get("event_type", "-"),
                "source_ip": event.get("source_ip", "-"),
                "command": event.get("command", "-"),
            }
        )

    incident_id = events[0].get("incident_id", "SIM-INCIDENT-001")
    summary = {
        "incident_id": incident_id,
        "event_count": len(events),
        "finding_count": len(findings),
        "severity": ai_assessment["severity"],
        "confidence": ai_assessment["confidence"],
    }

    return {
        "summary": summary,
        "timeline": timeline,
        "findings": findings,
        "ai_assessment": ai_assessment,
    }
