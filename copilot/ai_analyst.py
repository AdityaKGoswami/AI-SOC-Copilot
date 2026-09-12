"""AI-style reasoning layer.

The deterministic mode deliberately derives its conclusions from observable
signals. This keeps the demo reproducible. An external LLM can later consume
the same normalized evidence bundle without changing the detection layer.
"""

from __future__ import annotations

from typing import Any


def build_assessment(events: list[dict[str, Any]], findings: list[dict[str, Any]]) -> dict[str, Any]:
    titles = {f["rule_id"]: f["title"] for f in findings}
    rule_ids = set(titles)

    if {"DET-003", "DET-004", "DET-005"}.issubset(rule_ids) or "DET-006" in rule_ids:
        severity = "Critical"
        confidence = 96
    elif len(findings) >= 3:
        severity = "High"
        confidence = 91
    elif findings:
        severity = "Medium"
        confidence = 78
    else:
        severity = "Low"
        confidence = 45

    technique = "T1059.001 / T1003 / T1021 / T1547"
    threat_summary = (
        "The telemetry supports a multi-stage intrusion beginning with credential abuse, "
        "followed by execution, credential access, lateral movement, and persistence."
    )

    reasoning = []
    if "DET-002" in rule_ids:
        reasoning.append("Authentication evidence shows repeated failures followed by a successful login from the same source, consistent with credential attack activity.")
    if "DET-003" in rule_ids:
        reasoning.append("Encoded or download-capable PowerShell provides an execution signal that is materially stronger than a generic process start.")
    if "DET-004" in rule_ids:
        reasoning.append("Credential access appears after initial execution, indicating post-compromise discovery or credential theft rather than isolated login noise.")
    if "DET-005" in rule_ids:
        reasoning.append("The same investigation contains internal host movement, linking endpoint activity into a broader attack path.")
    if "DET-006" in rule_ids:
        reasoning.append("Persistence creation increases the likelihood that the attacker intended to retain access beyond the initial session.")

    recommended_actions = [
        "Isolate affected hosts from the network while preserving forensic evidence.",
        "Disable or rotate the compromised account and invalidate active sessions.",
        "Collect endpoint process, PowerShell, authentication, and persistence telemetry for the incident window.",
        "Hunt for the same source IP, credential artifact, and execution pattern across the environment.",
    ]

    return {
        "attack_technique": technique,
        "severity": severity,
        "confidence": confidence,
        "threat_summary": threat_summary,
        "reasoning": reasoning,
        "recommended_actions": recommended_actions,
    }
