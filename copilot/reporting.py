"""Human-readable incident report generation."""


def render_markdown_report(result: dict) -> str:
    summary = result["summary"]
    ai = result["ai_assessment"]

    lines = [
        f"# Incident Report: {summary['incident_id']}",
        "",
        f"**Severity:** {summary['severity']}",
        f"**Confidence:** {summary['confidence']}%",
        f"**Events analyzed:** {summary['event_count']}",
        f"**Detection findings:** {summary['finding_count']}",
        "",
        "## Executive Assessment",
        ai["threat_summary"],
        "",
        "## Attack Classification",
        ai["attack_technique"],
        "",
        "## Evidence-Linked Reasoning",
    ]
    lines.extend(f"- {item}" for item in ai["reasoning"])

    lines.extend(["", "## Detection Findings"])
    for finding in result["findings"]:
        lines.append(
            f"- **{finding['rule_id']} — {finding['title']}** ({finding['severity']}): "
            f"{finding['evidence']}"
        )

    lines.extend(["", "## Recommended Response"])
    lines.extend(f"1. {action}" for action in ai["recommended_actions"])

    lines.extend([
        "",
        "## Timeline",
        "| Timestamp | Host | User | Event | Source IP | Command |",
        "|---|---|---|---|---|---|",
    ])
    for row in result["timeline"]:
        lines.append(
            f"| {row['timestamp']} | {row['host']} | {row['user']} | "
            f"{row['event_type']} | {row['source_ip']} | {row['command']} |"
        )

    return "\n".join(lines) + "\n"
