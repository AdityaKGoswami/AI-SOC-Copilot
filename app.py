"""Streamlit UI for the AI Security Analyst demo."""

import json
from pathlib import Path

import streamlit as st

from copilot.investigation import investigate_incident
from copilot.reporting import render_markdown_report

st.set_page_config(page_title="AI Security Analyst", page_icon="🛡️", layout="wide")

ROOT = Path(__file__).parent
DEFAULT_EVENTS = ROOT / "data" / "simulated_attack.json"

st.title("AI Security Analyst")
st.caption("Simulated incident investigation: telemetry → detection → correlation → AI-assisted analysis → analyst report")

with st.sidebar:
    st.header("Investigation")
    event_file = st.text_input("Event file", str(DEFAULT_EVENTS))
    run_button = st.button("Run investigation", type="primary", use_container_width=True)

    st.divider()
    st.markdown("**Mode**")
    st.code("LOCAL / DETERMINISTIC", language="text")
    st.markdown("No external API is required for the core investigation.")

if run_button or "result" not in st.session_state:
    try:
        result = investigate_incident(event_file)
        st.session_state.result = result
    except Exception as exc:
        st.error(f"Investigation failed: {exc}")
        st.stop()

result = st.session_state.result
summary = result["summary"]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Incident", summary["incident_id"])
c2.metric("Severity", summary["severity"])
c3.metric("Confidence", f"{summary['confidence']}%")
c4.metric("Events", summary["event_count"])

st.divider()

left, right = st.columns([1.15, 0.85])
with left:
    st.subheader("Attack timeline")
    st.dataframe(result["timeline"], use_container_width=True, hide_index=True)

with right:
    st.subheader("Detection findings")
    for finding in result["findings"]:
        st.markdown(
            f"**{finding['rule_id']} — {finding['title']}**  \n"
            f"Severity: `{finding['severity']}`  \n"
            f"Evidence: {finding['evidence']}"
        )

st.divider()

st.subheader("AI analyst assessment")
ai = result["ai_assessment"]

ac1, ac2 = st.columns(2)
with ac1:
    st.markdown(f"**Attack classification:** `{ai['attack_technique']}`")
    st.markdown(f"**Threat:** {ai['threat_summary']}")
    st.markdown(f"**Confidence:** {ai['confidence']}%")
with ac2:
    st.markdown("**Recommended actions**")
    for action in ai["recommended_actions"]:
        st.markdown(f"- {action}")

st.subheader("Evidence-linked reasoning")
for item in ai["reasoning"]:
    st.markdown(f"- {item}")

st.divider()

st.subheader("Analyst report")
report = render_markdown_report(result)
st.download_button(
    "Download incident report",
    report,
    file_name=f"{summary['incident_id']}_report.md",
    mime="text/markdown",
)
st.code(report, language="markdown")

with st.expander("Raw investigation output"):
    st.json(result)
