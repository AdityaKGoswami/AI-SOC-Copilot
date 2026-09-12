import json
from pathlib import Path

from copilot.detector import detect
from copilot.investigation import investigate_incident


ROOT = Path(__file__).parents[1]
DATA = ROOT / "data" / "simulated_attack.json"


def test_dataset_is_valid_json():
    payload = json.loads(DATA.read_text(encoding="utf-8"))
    assert len(payload) == 8
    assert payload[-1]["event_type"] == "persistence"


def test_detections_cover_multi_stage_attack():
    events = json.loads(DATA.read_text(encoding="utf-8"))
    findings = detect(events)
    rule_ids = {item["rule_id"] for item in findings}
    assert {"DET-001", "DET-002", "DET-003", "DET-004", "DET-005", "DET-006"}.issubset(rule_ids)


def test_end_to_end_investigation():
    result = investigate_incident(DATA)
    assert result["summary"]["incident_id"] == "SIM-APT-001"
    assert result["summary"]["severity"] == "Critical"
    assert result["summary"]["confidence"] >= 90
    assert len(result["timeline"]) == 8
    assert len(result["findings"]) >= 6
