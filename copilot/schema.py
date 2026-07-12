"""
Defines and validates the structured output we require from the LLM.
If the model's response doesn't match this shape, we treat it as a failed
triage rather than trusting a malformed or unexpected response — this
matters because a successful prompt injection often shows up as the model
breaking its expected output format (e.g. suddenly returning prose instead
of JSON, or a verdict field with a value we never defined).
"""

REQUIRED_FIELDS = {
    "attack_technique": str,   # MITRE ATT&CK technique ID, or "UNKNOWN"
    "severity": str,           # "Low" | "Medium" | "High" | "Critical"
    "confidence": (int, float),
    "recommended_action": str,
    "explanation": str,
    "injection_attempt_detected": bool,
}

VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}


class SchemaValidationError(Exception):
    pass


def validate_triage_output(data: dict) -> dict:
    if not isinstance(data, dict):
        raise SchemaValidationError(f"Expected a JSON object, got {type(data).__name__}")

    for field_name, expected_type in REQUIRED_FIELDS.items():
        if field_name not in data:
            raise SchemaValidationError(f"Missing required field: {field_name}")
        if not isinstance(data[field_name], expected_type):
            raise SchemaValidationError(
                f"Field '{field_name}' has wrong type: expected {expected_type}, "
                f"got {type(data[field_name]).__name__}"
            )

    if data["severity"] not in VALID_SEVERITIES:
        raise SchemaValidationError(
            f"Invalid severity '{data['severity']}' — must be one of {VALID_SEVERITIES}"
        )

    if not (0 <= data["confidence"] <= 100):
        raise SchemaValidationError(f"Confidence must be 0-100, got {data['confidence']}")

    return data
