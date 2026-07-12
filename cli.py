"""
CLI entrypoint.

Usage:
    python cli.py samples/example_alert.json
    python cli.py tests/adversarial_samples/injection_in_filename.json

Defaults to LLM_PROVIDER=mock if not set, so it runs out of the box with
no API key — set LLM_PROVIDER=anthropic or openai in .env for real analysis.
"""

import sys
import json
import os
from dotenv import load_dotenv

load_dotenv()
os.environ.setdefault("LLM_PROVIDER", "mock")

from copilot.triage import triage_alert


def main():
    if len(sys.argv) != 2:
        print("Usage: python cli.py <path_to_alert.json>")
        sys.exit(1)

    alert_path = sys.argv[1]
    with open(alert_path) as f:
        alert = json.load(f)

    print(f"Provider: {os.environ['LLM_PROVIDER']}")
    print(f"Analyzing: {alert_path}\n")

    result = triage_alert(alert)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
