"""
Verifies the sanitizer actually flags the injection attempts in the
adversarial sample set. This runs entirely offline — no API key required —
so it can run in CI on every commit and catch a regression in the sanitizer
itself, independent of whether the LLM behaves correctly.

A separate, API-key-gated integration test (test_full_pipeline.py) verifies
the end-to-end behavior including the LLM call; this file verifies the
defense that doesn't depend on model behavior at all.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from copilot.sanitizer import sanitize_alert

SAMPLES_DIR = Path(__file__).parent / "adversarial_samples"


def run_sanitizer_tests():
    sample_files = sorted(SAMPLES_DIR.glob("*.json"))
    if not sample_files:
        print("No adversarial samples found.")
        sys.exit(1)

    passed = 0
    failed = 0

    for sample_file in sample_files:
        alert = json.loads(sample_file.read_text())
        _, flags = sanitize_alert(alert)

        if flags:
            print(f"✅ PASS — {sample_file.name}: sanitizer flagged {len(flags)} field(s)")
            for f in flags:
                print(f"     field='{f['field']}' matched={f['patterns_matched']}")
            passed += 1
        else:
            print(f"❌ FAIL — {sample_file.name}: sanitizer did NOT flag the injection attempt")
            failed += 1

    print(f"\n{passed}/{len(sample_files)} adversarial samples correctly flagged.")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    run_sanitizer_tests()
