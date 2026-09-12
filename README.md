# Build Your Own AI Security Analyst

A runnable defensive cybersecurity project that investigates a simulated multi-stage intrusion from raw telemetry to an analyst-ready incident report.

## What this project demonstrates

```text
Simulated telemetry
        ↓
Detection-as-code
        ↓
Evidence correlation
        ↓
AI-style analyst reasoning
        ↓
Severity + ATT&CK mapping
        ↓
Recommended response
        ↓
Incident report
```

The default path is deterministic and local. No LLM API key is required to run the investigation. This is intentional: the detection and evidence pipeline should remain reproducible instead of making the demo dependent on an external model.

## Attack scenario

The included dataset models a simple enterprise intrusion:

1. Repeated VPN authentication failures.
2. Successful authentication from the same external source.
3. Encoded PowerShell execution on a workstation.
4. Credential access through LSASS.
5. Lateral movement from the workstation to a file server.
6. Persistence through a scheduled task.

All telemetry is simulated and safe for local testing.

## Project structure

```text
AI-SOC-Copilot/
├── app.py                         # Streamlit analyst dashboard
├── cli.py                         # Original CLI triage entry point
├── copilot/
│   ├── ai_analyst.py              # Evidence-based analyst reasoning
│   ├── detector.py                # Detection rules
│   ├── investigation.py           # End-to-end investigation pipeline
│   ├── reporting.py               # Markdown incident report generation
│   ├── sanitizer.py               # Prompt-injection defense layer
│   ├── schema.py                  # Structured-output validation
│   ├── triage.py                  # Optional LLM alert-triage path
│   └── llm_provider.py            # Anthropic/OpenAI/mock adapters
├── data/
│   └── simulated_attack.json      # Safe synthetic telemetry
├── samples/
│   └── example_alert.json         # Original triage sample
└── tests/
    ├── test_investigation.py     # End-to-end investigation tests
    └── adversarial_samples/       # Prompt-injection test cases
```

## Run locally

### 1. Clone

```bash
git clone https://github.com/AdityaKGoswami/AI-SOC-Copilot.git
cd AI-SOC-Copilot
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the investigation dashboard

```bash
streamlit run app.py
```

Then open the local Streamlit URL shown in the terminal.

### 5. Run the tests

```bash
pytest -q
```

### 6. Run the original alert-triage CLI in mock mode

```bash
python cli.py samples/example_alert.json
```

## Optional LLM mode

The project retains the original provider abstraction for LLM-assisted alert triage. Set one of these in `.env`:

```env
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=your_key
```

or

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=your_key
```

The LLM layer is deliberately separated from the deterministic investigation pipeline. This makes it possible to compare model reasoning against fixed detection evidence instead of letting the model become the only source of truth.

## Security design

The project also demonstrates a second security problem: attacker-controlled log data can contain prompt-injection text. The existing triage path therefore sanitizes untrusted fields, wraps alert data in an explicit trust boundary, and validates structured model output before accepting it. See `copilot/sanitizer.py`, `copilot/triage.py`, and `copilot/schema.py`.

The system does not perform autonomous containment. Response actions are presented as recommendations for a human analyst.

## Important limitation

This is a lab and portfolio project, not a production SOC platform. Detection logic is intentionally small and transparent, the dataset is synthetic, and the AI analyst is constrained by the evidence available in the test scenario.

## License

MIT
