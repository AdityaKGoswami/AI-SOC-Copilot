<div align="center">

# AI SOC Copilot

**An LLM-powered alert triage assistant — built with prompt-injection defense as a first-class feature, not an afterthought.**

![Python](https://img.shields.io/badge/Python-0d1012?style=flat-square&logo=python&logoColor=4dd4e8&labelColor=0d1012)
![Claude](https://img.shields.io/badge/Claude%20API-0d1012?style=flat-square&logoColor=4dd4e8&labelColor=0d1012)
![OpenAI](https://img.shields.io/badge/OpenAI%20API-0d1012?style=flat-square&logo=openai&logoColor=4dd4e8&labelColor=0d1012)
![License](https://img.shields.io/badge/License-MIT-0d1012?style=flat-square&labelColor=0d1012&color=4dd4e8)

</div>

<br/>

## Why this exists

"AI SOC copilots" are the direction the whole industry is moving — CrowdStrike Charlotte AI, IBM ATOM, Google's agentic defense layer all do some version of LLM-assisted triage. But feeding attacker-controlled log data (filenames, User-Agent strings, process command lines) directly into an LLM prompt creates a real, documented risk: **prompt injection**, currently ranked #1 on the OWASP Top 10 for LLM Applications. An attacker who knows a SOC uses AI triage can plant instructions inside a filename hoping the model follows them instead of analyzing them.

This project is a small, working demonstration of both sides of that problem: a functional triage pipeline, and a defense layer that's actually tested against real injection attempts — not just claimed.

<br/>

## How the defense works

1. **Sanitizer** (`copilot/sanitizer.py`) — every untrusted field is length-capped and scanned for known injection patterns. Matches are *flagged*, not silently stripped, so a SOC analyst can see that an injection attempt was made — that's a signal worth attention in its own right.
2. **Enforced trust boundary in the prompt** (`copilot/triage.py`) — untrusted alert content is wrapped in an explicit `<ALERT_DATA>` block, and the system prompt repeatedly and explicitly instructs the model to treat everything inside it as data, never as instructions, regardless of what it claims to be.
3. **Strict output validation** (`copilot/schema.py`) — the model's response must match an exact schema. A response that breaks format (which is often what a successful injection looks like from the outside) is treated as a **failed triage**, not silently accepted.

<br/>

## Proof, not just claims

`tests/test_sanitizer_defense.py` runs the sanitizer against three real adversarial samples — injection attempts hidden in a filename, a User-Agent header, and a process command line — plus a benign control sample to check for false positives. Run it yourself:

```bash
python tests/test_sanitizer_defense.py
```

```
✅ PASS — injection_in_command_line.json: sanitizer flagged 1 field(s)
✅ PASS — injection_in_filename.json: sanitizer flagged 1 field(s)
✅ PASS — injection_in_user_agent.json: sanitizer flagged 1 field(s)

3/3 adversarial samples correctly flagged.
```

This runs entirely offline — no API key required — because the sanitizer defense shouldn't depend on model behavior to be verifiable.

<br/>

## Running it

```bash
git clone https://github.com/Aditya-Sec/AI-SOC-Copilot.git
cd AI-SOC-Copilot
pip install -r requirements.txt
cp .env.example .env
```

**Try it with zero setup** (mock mode, no API key needed):
```bash
python cli.py samples/example_alert.json
python cli.py tests/adversarial_samples/injection_in_filename.json
```

**For real analysis**, set `LLM_PROVIDER=anthropic` (or `openai`) in `.env` and add your API key.

<br/>

## What's deliberately out of scope

This is a triage *assistant*, not an autonomous responder — it doesn't take any containment action itself, by design. Given how new and fast-moving agentic-SOC tooling is, keeping a human in the loop for anything beyond classification/recommendation is the more defensible design choice, not a limitation.

<br/>

## License

MIT — see [LICENSE](LICENSE).
