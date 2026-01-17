# ShieldGPT — Explainable AI for Scam & Privacy Defense

ShieldGPT is an **explainable, privacy‑first AI system** that detects phishing, scam links, and social‑engineering attacks in real time. It combines **deterministic security rules** with **optional LLM intent analysis** to produce a transparent risk score, concrete evidence, and clear next steps—so users can *verify before they trust*.

> **What makes ShieldGPT different:** it does not rely on opaque “AI says so” judgments. Every decision is backed by **visible evidence**, **weighted subscores**, and a **timeline** that shows how risk accumulates.

---

## Why this matters

Scams increasingly blend convincing language, look‑alike domains, and time pressure. Most tools either block content without explanation or require expertise to interpret alerts. ShieldGPT focuses on **clarity and education**: it shows *why* something is risky and *what to do next*, helping users avoid mistakes now and recognize threats later.

---

## What ShieldGPT does

### Analyze messages and links

* Accepts **URLs**, **email text**, **SMS/DM text**, or **combined inputs**.
* Produces a **0–100 risk score** with **explicit, weighted subscores** (domain, content, urgency, spoofing) and a **confidence level**.

### Show the evidence (explainability by design)

* Highlights the **exact phrases** and signals that triggered risk (e.g., urgency, authority claims, payment pressure).
* Performs **domain intelligence** checks (typosquats, suspicious TLDs, shorteners, redirect chains, punycode, TLS sanity, domain age when enabled).
* Displays a **visual timeline** that explains how risk accumulates from link analysis → intent detection → manipulation signals → final verdict.

### Give safe, actionable guidance

* Generates a **Safety Plan** (what *not* to do, what to do next, and how to verify independently).
* Provides **context‑aware Safe Reply templates** that let users disengage without escalating risk.

### Train users, not just block threats

* Includes a **Scam Call Simulator** with scored decision points and rationales for each choice.
* Optional **ElevenLabs TTS** narrates realistic scenarios for hands‑on learning.

### Keep a local record

* Saves scans to **SQLite** with session metadata.
* Exports **HTML/PDF reports** for sharing or review.

---

## Privacy & safety model (no hand‑waving)

ShieldGPT is **privacy‑first by default**.

* **Privacy Lock ON (default):** analysis runs locally. Network features (redirect checks, domain‑age lookups, TLS checks), OpenAI, ElevenLabs, and external API calls are **disabled**.
* **Privacy Lock OFF (opt‑in):** enables optional cloud checks and LLM intent analysis.
* **No user content is stored or transmitted** unless you explicitly disable Privacy Lock.

This design lets users choose transparency and capability **without sacrificing control**.

---

## How it works (architecture)

```
Input
  ↓
Pre‑processing & URL extraction
  ↓
Rule Engine (deterministic signals)
  ├─ domain & link intelligence
  ├─ manipulation/urgency patterns
  └─ spoofing heuristics
        ↓
(Optional) LLM Intent Analysis
        ↓
Weighted Risk Aggregator
  ├─ explicit weights
  ├─ subscores
  └─ confidence
        ↓
Explanation Engine
  ├─ evidence highlights
  ├─ timeline
  └─ safety plan + safe replies
```

This **hybrid approach** balances reliability (rules) with adaptability (LLMs) and keeps decisions explainable.

---

## Technology stack

* **Frontend:** Streamlit
* **Backend API:** FastAPI
* **Storage:** SQLite (local)
* **Security logic:** Python (rule engine + scoring)
* **Optional AI:** OpenAI (intent classification/explanations)
* **Optional audio:** ElevenLabs (simulator narration)

---

## Quickstart (run locally)

> Python **3.10+** recommended

```bash
pip install -r requirements.txt

# (Optional) start the API
uvicorn app/backend/main:app --reload

# start the UI
streamlit run app/streamlit_app.py
```

Optional environment variables:

* `OPENAI_API_KEY` – enable LLM intent scoring
* `ELEVENLABS_API_KEY` – enable simulator narration
* `SHIELDGPT_API_URL` – point the UI to a running API (default: local)

---

## Demo flows

* **Analyzer:** paste a message or link → analyze → review score, evidence, and timeline → export report.
* **Simulator:** listen to a realistic scam script (optional TTS) → choose responses → review your safety score and rationale.
* **History:** browse recent scans saved locally.

---

## Browser extension (concept)

ShieldGPT exposes a **lightweight endpoint** designed for a future browser extension:

`POST /ext/analyze`

```json
{
  "text": "...",
  "include_llm": true,
  "allow_network": false,
  "llm_model": "gpt-4.1"
}
```

It returns a **badge** (Safe / Caution / Suspicious / Scam Likely), a brief summary, quick actions, and a one‑click safe reply—ideal for a **“scan before click”** context‑menu workflow.

---

## Project layout

```
app/
├── backend/          # risk engine, rules, API, storage, reporting, simulator
├── streamlit_app.py # UI
└── extension/       # browser‑extension mock
```

---

## Limitations & future work (transparent by design)

* Heuristic scoring trades some recall for explainability.
* Domain‑age and redirect checks depend on network access when enabled.
* The browser extension is a concept demo; full deployment is future work.

---

## License

MIT

---

## Acknowledgements

Built to demonstrate that **AI security tools can be powerful *and* understandable**—without compromising user privacy.
