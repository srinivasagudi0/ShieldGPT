# ShieldGPT — Real-Time Scam + Privacy Defense

Hybrid Streamlit + FastAPI app that scores risky links/messages, explains evidence, and generates safety actions, reports, and simulator flows.

## Quickstart (How to run locally)
1. Install deps (Python 3.10+): `pip install -r requirements.txt`
2. Run FastAPI (optional but keeps it “real”): `uvicorn backend.main:app --reload`
3. Run UI: `streamlit run streamlit_app.py`
   - Optional: point UI to API with `SHIELDGPT_API_URL=http://localhost:8000`
4. Set `OPENAI_API_KEY` to enable LLM intent scoring and `ELEVENLABS_API_KEY` to narrate the simulator call.

## Privacy Lock
Privacy Lock keeps analysis local-only. It disables network features (redirect checks, domain-age lookups, TLS checks), OpenAI, ElevenLabs, and external API calls. Toggle off only when you explicitly want cloud checks.

## Features
- Multi-input analyzer (URL, email, SMS/DM, combined) with explainable subscores (domain, intent, content, urgency, spoofing, confidence).
- Evidence highlighting of risky phrases + domain intelligence (typosquats, suspicious TLDs, redirects, shorteners, punycode, TLS sanity, domain age).
- Trust badges (“Safe/Suspicious/Dangerous”) with visual timeline and weights displayed for transparency.
- Safety plan + context-aware Safe Reply templates; exportable HTML/PDF reports; SQLite history with session metadata.
- Scam Call Simulator with scored choices, rationale per decision, and optional ElevenLabs TTS.
- Vision tab shows browser extension mock (“Scan before click”) and org/school mode concepts for future work.
- Browser-extension ready endpoint: `POST /ext/analyze` with `{ "text": "...", "include_llm": true|false, "allow_network": true, "llm_model": "gpt-4.1" }` returns a badge (`Scam Likely/Suspicious/Caution/Safe`), score, brief summary, quick actions, and a one-click safe reply for context-menu overlays.

## Project layout
- `streamlit_app.py`: Frontend experience (analyzer, reports, simulator, history).
- `backend/`: Risk engine, rules, FastAPI API, SQLite storage, reporting helpers, simulator.
- `data/`: SQLite DB is created here on first run.

## Demo flows
- Analyzer: paste message/URL → toggle LLM if desired → Analyze → review risk, evidence, actions → export report.
- Simulator: play the scam script (with TTS if enabled), pick responses, and review your safety score.
- History: see recent scans saved locally.

## Screenshots
![Analyzer](docs/analyzer.png)
![Timeline + Evidence](docs/timeline.png)
