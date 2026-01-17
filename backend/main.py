from __future__ import annotations

from typing import List, Optional

import os
from fastapi import FastAPI, HTTPException, Response, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .reporting import build_html_report, build_pdf_report
from .risk_engine import RiskEngine, extract_urls
from .simulator import get_scenario, synthesize_voice
from .storage import HistoryStore

ALLOWED_ORIGINS = os.getenv("SHIELDGPT_ALLOWED_ORIGINS", "http://localhost:8501,http://127.0.0.1:8501").split(",")
API_KEY = os.getenv("SHIELDGPT_API_KEY")
RATE_LIMIT = int(os.getenv("SHIELDGPT_RATE_LIMIT", "60"))  # requests per minute placeholder
last_requests = {}


app = FastAPI(title="ShieldGPT API", version="0.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in ALLOWED_ORIGINS if o],
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = RiskEngine()
store = HistoryStore()


class AnalyzeRequest(BaseModel):
    message_text: str
    urls: Optional[List[str]] = None
    include_llm: bool = False
    input_type: str = "unknown"
    allow_network: bool = False
    llm_model: Optional[str] = None


class ExtensionAnalyzeRequest(BaseModel):
    text: str
    include_llm: bool = False
    allow_network: bool = False
    llm_model: Optional[str] = None


@app.post("/analyze")
def _require_api_key(auth: Optional[str] = Header(default=None)):
    if API_KEY and (not auth or auth.replace("Bearer ", "") != API_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized")


def _rate_limit(client_id: str):
    import time
    now = int(time.time())
    window = now // 60
    key = (client_id, window)
    last_requests[key] = last_requests.get(key, 0) + 1
    if last_requests[key] > RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


def _validate_input(msg: str, urls: Optional[List[str]]):
    if msg and len(msg) > 8000:
        raise HTTPException(status_code=400, detail="Input too large (max 8000 chars)")
    if urls and len(urls) > 12:
        raise HTTPException(status_code=400, detail="Too many URLs (max 12)")


@app.post("/analyze")
def analyze(req: AnalyzeRequest, authorization: Optional[str] = Header(default=None)):
    _require_api_key(authorization)
    _rate_limit(authorization or "anon")
    _validate_input(req.message_text, req.urls)
    result = engine.analyze(
        req.message_text,
        urls=req.urls,
        include_llm=req.include_llm,
        allow_network=req.allow_network,
        llm_model=req.llm_model,
    )
    scan_id = store.save_scan(result, req.input_type, req.message_text, urls=req.urls)
    payload = result.model_dump()
    payload["scan_id"] = scan_id
    return payload


def _brief(result):
    top_issue = ""
    if result.domain_findings:
        worst = max(result.domain_findings, key=lambda d: d.score)
        if worst.issues:
            top_issue = worst.issues[0]
    top_highlight = result.highlights[0]["phrase"] if result.highlights else ""
    badge = "Scam Likely" if result.overall_risk >= 90 else "Suspicious" if result.overall_risk >= 60 else "Caution" if result.overall_risk >= 30 else "Safe"
    badge_detail = (
        "Dangerous — likely scam" if badge == "Scam Likely" else
        "Suspicious — proceed with care" if badge == "Suspicious" else
        "Caution — review details" if badge == "Caution" else
        "Safe — low risk signals"
    )
    return {
        "trust": result.trust_label,
        "score": result.overall_risk,
        "badge": badge,
        "badge_detail": badge_detail,
        "top_issue": top_issue,
        "top_highlight": top_highlight,
        "actions": result.recommended_actions[:2],
        "safe_reply": result.safe_replies[0] if result.safe_replies else "",
    }


@app.post("/ext/analyze")
@app.post("/ext/analyze")
def ext_analyze(req: ExtensionAnalyzeRequest, authorization: Optional[str] = Header(default=None)):
    _require_api_key(authorization)
    _rate_limit(authorization or "anon")
    _validate_input(req.text, None)
    urls = extract_urls(req.text)
    result = engine.analyze(
        req.text,
        urls=urls,
        include_llm=req.include_llm,
        allow_network=req.allow_network,
        llm_model=req.llm_model,
    )
    brief = _brief(result)
    return {
        "summary": f"{brief['badge']} ({brief['score']}/100). Issue: {brief['top_issue'] or 'N/A'}. Highlight: {brief['top_highlight'] or 'N/A'}.",
        "trust": brief["trust"],
        "score": brief["score"],
        "badge": brief["badge"],
        "badge_detail": brief["badge_detail"],
        "actions": brief["actions"],
        "safe_reply": brief["safe_reply"],
        "scan": result.model_dump(),
    }


@app.get("/history")
def history(limit: int = 25):
    return store.list_scans(limit=limit)


@app.get("/history/{scan_id}")
def history_item(scan_id: int):
    row = store.load_scan(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return row


@app.get("/report/{scan_id}/html")
def report_html(scan_id: int):
    row = store.load_scan(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Rehydrate minimal result for report formatting
    from .risk_engine import ScoreBreakdown, DomainFinding, RiskResult
    import time as _time
    import json as _json

    breakdown = ScoreBreakdown(**row["breakdown"])
    domain_findings = [
        DomainFinding(url=d["url"], issues=d.get("issues", []), score=d.get("score", 0))
        for d in row.get("domain_findings", [])
    ]
    result = RiskResult(
        overall_risk=row["overall"],
        trust_label=row.get("trust_label", ""),
        breakdown=breakdown,
        domain_findings=domain_findings,
        highlights=row["highlights"],
        scam_types=row.get("scam_types", []),
        recommended_actions=row["actions"],
        safe_replies=row["safe_replies"],
        detected_urls=row["urls"],
        generated_at=row.get("created_at", _time.time()),
        reasoning=row.get("reasoning", ""),
    )
    html = build_html_report(result, scan_id=scan_id)
    return Response(content=html, media_type="text/html")


@app.get("/report/{scan_id}/pdf")
def report_pdf(scan_id: int):
    row = store.load_scan(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    from .risk_engine import ScoreBreakdown, DomainFinding, RiskResult
    import time as _time

    breakdown = ScoreBreakdown(**row["breakdown"])
    domain_findings = [
        DomainFinding(url=d["url"], issues=d.get("issues", []), score=d.get("score", 0))
        for d in row.get("domain_findings", [])
    ]
    result = RiskResult(
        overall_risk=row["overall"],
        trust_label=row.get("trust_label", ""),
        breakdown=breakdown,
        domain_findings=domain_findings,
        highlights=row["highlights"],
        scam_types=row.get("scam_types", []),
        recommended_actions=row["actions"],
        safe_replies=row["safe_replies"],
        detected_urls=row["urls"],
        generated_at=row.get("created_at", _time.time()),
        reasoning=row.get("reasoning", ""),
    )
    pdf_bytes = build_pdf_report(result, scan_id=scan_id)
    return Response(content=pdf_bytes, media_type="application/pdf")


@app.get("/simulator/scenario")
def simulator_scenario(scenario_id: str = "bank_fraud"):
    scenario = get_scenario(scenario_id)
    return {
        "id": scenario.id,
        "title": scenario.title,
        "script": scenario.script,
        "steps": [{"prompt": step.prompt, "options": step.options} for step in scenario.steps],
    }


@app.get("/simulator/audio")
def simulator_audio(scenario_id: str = "bank_fraud"):
    scenario = get_scenario(scenario_id)
    audio = synthesize_voice(scenario.script)
    if not audio:
        raise HTTPException(status_code=400, detail="Audio synthesis unavailable (missing key or request failed)")
    return Response(content=audio, media_type="audio/mpeg")


# Convenience for uvicorn
def get_app():
    return app
