import json
import os
from pathlib import Path
from typing import List, Optional

import requests
import streamlit as st

from backend.reporting import build_html_report, build_pdf_report
from backend.risk_engine import RiskEngine, RiskResult, extract_urls
from backend.simulator import get_scenario, synthesize_voice
from backend.storage import HistoryStore


st.set_page_config(
    page_title="ShieldGPT — Scam + Privacy Defense",
    page_icon="🛡️",
    layout="wide",
)

brand_css = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Manrope:wght@500;700&family=Space+Grotesk:wght@400;600&display=swap');
html, body, [class*="css"]  {
    font-family: 'Manrope', 'Space Grotesk', sans-serif;
    background: radial-gradient(circle at 12% 20%, #111827, #0b1021 38%), #0b0f1a;
    color: #e2e8f0;
}
.pill {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    background: linear-gradient(90deg, #0ea5e9, #22d3ee);
    color: #0b1021;
    font-weight: 700;
    font-size: 12px;
}
.chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    border-radius: 999px;
    background: #0f172a;
    border: 1px solid #1e293b;
    font-size: 12px;
    font-weight: 700;
    color: #cbd5e1;
}
.chip .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #22d3ee;
    display: inline-block;
}
.card {
    padding: 14px 16px;
    border-radius: 12px;
    background: #0b1224;
    color: #e2e8f0;
    border: 1px solid #1f2937;
}
.highlight {
    padding: 8px 10px;
    border-radius: 8px;
    background: #0f172a;
    border: 1px solid #1e293b;
    margin-bottom: 6px;
}
.tag {
    padding: 4px 8px;
    background: #e0f2fe;
    color: #0f172a;
    border-radius: 8px;
    font-size: 11px;
    margin-right: 6px;
}
.score-ring {
    border-radius: 12px;
    padding: 12px;
    background: linear-gradient(135deg, #0b1224, #0e172f);
    color: #e2e8f0;
    border: 1px solid #1f2937;
}
.soft-card {
    padding: 16px;
    border-radius: 14px;
    background: #0b1224;
    border: 1px solid #1e293b;
    color: #e2e8f0;
}
.trust-badge {
    display: inline-block;
    padding: 6px 12px;
    border-radius: 10px;
    font-weight: 700;
    color: #0b1021;
}
.hero {
    background: linear-gradient(135deg, #0b1224, #0c1a33);
    padding: 18px;
    border-radius: 16px;
    border: 1px solid #1e293b;
    box-shadow: 0 20px 60px rgba(0,0,0,0.25);
}
.meter {
    width: 100%;
    background: #0b1220;
    border-radius: 999px;
    border: 1px solid #1f2937;
    overflow: hidden;
    height: 18px;
    margin-top: 6px;
}
.meter-fill {
    height: 100%;
    border-radius: 999px;
}
.subscore-bar {
    height: 10px;
    border-radius: 999px;
    background: #0b1220;
    border: 1px solid #1e293b;
    overflow: hidden;
}
.subscore-fill {
    height: 100%;
    border-radius: 999px;
}
.evidence {
    padding: 10px 12px;
    border-radius: 10px;
    background: #0f172a;
    border: 1px solid #1e293b;
    margin-bottom: 6px;
}
.sev {
    display:inline-block;
    padding:2px 8px;
    border-radius: 999px;
    font-size:11px;
    font-weight:700;
    margin-right:6px;
}
.panel {
    background: #0c1428;
    border: 1px solid #1f2937;
    border-radius: 14px;
    padding: 14px;
    box-shadow: inset 0 0 0 1px rgba(255,255,255,0.02);
}
.label-ghost {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 8px;
    background: #111827;
    border: 1px solid #1f2937;
    font-size: 11px;
    color: #cbd5e1;
}
.score-grid {
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 12px;
    align-items: center;
}
.score-number {
    font-size: 42px;
    font-weight: 800;
    line-height: 1;
}
.microcopy {
    color: #94a3b8;
    font-size: 13px;
}
.shadow {
    box-shadow: 0 10px 30px rgba(0,0,0,0.28);
}
</style>
"""
st.markdown(brand_css, unsafe_allow_html=True)

engine = RiskEngine()
store = HistoryStore()
API_URL = os.getenv("SHIELDGPT_API_URL")
if "privacy_lock" not in st.session_state:
    st.session_state["privacy_lock"] = True


def trust_color(label: str) -> str:
    return {"Dangerous": "#dc2626", "Suspicious": "#f97316"}.get(label, "#16a34a")


def render_breakdown(result: RiskResult):
    st.subheader("Subscores")
    cols = st.columns(5)
    subs = [
        ("Domain", result.breakdown.domain_risk),
        ("Intent", result.breakdown.intent_risk),
        ("Content", result.breakdown.content_risk),
        ("Urgency", result.breakdown.urgency_risk),
        ("Spoofing", result.breakdown.spoof_risk),
    ]
    for col, (label, val) in zip(cols, subs):
        color = "#f97316" if val >= 60 else "#10b981"
        with col:
            st.markdown(f"**{label}** {val}/100")
            st.markdown(
                f"""<div class='subscore-bar'><div class='subscore-fill' style='width:{min(val,100)}%;background:{color};'></div></div>""",
                unsafe_allow_html=True,
            )
    if getattr(result, "weights", None):
        weight_text = " • ".join(f"{k}: {v:.2f}" for k, v in result.weights.items())
        st.caption(f"Scoring weights → {weight_text}")


def render_domain_intel(result: RiskResult):
    st.subheader("Domain intelligence")
    if not result.domain_findings:
        st.info("No domains detected.")
        return
    for finding in result.domain_findings:
        with st.container():
            st.markdown(
                f"<div class='card'><div class='pill'>URL</div> <strong>{finding.url}</strong>"
                f"<br/><span>Risk {finding.score}/100</span><br/>"
                + ("<br/>".join(f"• {issue}" for issue in finding.issues) or "Clean")
                + "</div>",
                unsafe_allow_html=True,
            )


def render_timeline(result: RiskResult):
    st.subheader("Risk escalation timeline")
    if getattr(result, "timeline", None):
        cols = st.columns(len(result.timeline))
        for idx, item in enumerate(result.timeline):
            risk = item.get("risk", "mid")
            try:
                val = int(risk)
                color = "#b91c1c" if val >= 70 else "#f97316" if val >= 40 else "#10b981"
                score_txt = f"{val}/100"
            except ValueError:
                color = "#f97316" if risk == "mid" else "#b91c1c" if risk == "high" else "#10b981"
                score_txt = risk
            cols[idx].markdown(
                f"<div class='card' style='background:{color}1A;border-color:{color};'>"
                f"<div class='pill'>{item.get('stage','Stage')}</div><br/><strong>{score_txt}</strong><br/>{item.get('detail','')}</div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("No timeline data available.")


def render_highlights(result: RiskResult):
    st.subheader("Evidence highlights")
    if not result.highlights:
        st.info("No high-risk language detected.")
        return
    for h in result.highlights:
        st.markdown(
            f"<div class='highlight'><span class='tag'>{h.get('category','')}</span>"
            f"<strong>{h.get('phrase','')}</strong><br/><em>{h.get('snippet','')}</em></div>",
            unsafe_allow_html=True,
        )


def render_safety(result: RiskResult):
    st.subheader("Safety plan")
    st.write("What to do next:")
    for action in result.recommended_actions:
        st.markdown(f"- {action}")
    st.subheader("Safe replies")
    for reply in result.safe_replies:
        st.code(reply)


def render_report_downloads(result: RiskResult, scan_id: Optional[int]):
    html_report = build_html_report(result, scan_id=scan_id)
    pdf_report = build_pdf_report(result, scan_id=scan_id)
    st.download_button(
        "Download HTML report",
        data=html_report,
        file_name=f"shieldgpt-report-{scan_id or 'latest'}.html",
        mime="text/html",
    )
    st.download_button(
        "Download PDF report",
        data=pdf_report,
        file_name=f"shieldgpt-report-{scan_id or 'latest'}.pdf",
        mime="application/pdf",
    )


def analyze_input(
    message: str,
    urls: List[str],
    input_type: str,
    include_llm: bool,
    allow_external: bool,
    llm_model: str,
):
    if not message.strip() and not urls:
        st.warning("Provide message text or at least one URL.")
        return None, None
    deduped_urls = list({u.strip() for u in urls if u.strip()})
    try:
        if API_URL and allow_external:
            resp = requests.post(
                f"{API_URL}/analyze",
                json={
                    "message_text": message,
                    "urls": deduped_urls,
                    "include_llm": include_llm,
                    "allow_network": allow_external,
                    "input_type": input_type,
                    "llm_model": llm_model if include_llm else None,
                },
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()
            scan_id = payload.get("scan_id")
            result = RiskResult.model_validate(payload)
        else:
            result = engine.analyze(
                message,
                urls=deduped_urls,
                include_llm=include_llm if allow_external else False,
                allow_network=allow_external,
                llm_model=llm_model if include_llm else None,
            )
            scan_id = store.save_scan(result, input_type=input_type, raw_text=message, urls=deduped_urls)
        st.success(f"Scan saved as #{scan_id}")
        return result, scan_id
    except Exception as exc:
        st.error(f"Analysis failed: {exc}")
        return None, None


st.title("🛡️ ShieldGPT — Real-Time Scam + Privacy Defense")
st.caption("Paste a message or URL → get an explainable score, highlights, and safe actions in seconds.")

tabs = st.tabs(["Analyzer", "Scam Call Simulator", "History", "Vision"])
privacy_lock_state = st.session_state.get("privacy_lock", True)

with tabs[0]:
    privacy_lock_default = st.session_state.get("privacy_lock", True)
    st.markdown(
        f"""
        <div class='hero shadow'>
            <div style='display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap;'>
                <div>
                    <div class='pill'>Analyzer</div>
                    <h2 style='margin:6px 0 4px;'>Real-time scam check</h2>
                    <div class='microcopy'>Paste a message or URL — get a strict score, highlights, and what to do next.</div>
                </div>
                <div style='display:flex;gap:10px;flex-wrap:wrap;'>
                    <span class='chip'><span class='dot' style='background:{'#22d3ee' if privacy_lock_default else '#22c55e'}'></span>{"Privacy lock: On (local only)" if privacy_lock_default else "External checks enabled"}</span>
                    <span class='chip'><span class='dot'></span>Strict heuristics</span>
                    <span class='chip'><span class='dot'></span>Explainable output</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    control_cols = st.columns([1.4, 1, 1])
    with control_cols[0]:
        privacy_lock = st.toggle(
            "Privacy lock (strict local mode)",
            value=privacy_lock_default,
            help="When on, analysis stays on-device and disables API/LLM/TTS + network checks.",
        )
        st.caption("Local-only mode blocks redirects, RDAP age lookups, TLS checks, OpenAI, ElevenLabs, API calls.")
    with control_cols[1]:
        st.markdown(
            "<div class='panel'><span class='label-ghost'>Runbook</span><br/>"
            "1) Paste the text/URL<br/>2) Hit Analyze<br/>3) Copy the safety plan or Safe Reply</div>",
            unsafe_allow_html=True,
        )
    with control_cols[2]:
        st.markdown(
            "<div class='panel'><span class='label-ghost'>Detection focus</span><br/>"
            "• Urgency + manipulation<br/>• Spoofing language<br/>• Insecure or action-heavy URLs</div>",
            unsafe_allow_html=True,
        )
    st.session_state["privacy_lock"] = privacy_lock
    privacy_lock_state = privacy_lock

    col_left, col_right = st.columns([2, 1])
    with col_left:
        st.markdown("<span class='label-ghost'>Message / transcript</span>", unsafe_allow_html=True)
        sample_col1, sample_col2 = st.columns([1, 3])
        with sample_col1:
            if st.button("Sample phishing text", use_container_width=True):
                st.session_state["sample_message"] = (
                    "URGENT: Your account was locked. Verify now at http://paypaI.com/reset "
                    "or funds will be held for 24 hours."
                )
                st.session_state["sample_url"] = "http://paypaI.com/reset"
        with sample_col2:
            st.caption("Keep Privacy lock on for strict local analysis. Turn it off only if you need network checks/LLM.")
        message_default = st.session_state.get("sample_message", "")
        message = st.text_area(
            "Paste message/email text or notes",
            height=240,
            placeholder="Paste the suspicious email, SMS, DM, or transcript here...",
            value=message_default,
        )
    with col_right:
        st.markdown("<span class='label-ghost'>URL + options</span>", unsafe_allow_html=True)
        url_default = st.session_state.get("sample_url", "")
        url_input = st.text_input("Suspicious URL (optional)", value=url_default, placeholder="https://example.com/reset")
        input_type = st.radio(
            "What are you checking?",
            ["URL", "Email text", "SMS/DM text", "Combined"],
            horizontal=True,
        )
        include_llm_default = st.session_state.get("include_llm", False) and not privacy_lock_state
        include_llm = st.toggle(
            "Use LLM intent check (needs OPENAI_API_KEY)",
            value=include_llm_default,
            disabled=privacy_lock_state,
            help="Requires sending content to OpenAI; disabled in privacy lock.",
        )
        st.session_state["include_llm"] = include_llm
        llm_model = st.text_input(
            "LLM model (when enabled)",
            value=os.getenv("OPENAI_MODEL", "gpt-4.1"),
            disabled=privacy_lock_state or not include_llm,
            help="Model name for OpenAI (e.g., gpt-4.1). Ignored when privacy lock is on.",
        )
        submitted = st.button("Analyze now", use_container_width=True, type="primary")

        if submitted:
            urls = extract_urls(message)
            if url_input:
                urls.append(url_input)
            result, scan_id = analyze_input(
                message,
                urls,
                input_type=input_type,
                include_llm=include_llm,
                allow_external=not privacy_lock_state,
                llm_model=llm_model,
            )
            if result:
                st.session_state["last_result"] = result
                st.session_state["last_scan_id"] = scan_id

    last_result: Optional[RiskResult] = st.session_state.get("last_result")
    last_scan_id = st.session_state.get("last_scan_id")

    if last_result:
        trust = last_result.trust_label
        badge_color = trust_color(trust)
        st.markdown(
            f"""
            <div class='panel score-grid shadow'>
                <div>
                    <div class='pill'>Risk score</div>
                    <div class='score-number'>{last_result.overall_risk}/100</div>
                    <div class='microcopy'>Confidence: {last_result.breakdown.confidence}</div>
                    <div class='microcopy' style='margin-top:4px;'>{last_result.reasoning}</div>
                    {("<div style='margin-top:8px;'>" + " ".join(f"<span class='pill'>{t}</span>" for t in last_result.scam_types) + "</div>") if last_result.scam_types else ""}
                </div>
                <div style='text-align:right;'>
                    <span class='trust-badge' style='background:{badge_color}33;border:1px solid {badge_color};color:{badge_color};'>{trust}</span>
                    <div class='meter' style='margin-top:10px;'><div class='meter-fill' style='width:{last_result.overall_risk}%;background:{badge_color};'></div></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        render_breakdown(last_result)
        st.divider()
        upper_cols = st.columns([1.5, 1])
        with upper_cols[0]:
            render_timeline(last_result)
            render_highlights(last_result)
            if hasattr(last_result, "evidence") and last_result.evidence:
                st.subheader("Evidence")
                for ev in last_result.evidence:
                    sev = ev.get("severity", "")
                    sev_badge = f"<span class='sev' style='background:#fbbf2444;color:#fbbf24;'>sev {sev}</span>" if sev else ""
                    detail = ev.get("detail", "")
                    snippet = ev.get("snippet", "")
                    st.markdown(
                        f"<div class='evidence'>{sev_badge}<strong>{ev.get('type','')}</strong>: {detail}"
                        + (f"<br/><em>{snippet}</em>" if snippet else "")
                        + "</div>",
                        unsafe_allow_html=True,
                    )
        with upper_cols[1]:
            render_domain_intel(last_result)
            render_safety(last_result)
            st.subheader("Exportable report")
            render_report_downloads(last_result, last_scan_id)

with tabs[1]:
    st.subheader("Interactive Scam Call Simulator")
    scenario = get_scenario("bank_fraud")
    st.write(scenario.script)
    if st.button(
        "Play narrated scam (ElevenLabs)",
        use_container_width=True,
        disabled=privacy_lock_state,
        help="Requires sending text to ElevenLabs; enable external services by turning off Privacy lock.",
    ):
        audio = synthesize_voice(scenario.script)
        if audio:
            st.audio(audio, format="audio/mpeg")
        else:
            st.info("Audio unavailable. Add ELEVENLABS_API_KEY to enable TTS.")

    st.markdown("Choose responses for each stage:")
    choices = []
    for idx, step in enumerate(scenario.steps):
        st.markdown(f"**Step {idx + 1}: {step.prompt}**")
        option = st.radio(
            "Pick a response",
            range(len(step.options)),
            format_func=lambda i, opts=step.options: opts[i]["label"],
            key=f"sim-step-{idx}",
        )
        choices.append((step, option))

    if st.button("Score my responses", use_container_width=True):
        total = 0
        feedback_lines = []
        detailed = []
        for step, choice_idx in choices:
            opt = step.options[choice_idx]
            total += opt["score"]
            feedback_lines.append(f"- {opt['label']}: {opt['feedback']} ({opt['score']} pts)")
            detailed.append(
                {
                    "choice": opt["label"],
                    "delta": opt["score"],
                    "reason": opt.get("reason", opt.get("feedback", "")),
                }
            )
        st.session_state["sim_score"] = total
        st.session_state["sim_feedback"] = feedback_lines
        st.success(f"Simulator safety score: {total} (higher is safer)")
        for item in detailed:
            st.markdown(
                f"- **{item['choice']}** — {item['delta']} pts<br/><small>{item['reason']}</small>",
                unsafe_allow_html=True,
            )

with tabs[2]:
    st.subheader("Recent scans")
    if API_URL and not privacy_lock_state:
        try:
            resp = requests.get(f"{API_URL}/history", params={"limit": 20}, timeout=10)
            resp.raise_for_status()
            scans = resp.json()
        except Exception as exc:
            st.error(f"Could not load history from API: {exc}")
            scans = []
    else:
        scans = store.list_scans(limit=20)
    if not scans:
        st.info("No scans yet.")
    else:
        st.dataframe(
            [
                {
                    "id": s["id"],
                    "session": s.get("session_id", ""),
                    "type": s["input_type"],
                    "overall": s["overall"],
                    "confidence": s.get("confidence", ""),
                    "trust": s.get("trust_label", ""),
                    "scam": s.get("scam_type", ""),
                    "urls": ", ".join(s["urls"]),
                    "preview": (s["raw_text"] or "")[:80],
                }
                for s in scans
            ],
            use_container_width=True,
        )

with tabs[3]:
    st.subheader("Browser Extension — live mock")
    st.caption("Simulate right-click → Scan with ShieldGPT")
    ext_msg = st.text_input(
        "Selected text or link",
        value="Urgent: verify your account at http://paypaI.com/reset to avoid suspension.",
    )
    if st.button("Scan in extension mode", use_container_width=True):
        ext_urls = extract_urls(ext_msg)
        ext_result = engine.analyze(
            ext_msg,
            urls=ext_urls,
            include_llm=False,
            allow_network=not privacy_lock_state,
        )
        color = trust_color(ext_result.trust_label)
        st.markdown(
            f"<div class='card' style='border-color:{color};'>"
            f"<div class='pill'>Extension badge</div> "
            f"<span class='trust-badge' style='background:{color}33;border:1px solid {color};color:{color};'>"
            f"{ext_result.trust_label}</span> "
            f"<span style='color:{color};font-weight:700;'>{ext_result.overall_risk}/100</span>"
            f"<br/><small>Inline overlay shown before clicking.</small>"
            f"</div>",
            unsafe_allow_html=True,
        )
        st.write("One-click Safe Reply:")
        if ext_result.safe_replies:
            st.code(ext_result.safe_replies[0])
        st.write("Quick evidence:")
        if ext_result.highlights:
            for h in ext_result.highlights[:3]:
                st.markdown(f"- **{h.get('phrase','')}** ({h.get('category','')}) — {h.get('snippet','')}")
        else:
            st.markdown("- No highlights found.")

    st.subheader("What's next (concepts)")
    st.markdown(
        """
        **Browser Extension (shipping path)**
        - Right-click “Scan with ShieldGPT” on any link/email.
        - Inline badge overlay: Safe / Suspicious / Dangerous.
        - One-click report export + Safe Reply insert in Gmail.

        **Org / School Mode**
        - Teacher/parent dashboard with bulk message upload.
        - Safety drills with simulator scores per student.
        - Trends: top scam categories, risky domains, response quality over time.
        - “Privacy mode” default with opt-in LLM/TTS per organization.
        """
    )
