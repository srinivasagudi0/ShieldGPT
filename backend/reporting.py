from __future__ import annotations

from datetime import datetime
from typing import Optional

from fpdf import FPDF

from .risk_engine import RiskResult


def _format_breakdown(result: RiskResult) -> str:
    b = result.breakdown
    return (
        f"Domain: {b.domain_risk}/100 | Intent: {b.intent_risk}/100 | "
        f"Content: {b.content_risk}/100 | Urgency: {b.urgency_risk}/100 "
        f"(Confidence: {b.confidence})"
    )


def _safe_text(text: str) -> str:
    # Replace common unicode punctuation with ASCII-safe equivalents for built-in fonts
    return (
        text.replace("—", "-")
        .replace("–", "-")
        .replace("“", '"')
        .replace("”", '"')
        .replace("’", "'")
        .replace("•", "-")
        .replace("\t", " ")
        .replace("\n", " ")
    )


def _break_long_tokens(text: str, chunk: int = 30) -> str:
    parts = []
    for token in text.split(" "):
        if len(token) <= chunk:
            parts.append(token)
        else:
            # insert breakpoints into long continuous strings (e.g., URLs, hashes)
            parts.append(" ".join(token[i : i + chunk] for i in range(0, len(token), chunk)))
    return " ".join(parts)


def _wrap_line(text: str, max_len: int = 120) -> str:
    text = _safe_text(text)
    text = _break_long_tokens(text)
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def _mc(pdf: FPDF, text: str, height: int = 6, max_len: int = 120):
    """Safe multi_cell helper with width and cursor reset."""
    usable_width = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(usable_width, height, _wrap_line(text, max_len))


def build_html_report(result: RiskResult, scan_id: Optional[int] = None) -> str:
    issued = datetime.fromtimestamp(result.generated_at).isoformat()
    domain_section = "".join(
        f"<li><strong>{finding.url}</strong> — {finding.score}/100<br/>"
        + "<br/>".join(f"- {issue}" for issue in finding.issues)
        + "</li>"
        for finding in result.domain_findings
    )
    highlight_section = "".join(
        f"<li><strong>{h['phrase']}</strong> ({h['category']}) — <em>{h['snippet']}</em></li>"
        for h in result.highlights
    )
    actions = "".join(f"<li>{a}</li>" for a in result.recommended_actions)
    replies = "".join(f"<li>{r}</li>" for r in result.safe_replies)
    scam_types = " ".join(f"<span class='pill'>{s}</span>" for s in result.scam_types)

    return f"""
    <html>
      <head>
        <style>
          body {{
            font-family: Arial, sans-serif;
            padding: 16px;
            color: #0f172a;
          }}
          h1, h2 {{
            color: #111827;
          }}
          .score {{
            font-size: 32px;
            color: #b91c1c;
          }}
          .pill {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            background: #f1f5f9;
            margin-right: 6px;
            font-size: 12px;
          }}
        </style>
      </head>
      <body>
        <h1>ShieldGPT Security Report {f"# {scan_id}" if scan_id else ""}</h1>
        <div>Issued: {issued}</div>
        <p class="score">Overall Risk: {result.overall_risk}/100</p>
        <div class="pill">Trust: {result.trust_label}</div>
        <div>{_format_breakdown(result)}</div>
        <div>Scam patterns: {scam_types or "None detected"}</div>

        <h2>Domain Intelligence</h2>
        <ul>{domain_section or "<li>No domains detected.</li>"}</ul>

        <h2>Evidence</h2>
        <ul>{highlight_section or "<li>No evidence extracted.</li>"}</ul>

        <h2>Safety Plan</h2>
        <ul>{actions}</ul>

        <h2>Safe Replies</h2>
        <ul>{replies}</ul>
      </body>
    </html>
    """


def build_pdf_report(result: RiskResult, scan_id: Optional[int] = None) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "ShieldGPT Report", ln=True)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 8, _safe_text(f"Scan ID: {scan_id or 'N/A'}"), ln=True)
    pdf.cell(0, 8, _safe_text(f"Overall Risk: {result.overall_risk}/100"), ln=True)
    pdf.cell(0, 8, _safe_text(f"Trust: {result.trust_label}"), ln=True)
    _mc(pdf, _safe_text(_format_breakdown(result)), height=8, max_len=200)
    if result.scam_types:
        _mc(pdf, _safe_text("Scam patterns: " + ", ".join(result.scam_types)), height=8, max_len=200)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Domain Intelligence", ln=True)
    pdf.set_font("Helvetica", "", 11)
    if result.domain_findings:
        for finding in result.domain_findings:
            pdf.cell(0, 7, _wrap_line(f"{finding.url} - {finding.score}/100", 90), ln=True)
            for issue in finding.issues:
                pdf.set_x(pdf.l_margin + 4)
                _mc(pdf, f"- {issue}", height=6, max_len=110)
    else:
        pdf.cell(0, 6, "No domains detected.", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Evidence", ln=True)
    pdf.set_font("Helvetica", "", 11)
    if result.highlights:
        for h in result.highlights:
            snippet = _wrap_line(f"{h['phrase']} ({h['category']}): {h['snippet']}", 120)
            _mc(pdf, snippet, height=6, max_len=120)
    else:
        pdf.cell(0, 6, "No evidence extracted.", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Safety Plan", ln=True)
    pdf.set_font("Helvetica", "", 11)
    for action in result.recommended_actions:
        _mc(pdf, f"- {action}", height=6, max_len=120)
    pdf.ln(3)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Safe Replies", ln=True)
    pdf.set_font("Helvetica", "", 11)
    for reply in result.safe_replies:
        _mc(pdf, f"- {reply}", height=6, max_len=120)
    pdf.ln(3)

    output = pdf.output(dest="S")
    return bytes(output) if not isinstance(output, str) else output.encode("latin-1")
