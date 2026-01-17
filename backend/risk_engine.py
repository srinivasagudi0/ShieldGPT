from __future__ import annotations

import json
import os
import re
import socket
import ssl
import ipaddress
import time
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import tldextract
from pydantic import BaseModel

from .rules import (
    CATEGORY_ACTIONS,
    CATEGORY_PATTERNS,
    CATEGORY_REPLIES,
    KNOWN_BRANDS,
    MANIPULATION_PATTERNS,
    SAFE_ACTIONS,
    SAFE_REPLIES,
    SHORTENERS,
    SPOOF_PATTERNS,
    SUSPICIOUS_TLDS,
    URGENCY_PATTERNS,
)

# Configurable weights for explainable scoring
WEIGHTS = {
    "domain": 0.35,
    "content": 0.30,
    "urgency": 0.20,
    "spoof": 0.15,
}

HOST_ALLOWLIST = {h.strip() for h in os.getenv("SHIELDGPT_HOST_ALLOWLIST", "").split(",") if h.strip()}
HOST_BLOCKLIST = {h.strip() for h in os.getenv("SHIELDGPT_HOST_BLOCKLIST", "").split(",") if h.strip()}

# Match common URLs (with or without scheme) and avoid over-escaped literals.
URL_REGEX = re.compile(
    r"(?i)\b((?:(https?|ftp)://)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#\[\]@!$&'()*+,;=]+)"
)


def extract_urls(text: str) -> List[str]:
    return list({match[0] for match in URL_REGEX.findall(text or "")})


def normalize_score(value: int) -> int:
    return max(0, min(100, int(value)))


def _safe_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _check_redirects(url: str) -> int:
    try:
        resp = requests.get(url, timeout=4, allow_redirects=True)
        return len(resp.history)
    except Exception:
        return 0


def _punycode_present(domain: str) -> bool:
    return domain.startswith("xn--")


def _typosquat_score(domain: str) -> float:
    clean = domain.split(".")[0]
    best = max((_safe_ratio(clean, brand) for brand in KNOWN_BRANDS), default=0)
    return best


def _shortener_used(domain: str) -> bool:
    return domain.lower() in SHORTENERS


def _suspicious_tld(suffix: str) -> bool:
    return suffix.lower() in SUSPICIOUS_TLDS


def _https_score(url: str) -> int:
    return 0 if url.startswith("https://") else 20


def _trust_label(score: int) -> str:
    if score >= 70:
        return "Dangerous"
    if score >= 40:
        return "Suspicious"
    return "Safe"


def _domain_entropy(domain: str) -> float:
    if not domain:
        return 0.0
    import math

    freq: Dict[str, int] = {}
    for ch in domain:
        freq[ch] = freq.get(ch, 0) + 1
    total = float(len(domain))
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def _collect_phrases(text: str, patterns: List, category: str) -> List[Dict[str, str]]:
    findings = []
    lowered = text.lower()
    for pattern in patterns:
        meta = {"pattern": pattern, "severity": 0.5, "explanation": ""}
        regex = pattern
        if isinstance(pattern, dict):
            meta = pattern
            regex = pattern.get("pattern", "")
        matches = re.finditer(regex, lowered)
        for match in matches:
            start, end = match.span()
            snippet_start = max(0, start - 30)
            snippet_end = min(len(text), end + 30)
            findings.append(
                {
                    "phrase": text[start:end],
                    "category": category,
                    "snippet": text[snippet_start:snippet_end],
                    "pattern": regex,
                    "severity": meta.get("severity", 0.5),
                    "explanation": meta.get("explanation", ""),
                }
            )
    return findings


def _is_safe_target(url: str) -> bool:
    """Rudimentary SSRF guard: allow only public hostnames and non-private IPs."""
    try:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
        host = parsed.hostname or ""
        if not host or host in {"localhost"} or host.startswith("localhost"):
            return False
        # Disallow obvious internal hostnames
        if host.endswith(".local") or host.endswith(".internal"):
            return False
        # If it's an IP, ensure it's not private/link-local
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            pass
        if HOST_ALLOWLIST and host not in HOST_ALLOWLIST:
            return False
        if host in HOST_BLOCKLIST:
            return False
        return True
    except Exception:
        return False


def _domain_age_days(fqdn: str) -> Optional[int]:
    try:
        resp = requests.get(f"https://rdap.org/domain/{fqdn}", timeout=4)
        if resp.status_code != 200:
            return None
        data = resp.json()
        events = data.get("events", [])
        for event in events:
            if event.get("eventAction") in ("registration", "domain registration"):
                date_str = event.get("eventDate")
                if not date_str:
                    continue
                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None
    return None


def _cert_days_remaining(hostname: str) -> Optional[int]:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(4)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            not_after = cert.get("notAfter")
            if not_after:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                return (exp - datetime.utcnow()).days
    except Exception:
        return None
    return None


def _categorize_message(text: str) -> List[str]:
    hits: Dict[str, int] = {}
    lowered = text.lower()
    for category, patterns in CATEGORY_PATTERNS.items():
        score = 0
        for pattern in patterns:
            matches = re.findall(pattern, lowered)
            score += len(matches)
        if score:
            hits[category] = score
    # sort by hit count descending
    return [k for k, _ in sorted(hits.items(), key=lambda kv: kv[1], reverse=True)]


def _generate_actions(categories: List[str]) -> List[str]:
    actions = list(SAFE_ACTIONS)
    for cat in categories:
        actions.extend(CATEGORY_ACTIONS.get(cat, []))
    # dedupe while preserving order
    seen = set()
    unique = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            unique.append(a)
    return unique


def _generate_replies(categories: List[str]) -> List[str]:
    replies = list(SAFE_REPLIES)
    for cat in categories:
        replies.extend(CATEGORY_REPLIES.get(cat, []))
    seen = set()
    unique = []
    for r in replies:
        if r not in seen:
            seen.add(r)
            unique.append(r)
    return unique


class ScoreBreakdown(BaseModel):
    domain_risk: int
    intent_risk: int
    content_risk: int
    urgency_risk: int
    spoof_risk: int = 0
    confidence: str = "Medium"


class DomainFinding(BaseModel):
    url: str
    issues: List[str]
    score: int


class RiskResult(BaseModel):
    overall_risk: int
    trust_label: str
    breakdown: ScoreBreakdown
    domain_findings: List[DomainFinding]
    highlights: List[Dict[str, str]]
    scam_types: List[str]
    recommended_actions: List[str]
    safe_replies: List[str]
    detected_urls: List[str]
    generated_at: float
    reasoning: str
    evidence: List[Dict[str, str]] = []
    total_score: int = 0
    timeline: List[Dict[str, str]] = []
    weights: Dict[str, float] = {}


class RiskEngine:
    def __init__(self, openai_api_key: Optional[str] = None):
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")

    @staticmethod
    def _build_timeline(
        breakdown: ScoreBreakdown,
        scam_types: List[str],
        overall: int,
        confidence: str,
        domain_findings: List[DomainFinding],
        content_highlights: List[Dict[str, str]],
        urgency_highlights: List[Dict[str, str]],
        spoof_highlights: List[Dict[str, str]],
    ) -> List[Dict[str, str]]:
        timeline: List[Dict[str, str]] = []
        domain_detail = domain_findings[0].issues[0] if domain_findings and domain_findings[0].issues else "Domain scan completed."
        content_detail = content_highlights[0].get("phrase", "") if content_highlights else "No manipulation phrases flagged."
        urgency_detail = urgency_highlights[0].get("phrase", "") if urgency_highlights else "No urgency triggers."
        spoof_detail = spoof_highlights[0].get("phrase", "") if spoof_highlights else "No spoofing cues."
        scam_label = scam_types[0] if scam_types else "general"
        timeline.append({"stage": "Link & Domain Check", "risk": str(breakdown.domain_risk), "detail": domain_detail})
        timeline.append({"stage": "Intent & Scam Type", "risk": str(breakdown.intent_risk), "detail": f"Detected: {scam_label} (confidence: {confidence})"})
        timeline.append({"stage": "Manipulation Signals", "risk": str(breakdown.urgency_risk), "detail": urgency_detail})
        timeline.append({"stage": "Spoofing/Branding", "risk": str(breakdown.spoof_risk), "detail": spoof_detail})
        timeline.append({"stage": "Final Decision", "risk": str(overall), "detail": f"Overall score: {overall}/100 → {_trust_label(overall)}"})
        return timeline

    def _heuristic_intent(self, text: str) -> Tuple[int, List[Dict[str, str]], str]:
        urgency_hits = _collect_phrases(text, URGENCY_PATTERNS, "urgency")
        manipulation_hits = _collect_phrases(text, MANIPULATION_PATTERNS, "manipulation")
        spoof_hits = _collect_phrases(text, SPOOF_PATTERNS, "spoofing")

        intent_score = 0
        intent_score += 15 * len(manipulation_hits)
        intent_score += 10 * len(spoof_hits)
        intent_score += 8 * len(urgency_hits)
        # mild bump for long messages pushing actions
        if len(text) > 500:
            intent_score += 10

        highlights = urgency_hits + manipulation_hits + spoof_hits
        explanation = "Heuristic intent analysis from keyword patterns and tone."
        return normalize_score(intent_score), highlights, explanation

    def _llm_intent(self, text: str, model: Optional[str] = None) -> Optional[Tuple[int, str]]:
        if not self.openai_api_key or not text.strip():
            return None
        try:
            import openai

            client = openai.OpenAI(api_key=self.openai_api_key)
            model_name = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            response = client.chat.completions.create(
                model=model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "Rate phishing/social-engineering intent from 0-100 and explain briefly. Reply ONLY with JSON {\"score\": number, \"reason\": \"...\"}",
                    },
                    {"role": "user", "content": text[:4000]},
                ],
            )
            content = response.choices[0].message.content
            data = json.loads(content)
            if not isinstance(data, dict) or "score" not in data:
                return None
            score = int(data.get("score", 0))
            reason = data.get("reason", "LLM-based intent classification.")
            return normalize_score(score), reason
        except Exception:
            return None

    def _analyze_domain(self, url: str, allow_network: bool = False) -> DomainFinding:
        issues: List[str] = []
        score = 0
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        parsed = tldextract.extract(url)
        domain = parsed.domain
        suffix = parsed.suffix
        fqdn = ".".join(part for part in [parsed.domain, parsed.suffix] if part)
        netloc = urlparse(url).netloc
        host = netloc.split(":")[0] if netloc else fqdn

        if _shortener_used(fqdn):
            issues.append("Uses URL shortener")
            score += 25

        if _suspicious_tld(suffix):
            issues.append(f"Suspicious TLD .{suffix}")
            score += 20

        if _punycode_present(parsed.domain):
            issues.append("Punycode detected")
            score += 20

        typo_ratio = _typosquat_score(domain)
        if typo_ratio >= 0.82:
            issues.append(f"Looks like typo-squat of a known brand (similarity {typo_ratio:.2f})")
            score += 30

        net_allowed = allow_network and _is_safe_target(url)
        if allow_network and not net_allowed:
            issues.append("Network checks skipped (unsafe target)")

        if net_allowed:
            redirect_count = _check_redirects(url) if url.startswith("http") else 0
            if redirect_count >= 2:
                issues.append(f"Multiple redirects detected ({redirect_count})")
                score += 15
            elif redirect_count == 1:
                issues.append("Redirect present")
                score += 8
        else:
            issues.append("Redirect check skipped (privacy lock)")

        entropy = _domain_entropy(domain)
        if entropy > 2.5:
            issues.append("High domain entropy (looks randomised)")
            score += 10

        age_days = _domain_age_days(fqdn) if fqdn and net_allowed else None
        if net_allowed:
            if age_days is not None:
                if age_days < 30:
                    issues.append(f"New domain (~{age_days} days old)")
                    score += 20
                elif age_days < 180:
                    issues.append(f"Recently registered domain (~{age_days} days old)")
                    score += 10
            else:
                issues.append("Domain age unknown (WHOIS/RDAP unavailable)")
        else:
            issues.append("Domain age check skipped (privacy lock)")

        if host and net_allowed:
            cert_days = _cert_days_remaining(host)
            if cert_days is not None and cert_days < 30:
                issues.append("TLS certificate close to expiry or misconfigured")
                score += 8
            elif cert_days is None:
                issues.append("TLS certificate status unknown")
        elif host and not allow_network:
            issues.append("TLS check skipped (privacy lock)")

        score += _https_score(url)
        return DomainFinding(url=url, issues=issues, score=normalize_score(score))

    def _content_risk(self, text: str) -> Tuple[int, List[Dict[str, str]]]:
        highlights = _collect_phrases(text, MANIPULATION_PATTERNS, "content")
        score = 10 * len(highlights)
        if "gift card" in text.lower() or "crypto" in text.lower():
            score += 15
        if "password" in text.lower():
            score += 10
        return normalize_score(score), highlights

    def _urgency_risk(self, text: str) -> Tuple[int, List[Dict[str, str]]]:
        highlights = _collect_phrases(text, URGENCY_PATTERNS, "urgency")
        score = 12 * len(highlights)
        if "minutes" in text.lower():
            score += 8
        return normalize_score(score), highlights

    def _spoof_risk(self, text: str) -> Tuple[int, List[Dict[str, str]]]:
        highlights = _collect_phrases(text, SPOOF_PATTERNS, "spoofing")
        score = 12 * len(highlights)
        return normalize_score(score), highlights

    def analyze(
        self,
        message_text: str,
        urls: Optional[List[str]] = None,
        include_llm: bool = True,
        allow_network: bool = False,
        llm_model: Optional[str] = None,
    ) -> RiskResult:
        text = message_text or ""
        detected_urls = urls or extract_urls(text)
        scam_types = _categorize_message(text)

        domain_findings = [self._analyze_domain(url, allow_network=allow_network) for url in detected_urls]
        domain_score = (
            sum(f.score for f in domain_findings) / len(domain_findings) if domain_findings else 0
        )

        content_score, content_highlights = self._content_risk(text)
        urgency_score, urgency_highlights = self._urgency_risk(text)
        spoof_score, spoof_highlights = self._spoof_risk(text)

        intent_score, intent_highlights, intent_reason = self._heuristic_intent(text)
        confidence = "Medium"
        reasoning = intent_reason

        if include_llm and allow_network:
            llm_result = self._llm_intent(text, model=llm_model)
            if llm_result:
                intent_score = normalize_score(int((intent_score + llm_result[0]) / 2))
                confidence = "High"
                reasoning = llm_result[1]

        breakdown = ScoreBreakdown(
            domain_risk=normalize_score(domain_score),
            intent_risk=normalize_score(intent_score),
            content_risk=normalize_score(content_score),
            urgency_risk=normalize_score(urgency_score),
            spoof_risk=normalize_score(spoof_score),
            confidence=confidence,
        )

        overall = normalize_score(
            WEIGHTS["domain"] * breakdown.domain_risk
            + WEIGHTS["content"] * breakdown.content_risk
            + WEIGHTS["urgency"] * breakdown.urgency_risk
            + WEIGHTS["spoof"] * breakdown.spoof_risk
        )

        highlights = content_highlights + urgency_highlights + intent_highlights + spoof_highlights

        timeline = self._build_timeline(
            breakdown,
            scam_types,
            overall,
            confidence,
            domain_findings,
            content_highlights,
            urgency_highlights,
            spoof_highlights,
        )

        evidence: List[Dict[str, str]] = []
        for finding in domain_findings:
            for issue in finding.issues:
                evidence.append({"type": "domain", "detail": issue, "url": finding.url, "severity": "0.5"})
        for h in highlights:
            evidence.append(
                {
                    "type": h.get("category", ""),
                    "detail": h.get("phrase", ""),
                    "snippet": h.get("snippet", ""),
                    "severity": str(h.get("severity", "")),
                    "explanation": h.get("explanation", ""),
                }
            )

        def _clean(items: List[Dict[str, str]]) -> List[Dict[str, str]]:
            seen = set()
            deduped = []
            for item in items:
                key = (item.get("type"), item.get("detail"), item.get("snippet"))
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(item)
            deduped.sort(key=lambda x: float(x.get("severity", 0) or 0), reverse=True)
            return deduped[:12]

        evidence = _clean(evidence)
        highlights = _clean(highlights)

        recommended_actions = _generate_actions(scam_types)
        safe_replies = _generate_replies(scam_types)

        return RiskResult(
            overall_risk=overall,
            trust_label=_trust_label(overall),
            breakdown=breakdown,
            domain_findings=domain_findings,
            highlights=highlights,
            scam_types=scam_types,
            recommended_actions=recommended_actions,
            safe_replies=safe_replies,
            detected_urls=detected_urls,
            generated_at=time.time(),
            reasoning=reasoning,
            evidence=evidence,
            total_score=overall,
            timeline=timeline,
            weights=WEIGHTS,
        )
