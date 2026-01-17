import json
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional

from .risk_engine import RiskResult


class HistoryStore:
    def __init__(self, db_path: str = "data/shieldgpt.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    session_id TEXT,
                    input_type TEXT,
                    raw_text TEXT,
                    urls TEXT,
                    overall INTEGER,
                    trust_label TEXT,
                    confidence TEXT,
                    scam_type TEXT,
                    breakdown TEXT,
                    highlights TEXT,
                    actions TEXT,
                    safe_replies TEXT,
                    reasoning TEXT,
                    domain_findings TEXT,
                    scam_types TEXT
                )
                """
            )
            # Lightweight migration to add domain_findings column if missing
            columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(scans)").fetchall()
            }
            if "session_id" not in columns:
                conn.execute("ALTER TABLE scans ADD COLUMN session_id TEXT")
            if "domain_findings" not in columns:
                conn.execute("ALTER TABLE scans ADD COLUMN domain_findings TEXT")
            if "scam_types" not in columns:
                conn.execute("ALTER TABLE scans ADD COLUMN scam_types TEXT")
            if "trust_label" not in columns:
                conn.execute("ALTER TABLE scans ADD COLUMN trust_label TEXT")
            if "confidence" not in columns:
                conn.execute("ALTER TABLE scans ADD COLUMN confidence TEXT")
            if "scam_type" not in columns:
                conn.execute("ALTER TABLE scans ADD COLUMN scam_type TEXT")
            conn.commit()

    def save_scan(
        self, result: RiskResult, input_type: str, raw_text: str, urls: Optional[List[str]] = None
    ) -> int:
        import uuid

        session_id = str(uuid.uuid4())
        primary_scam = result.scam_types[0] if result.scam_types else ""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (
                    created_at,
                    session_id,
                    input_type,
                    raw_text,
                    urls,
                    overall,
                    trust_label,
                    confidence,
                    scam_type,
                    breakdown,
                    highlights,
                    actions,
                    safe_replies,
                    reasoning,
                    domain_findings,
                    scam_types
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    session_id,
                    input_type,
                    raw_text,
                    json.dumps(urls or []),
                    result.overall_risk,
                    result.trust_label,
                    result.breakdown.confidence,
                    primary_scam,
                    result.breakdown.model_dump_json(),
                    json.dumps(result.highlights),
                    json.dumps(result.recommended_actions),
                    json.dumps(result.safe_replies),
                    result.reasoning,
                    json.dumps([df.model_dump() for df in result.domain_findings]),
                    json.dumps(result.scam_types),
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def list_scans(self, limit: int = 25) -> List[Dict]:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                SELECT id, created_at, session_id, input_type, overall, trust_label, confidence, scam_type, urls, raw_text, scam_types
                FROM scans ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
        return [
            {
                "id": row[0],
                "created_at": row[1],
                "session_id": row[2],
                "input_type": row[3],
                "overall": row[4],
                "trust_label": row[5],
                "confidence": row[6],
                "scam_type": row[7],
                "urls": json.loads(row[8]) if row[8] else [],
                "raw_text": row[9],
                "scam_types": json.loads(row[10]) if len(row) > 10 and row[10] else [],
            }
            for row in rows
        ]

    def load_scan(self, scan_id: int) -> Optional[Dict]:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                SELECT id, created_at, session_id, input_type, raw_text, urls, overall, trust_label,
                       confidence, scam_type, breakdown, highlights, actions, safe_replies, reasoning,
                       domain_findings, scam_types
                FROM scans WHERE id = ?
                """,
                (scan_id,),
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "created_at": row[1],
            "session_id": row[2],
            "input_type": row[3],
            "raw_text": row[4],
            "urls": json.loads(row[5]) if row[5] else [],
            "overall": row[6],
            "trust_label": row[7],
            "confidence": row[8],
            "scam_type": row[9],
            "breakdown": json.loads(row[10]),
            "domain_findings": json.loads(row[15]) if row[15] else [],
            "highlights": json.loads(row[11]),
            "actions": json.loads(row[12]),
            "safe_replies": json.loads(row[13]),
            "reasoning": row[14],
            "scam_types": json.loads(row[16]) if len(row) > 16 and row[16] else [],
        }
