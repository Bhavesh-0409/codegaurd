"""
Simple SQLite-backed audit log.

Kept intentionally minimal for hackathon scope:
- one table
- no auth/roles system (see NOTE in main.py)
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "sentinel.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    scan_type TEXT NOT NULL,      -- 'prompt' | 'code'
    verdict TEXT NOT NULL,        -- clean | unverified | typosquat | hallucinated | malicious | injection_detected
    flagged_item TEXT,            -- package name OR prompt snippet
    reason TEXT,
    severity TEXT NOT NULL        -- low | medium | high
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute(SCHEMA)


def log_event(user_id: str, scan_type: str, verdict: str, flagged_item: str, reason: str, severity: str):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO audit_log (user_id, timestamp, scan_type, verdict, flagged_item, reason, severity)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                datetime.now(timezone.utc).isoformat(),
                scan_type,
                verdict,
                flagged_item,
                reason,
                severity,
            ),
        )


def get_all_events(limit: int = 500):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_user_summary():
    """Flag counts per user, for the admin 'top offenders' view."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT user_id,
                   COUNT(*) AS total_flags,
                   SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high_severity_count,
                   MAX(timestamp) AS last_flag_at
            FROM audit_log
            WHERE verdict != 'clean'
            GROUP BY user_id
            ORDER BY total_flags DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]
