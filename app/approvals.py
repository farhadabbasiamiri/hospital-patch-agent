"""Human-in-the-loop approval queue (SQLite).

The agent can only SUBMIT a recommendation. A named human reviewer approves or rejects it.
Approval records the decision for the change plan; nothing is executed on any system.
"""
import json
import sqlite3
from datetime import datetime, timezone

import pandas as pd

from app.config import APPROVALS_DB
from app.monitoring import log_event

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT, asset_id TEXT, hostname TEXT, cve_id TEXT,
    decision TEXT, change_type TEXT, risk_score REAL, tier TEXT,
    required_approvers TEXT, summary TEXT, payload TEXT,
    status TEXT DEFAULT 'PENDING',
    reviewer TEXT, reviewer_role TEXT, review_note TEXT,
    submitted_at TEXT, reviewed_at TEXT
)"""


def _conn():
    APPROVALS_DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(APPROVALS_DB)
    c.execute(SCHEMA)
    return c


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def submit(rec: dict) -> int:
    """rec is the agent's final (guardrailed) recommendation."""
    with _conn() as c:
        existing = c.execute("SELECT id FROM approvals WHERE record_id=? AND status='PENDING'",
                             (rec["record_id"],)).fetchone()
        if existing:
            return existing[0]
        cur = c.execute(
            """INSERT INTO approvals (record_id, asset_id, hostname, cve_id, decision, change_type, risk_score,
               tier, required_approvers, summary, payload, submitted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rec["record_id"], rec["asset_id"], rec["hostname"], rec["cve_id"], rec["decision"],
             rec["change_type"], rec["risk_score"], rec["tier"], ", ".join(rec["approvers"]),
             rec["summary"], json.dumps(rec, default=str), _now()))
        aid = cur.lastrowid
    log_event("approval_submitted", approval_id=aid, record_id=rec["record_id"], decision=rec["decision"])
    return aid


def review(approval_id: int, approve: bool, reviewer: str, role: str, note: str) -> str:
    reviewer, role = (reviewer or "").strip(), (role or "").strip()
    if not reviewer or not role:
        raise ValueError("Reviewer name and role are required for an auditable approval.")
    with _conn() as c:
        row = c.execute("SELECT status, required_approvers FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if not row:
            raise ValueError(f"Approval #{approval_id} not found.")
        if row[0] != "PENDING":
            raise ValueError(f"Approval #{approval_id} is already {row[0]}.")
        status = "APPROVED" if approve else "REJECTED"
        c.execute("UPDATE approvals SET status=?, reviewer=?, reviewer_role=?, review_note=?, reviewed_at=? WHERE id=?",
                  (status, reviewer, role, (note or "")[:500], _now(), approval_id))
    log_event("approval_decided", approval_id=approval_id, status=status, reviewer_role=role)
    return status


def list_approvals(status: str | None = None) -> pd.DataFrame:
    cols = "id, status, record_id, hostname, cve_id, decision, change_type, risk_score, tier, required_approvers, " \
           "reviewer, reviewer_role, review_note, submitted_at, reviewed_at"
    with _conn() as c:
        q = f"SELECT {cols} FROM approvals" + (" WHERE status=?" if status else "") + " ORDER BY risk_score DESC, id"
        return pd.read_sql_query(q, c, params=(status,) if status else ())
