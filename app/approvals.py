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
SIGNOFF_SCHEMA = """
CREATE TABLE IF NOT EXISTS signoffs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id INTEGER, role TEXT, reviewer TEXT, approve INTEGER, note TEXT, signed_at TEXT,
    UNIQUE (approval_id, role)
)"""


def _conn():
    APPROVALS_DB.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(APPROVALS_DB)
    c.execute(SCHEMA)
    c.execute(SIGNOFF_SCHEMA)
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


def required_roles(approvers: str) -> list[str]:
    return [r.strip() for r in (approvers or "").split(",") if r.strip()]


def review(approval_id: int, approve: bool, reviewer: str, role: str, note: str) -> str:
    """Record one role's sign-off. Quorum rule: the change is APPROVED only when EVERY required
    role has approved; a rejection by any required role REJECTS it. Returns the resulting status
    ('PENDING' while sign-offs are still missing)."""
    reviewer, role = (reviewer or "").strip(), (role or "").strip()
    if not reviewer or not role:
        raise ValueError("Reviewer name and role are required for an auditable approval.")
    with _conn() as c:
        row = c.execute("SELECT status, required_approvers FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if not row:
            raise ValueError(f"Approval #{approval_id} not found.")
        if row[0] != "PENDING":
            raise ValueError(f"Approval #{approval_id} is already {row[0]}.")
        needed = required_roles(row[1])
        if role not in needed:
            raise ValueError(f"Role '{role}' is not an authorized approver for this change (required: {', '.join(needed)}).")
        if c.execute("SELECT 1 FROM signoffs WHERE approval_id=? AND role=?", (approval_id, role)).fetchone():
            raise ValueError(f"Role '{role}' has already signed off on approval #{approval_id}.")
        c.execute("INSERT INTO signoffs (approval_id, role, reviewer, approve, note, signed_at) VALUES (?,?,?,?,?,?)",
                  (approval_id, role, reviewer, int(approve), (note or "")[:500], _now()))
        signed = {r[0] for r in c.execute("SELECT role FROM signoffs WHERE approval_id=? AND approve=1", (approval_id,))}
        if not approve:
            status = "REJECTED"
        elif set(needed) <= signed:
            status = "APPROVED"
        else:
            status = "PENDING"
        if status != "PENDING":
            c.execute("UPDATE approvals SET status=?, reviewer=?, reviewer_role=?, review_note=?, reviewed_at=? WHERE id=?",
                      (status, reviewer, role, (note or "")[:500], _now(), approval_id))
    log_event("approval_signoff", approval_id=approval_id, role=role, approve=bool(approve), status=status)
    if status != "PENDING":
        log_event("approval_decided", approval_id=approval_id, status=status, reviewer_role=role)
    return status


def signoff_state(approval_id: int) -> dict:
    """Which required roles have signed / are still missing."""
    with _conn() as c:
        row = c.execute("SELECT required_approvers FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if not row:
            return {}
        signed = {r[0]: ("approved" if r[1] else "rejected")
                  for r in c.execute("SELECT role, approve FROM signoffs WHERE approval_id=?", (approval_id,))}
    needed = required_roles(row[0])
    return {"required": needed, "signed": signed, "missing": [r for r in needed if r not in signed]}


def list_approvals(status: str | None = None) -> pd.DataFrame:
    cols = "id, status, record_id, hostname, cve_id, decision, change_type, risk_score, tier, required_approvers, " \
           "reviewer, reviewer_role, review_note, submitted_at, reviewed_at"
    with _conn() as c:
        q = f"SELECT {cols} FROM approvals" + (" WHERE status=?" if status else "") + " ORDER BY risk_score DESC, id"
        df = pd.read_sql_query(q, c, params=(status,) if status else ())
        signed = {}
        for aid, role in c.execute("SELECT approval_id, role FROM signoffs WHERE approve=1"):
            signed.setdefault(aid, []).append(role)
        df.insert(df.columns.get_loc("required_approvers") + 1, "signed_off",
                  [", ".join(signed.get(i, [])) for i in df["id"]])
        return df
