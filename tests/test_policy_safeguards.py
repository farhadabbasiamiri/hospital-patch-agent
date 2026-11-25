"""Isolation (POL-06 section 5) and deferral-control (POL-05 section 2) safeguards."""
import sqlite3

import pytest

from app import approvals
from app.agent import run_agent
from app.config import MIN_DEFER_CONTROLS
from app.data_store import load_vulns
from app.plan import evaluate_record
from app.scoring import defer_control_status


def _all_results():
    return [evaluate_record(r) for r in load_vulns().to_dict("records")]


def test_isolation_never_offered_for_non_isolatable_assets():
    for e in _all_results():
        if not e["asset"]["can_isolate"]:
            assert e["result"]["decision"] != "ISOLATE", e["record"]["record_id"]
            assert "ISOLATE" not in e["result"]["allowed_options"], e["record"]["record_id"]


def test_non_isolatable_life_critical_device_is_deferred():
    rec = run_agent("R-0064", force_offline=True)  # patient-care device, window beyond SLA
    assert rec["decision"] == "DEFER_WITH_CONTROLS" and rec["allowed_options"] == ["DEFER_WITH_CONTROLS"]
    assert "POL-06 §5" in rec["policy_citations"] and "CISO" in rec["approvers"]


def test_every_deferral_reports_its_control_gap():
    for e in _all_results():
        r = e["result"]
        d = r["defer_controls"]
        assert d["missing"] == max(0, MIN_DEFER_CONTROLS - len(d["in_place"]))
        if r["decision"] == "DEFER_WITH_CONTROLS" and d["missing"]:
            assert any("POL-05 §2 requires" in reason for reason in r["reasons"])


def test_irrelevant_controls_do_not_count():
    asset = {"exposure": "internet", "category": "admin_business", "controls": ["segmentation", "mfa", "edr"]}
    d = defer_control_status(asset)
    assert d["in_place"] == ["edr"] and d["missing"] == 1


def _submit_deferral(tmp_path, monkeypatch):
    monkeypatch.setattr(approvals, "APPROVALS_DB", tmp_path / "a.db")
    rec = run_agent("R-0064", force_offline=True)  # no controls in place, so 2 are missing
    assert rec["defer_controls"]["missing"] == 2
    return rec, approvals.submit(rec)


def test_deferral_cannot_be_approved_without_enough_controls(tmp_path, monkeypatch):
    rec, aid = _submit_deferral(tmp_path, monkeypatch)
    first, last = rec["approvers"][:-1], rec["approvers"][-1]
    for role in first:
        assert approvals.review(aid, True, "Dr. Test", role, "") == "PENDING"
    with pytest.raises(ValueError, match="POL-05"):
        approvals.review(aid, True, "Dr. Test", last, "")
    with pytest.raises(ValueError, match="POL-05"):
        approvals.review(aid, True, "Dr. Test", last, "", controls=["segmentation"])  # only one
    assert approvals.signoff_state(aid)["missing"] == [last]  # refused sign-offs are not recorded
    assert approvals.review(aid, True, "Dr. Test", last, "", controls=["segmentation", "ips"]) == "APPROVED"
    assert approvals.signoff_state(aid)["deferral"]["still_needed"] == 0


def test_controls_accumulate_across_signers_without_double_counting(tmp_path, monkeypatch):
    rec, aid = _submit_deferral(tmp_path, monkeypatch)
    roles = rec["approvers"]
    assert approvals.review(aid, True, "A", roles[0], "", controls=["ips"]) == "PENDING"
    for role in roles[1:-1]:
        approvals.review(aid, True, "B", role, "")
    with pytest.raises(ValueError, match="POL-05"):
        approvals.review(aid, True, "C", roles[-1], "", controls=["ips"])  # same control again
    assert approvals.review(aid, True, "C", roles[-1], "", controls=["segmentation"]) == "APPROVED"


def test_invalid_control_refused_and_rejection_needs_none(tmp_path, monkeypatch):
    rec, aid = _submit_deferral(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="eligible"):
        approvals.review(aid, True, "A", rec["approvers"][0], "", controls=["wishful_thinking"])
    assert approvals.review(aid, False, "A", rec["approvers"][0], "unsafe") == "REJECTED"


def test_controls_refused_on_non_deferral(tmp_path, monkeypatch):
    monkeypatch.setattr(approvals, "APPROVALS_DB", tmp_path / "a.db")
    rec = run_agent("R-0138", force_offline=True)
    aid = approvals.submit(rec)
    with pytest.raises(ValueError, match="deferral"):
        approvals.review(aid, True, "A", rec["approvers"][0], "", controls=["ips"])


def test_older_signoff_table_is_migrated(tmp_path, monkeypatch):
    db = tmp_path / "old.db"
    monkeypatch.setattr(approvals, "APPROVALS_DB", db)
    with sqlite3.connect(db) as c:
        c.execute("CREATE TABLE signoffs (id INTEGER PRIMARY KEY AUTOINCREMENT, approval_id INTEGER, role TEXT, "
                  "reviewer TEXT, approve INTEGER, note TEXT, signed_at TEXT, UNIQUE (approval_id, role))")
    rec = run_agent("R-0138", force_offline=True)
    aid = approvals.submit(rec)
    assert approvals.review(aid, True, "A", rec["approvers"][0], "") == "PENDING"
