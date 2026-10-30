"""Run: pytest -q"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from app import approvals, config  # noqa: E402
from app.agent import run_agent, apply_guardrails, extract_json  # noqa: E402
from app.data_store import load_assets, load_vulns, get_record  # noqa: E402
from app.decision import decide  # noqa: E402
from app.plan import build_plan  # noqa: E402
from app.rag import get_index  # noqa: E402
from app.scoring import score_risk  # noqa: E402
from app.tools import execute_tool  # noqa: E402
from fake_llms import ScriptedLLM, ADVERSARIAL  # noqa: E402

BASE_ASSET = dict(asset_id="T", hostname="T", category="ehr_clinical_app", department="x", exposure="internal",
                  patient_safety_impact=4, operational_criticality=5, life_critical=False, downtime_tolerance="low",
                  next_window_days=3, vendor_validation_required=False, redundancy=True, can_isolate=True, controls=[])
KEV_CVE = dict(cve_id="CVE-2021-44228", title="t", cvss=10.0, kev=True, epss=0.97)
FIX = dict(record_id="T", patch_available=True, vendor_validated=True)


# ---------------- data
def test_dataset_size_and_categories():
    assert 100 <= len(load_vulns()) <= 300           # brief: 100-300 asset/CVE records
    assert 5 <= load_assets().category.nunique() <= 8  # brief: 5-8 asset categories


# ---------------- scoring
def test_score_bounds_and_components_sum():
    r = score_risk(BASE_ASSET, KEV_CVE)
    assert 0 <= r["score"] <= 100
    assert abs(sum(r["components"].values()) - r["score"]) < 0.2


def test_kev_raises_score():
    no_kev = {**KEV_CVE, "kev": False, "epss": 0.01}
    assert score_risk(BASE_ASSET, KEV_CVE)["score"] > score_risk(BASE_ASSET, no_kev)["score"]


def test_controls_capped():
    many = {**BASE_ASSET, "controls": list(config.CONTROL_CREDITS)}
    assert score_risk(BASE_ASSET, KEV_CVE)["score"] - score_risk(many, KEV_CVE)["score"] <= config.CONTROL_CAP


def test_safety_floor():
    a = {**BASE_ASSET, "category": "patient_care_device", "life_critical": True, "exposure": "isolated",
         "patient_safety_impact": 5, "controls": ["segmentation", "ips"]}
    r = score_risk(a, {**KEV_CVE, "kev": False, "epss": 0.01})
    assert r["tier"] in ("High", "Critical")


# ---------------- decision engine safety rules
def test_never_patch_unvalidated_medical_device():
    a = {**BASE_ASSET, "category": "patient_care_device", "vendor_validation_required": True}
    r = decide(a, {**FIX, "vendor_validated": False}, KEV_CVE)
    assert r["decision"] != "PATCH" and "PATCH" not in r["allowed_options"]


def test_no_downtime_system_isolated_first():
    a = {**BASE_ASSET, "category": "patient_care_device", "life_critical": True, "downtime_tolerance": "none",
         "redundancy": False, "next_window_days": 60}
    assert decide(a, FIX, KEV_CVE)["decision"] == "ISOLATE"


def test_every_change_needs_approval():
    plan = build_plan()
    assert plan[plan.decision != "MONITOR"].approval_required.all()
    assert not plan[plan.decision == "MONITOR"].approval_required.any()


def test_emergency_needs_ecab_and_ciso():
    r = decide({**BASE_ASSET, "next_window_days": 20}, FIX, KEV_CVE)
    assert r["change_type"] == "emergency"
    assert any("ECAB" in x for x in r["approvers"]) and "CISO" in r["approvers"]


# ---------------- RAG
def test_rag_returns_citations():
    hits = get_index().search("vendor validation medical device patch", k=3)
    assert hits and hits[0]["chunk_id"].startswith("POL-04")


# ---------------- tools
@pytest.mark.parametrize("name,args", [("get_asset_context", {"asset_id": "NOPE"}),
                                       ("get_vulnerability_intel", {"cve_id": "CVE-0000-0000"}),
                                       ("compute_risk_and_options", {"record_id": "R-9999"}),
                                       ("search_patch_policy", {"query": ""}),
                                       ("rm_rf", {}), ("get_asset_context", {"bad": 1})])
def test_tools_fail_gracefully(name, args):
    result, entry = execute_tool(name, args)
    assert "error" in result and entry["ok"] is False


# ---------------- agent + guardrails
def test_agent_offline_end_to_end():
    rec = run_agent("R-0001", force_offline=True)
    assert rec["decision"] in rec["allowed_options"]
    assert {t["tool"] for t in rec["trace"]} == {"get_asset_context", "get_vulnerability_intel",
                                                 "compute_risk_and_options", "search_patch_policy"}


def test_agent_llm_loop_with_scripted_llm():
    rec = run_agent("R-0001", llm=ScriptedLLM(get_record("R-0001")))
    assert rec["mode"] == "llm" and rec["guardrail_flags"] == []
    assert all(t["chosen_by"] == "LLM" for t in rec["trace"])


@pytest.mark.parametrize("cls", ADVERSARIAL, ids=lambda c: c.name)
def test_guardrails_block_adversarial_llms(cls):
    rid = "R-0001"
    rec = run_agent(rid, llm=cls(get_record(rid)))
    assert rec["decision"] in rec["allowed_options"]
    assert rec["approval_required"] == (rec["decision"] != "MONITOR")
    assert rec["guardrail_flags"], "attack should be flagged"
    assert rec["summary"]


def test_extract_json_handles_markdown():
    assert extract_json('```json\n{"decision": "PATCH"}\n```') == {"decision": "PATCH"}
    assert extract_json("no json here") is None


def test_guardrail_unit():
    engine = {"decision": "ISOLATE", "allowed_options": ["ISOLATE"], "approval_required": True,
              "approvers": ["CISO"], "policy_refs": ["POL-06 §3"]}
    out, flags = apply_guardrails({"decision": "patch", "approval_required": False,
                                   "policy_citations": ["POL-77 §1"]}, engine, set())
    assert out["decision"] == "ISOLATE" and out["approval_required"] and out["policy_citations"] == ["POL-06 §3"]
    assert len(flags) == 3


# ---------------- human approval
def test_approval_flow(tmp_path, monkeypatch):
    monkeypatch.setattr(approvals, "APPROVALS_DB", tmp_path / "a.db")
    rec = run_agent("R-0001", force_offline=True)
    aid = approvals.submit(rec)
    assert approvals.submit(rec) == aid  # no duplicate pending items
    with pytest.raises(ValueError):
        approvals.review(aid, True, "", "", "")  # anonymous approval refused
    assert approvals.review(aid, True, "Dr. Test", "CISO", "ok") == "APPROVED"
    with pytest.raises(ValueError):
        approvals.review(aid, False, "X", "CISO", "")  # cannot re-decide
