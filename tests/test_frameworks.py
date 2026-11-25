"""MITRE ATT&CK / NIST CSF mapping completeness and wiring."""
import re

from app.agent import run_agent
from app.config import CONTROL_CREDITS, DECISIONS
from app.data_store import load_intel
from app.frameworks import load_mapping, map_finding
from app.plan import build_plan


def test_every_cve_has_a_mapping():
    m = load_mapping()
    assert set(load_intel()["cves"]) == set(m["cves"])
    for cve in m["cves"].values():
        assert cve["techniques"] and cve["rationale"]


def test_all_referenced_ids_are_defined():
    m = load_mapping()
    for cve in m["cves"].values():
        assert set(cve["techniques"]) <= set(m["techniques"])
    assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in m["techniques"])
    assert set(m["control_mitigations"].values()) <= set(m["mitigations"])
    for d in DECISIONS:
        assert set(m["decision_mitigations"][d]) <= set(m["mitigations"])
        assert set(m["decision_csf"][d]) | set(m["csf_common"]) <= set(m["csf"])


def test_every_scored_control_has_a_mitigation():
    assert set(CONTROL_CREDITS) <= set(load_mapping()["control_mitigations"])


def test_unknown_cve_is_handled():
    f = map_finding("CVE-0000-0000", "MONITOR", ["unknown-control"])
    assert f["attack_techniques"] == [] and f["mitigations_in_place"] == []


def test_mapping_reaches_agent_output_and_plan():
    rec = run_agent("R-0138", force_offline=True)
    assert rec["attack_techniques"] and "PR.PS-02" in {c["id"] for c in rec["nist_csf"]}
    plan = build_plan()
    assert (plan.attack != "").all() and (plan.nist_csf != "").all()
