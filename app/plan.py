"""Builds the ranked remediation plan for the whole synthetic hospital."""
import pandas as pd

from app.data_store import load_assets, load_vulns, get_asset, get_cve
from app.decision import decide


def evaluate_record(record: dict) -> dict:
    asset = get_asset(record["asset_id"])
    cve = get_cve(record["cve_id"])
    return {"asset": asset, "cve": cve, "record": record, "result": decide(asset, record, cve)}


def build_plan() -> pd.DataFrame:
    rows = []
    for rec in load_vulns().to_dict("records"):
        e = evaluate_record(rec)
        a, c, r = e["asset"], e["cve"], e["result"]
        rows.append({
            "record_id": rec["record_id"],
            "asset_id": a["asset_id"],
            "hostname": a["hostname"],
            "category": a["category"],
            "department": a["department"],
            "cve_id": c["cve_id"],
            "vulnerability": c["title"],
            "cvss": c["cvss"],
            "kev": c["kev"],
            "epss": c["epss"],
            "exposure": a["exposure"],
            "patient_impact": a["patient_safety_impact"],
            "risk_score": r["risk"]["score"],
            "tier": r["risk"]["tier"],
            "decision": r["decision"],
            "change_type": r["change_type"],
            "due_in_days": r["due_in_days"],
            "approval_required": r["approval_required"],
            "approvers": ", ".join(r["approvers"]),
        })
    df = pd.DataFrame(rows).sort_values(["risk_score", "epss"], ascending=False).reset_index(drop=True)
    df.insert(0, "rank", df.index + 1)
    return df
