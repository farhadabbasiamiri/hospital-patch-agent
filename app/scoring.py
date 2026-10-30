"""Transparent, explainable risk score (0-100).

score = severity + threat + exposure + patient_safety + operational - control_credit

Every component is returned so the dashboard and the report can show exactly why an
asset/CVE pair ranks where it does. No black box: an analyst can recompute it by hand.
"""
from app.config import (WEIGHTS, EXPOSURE_POINTS, CONTROL_CREDITS, CONTROL_CAP, TIERS, SAFETY_FLOOR_CVSS)

PERIMETER_CATEGORIES = {"identity_infra", "network_perimeter"}


def control_credit(asset: dict) -> tuple[float, list[str]]:
    """Compensating-control credit. Controls only count where they actually help."""
    applied = []
    total = 0.0
    exposure = asset["exposure"]
    for c in asset.get("controls", []):
        pts = CONTROL_CREDITS.get(c, 0)
        if c == "segmentation" and exposure == "internet":
            continue
        if c == "waf" and exposure not in ("internet", "dmz"):
            continue
        if c == "mfa" and asset["category"] not in PERIMETER_CATEGORIES:
            continue
        total += pts
        applied.append(f"{c} (-{pts})")
    return min(total, CONTROL_CAP), applied


def tier_for(score: float) -> str:
    for threshold, name in TIERS:
        if score >= threshold:
            return name
    return "Low"


def score_risk(asset: dict, cve: dict) -> dict:
    severity = cve["cvss"] / 10 * WEIGHTS["severity_max"]
    threat = (WEIGHTS["kev_bonus"] if cve["kev"] else 0) + cve["epss"] * WEIGHTS["epss_max"]
    exposure = EXPOSURE_POINTS[asset["exposure"]]
    patient = asset["patient_safety_impact"] / 5 * WEIGHTS["patient_safety_max"]
    operational = asset["operational_criticality"] / 5 * WEIGHTS["operational_max"]
    credit, applied = control_credit(asset)

    raw = severity + threat + exposure + patient + operational
    score = round(max(0.0, min(100.0, raw - credit)), 1)
    tier = tier_for(score)

    # Patient-safety floor (added after Week-6 evaluation, scenario S04): a near-maximum
    # severity flaw on a life-critical device is never below High, even with low EPSS.
    floor_applied = False
    if asset.get("life_critical") and cve["cvss"] >= SAFETY_FLOOR_CVSS and tier in ("Medium", "Low"):
        tier, floor_applied = "High", True
    return {
        "score": score,
        "tier": tier,
        "safety_floor_applied": floor_applied,
        "components": {
            "severity (CVSS)": round(severity, 1),
            "threat (KEV + EPSS)": round(threat, 1),
            "exposure": round(exposure, 1),
            "patient safety": round(patient, 1),
            "operational": round(operational, 1),
            "compensating controls": -round(credit, 1),
        },
        "controls_credited": applied,
    }


def cvss_only_score(cve: dict) -> float:
    """Baseline used in evaluation: what a CVSS-only scanner report would rank by."""
    return cve["cvss"] * 10
