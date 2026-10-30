"""Policy decision engine: turns a risk score + operational constraints into a safe
remediation recommendation (PATCH / ISOLATE / MONITOR / DEFER_WITH_CONTROLS).

This engine is deterministic and is the safety authority. The LLM agent explains and may
choose among `allowed_options`, but it cannot pick an action outside them and cannot
lower the approval requirement (see agent.apply_guardrails).
"""
from app.config import SLA_DAYS, KEV_INTERNET_SLA_DAYS
from app.scoring import score_risk


def _approval(decision: str, change_type: str, asset: dict, tier: str) -> tuple[bool, list[str], list[str]]:
    """Returns (approval_required, approvers, policy_refs)."""
    clinical = asset["category"] in ("medical_imaging", "patient_care_device")
    sensitive = asset["downtime_tolerance"] in ("none", "low")
    if decision == "MONITOR":
        return False, ["Owner team (acknowledge only)"], ["POL-01 §4"]
    if decision == "DEFER_WITH_CONTROLS":
        if tier in ("Critical", "High"):
            return True, ["CISO", "Asset clinical/business owner"], ["POL-05 §3", "POL-05 §2"]
        return True, ["Owner team manager"], ["POL-05 §3"]
    if decision == "ISOLATE":
        if clinical or sensitive:
            return True, ["CISO", "Clinical Engineering", "Clinical Lead of affected unit"], ["POL-06 §3"]
        return True, ["Owner team manager", "Security Operations"], ["POL-06 §3"]
    # PATCH
    if change_type == "emergency":
        approvers = ["Emergency CAB (ECAB)", "CISO"]
        if asset["life_critical"] or clinical:
            approvers.append("On-call Clinical Lead")
        return True, approvers, ["POL-02 §3"]
    approvers = ["IT Change Advisory Board (CAB)"]
    if sensitive:
        approvers.append("Clinical Systems Lead")
    if clinical:
        approvers.append("Clinical Engineering (Biomed)")
    return True, approvers, ["POL-02 §2"]


def decide(asset: dict, vuln: dict, cve: dict) -> dict:
    risk = score_risk(asset, cve)
    tier = risk["tier"]
    reasons, refs = [], ["POL-01 §2", "POL-01 §3"]
    if risk["safety_floor_applied"]:
        reasons.append(f"Patient-safety floor: CVSS {cve['cvss']} on a life-critical device is treated as at least High.")

    sla = SLA_DAYS[tier]
    if cve["kev"] and asset["exposure"] == "internet":
        sla = KEV_INTERNET_SLA_DAYS
        reasons.append("KEV-listed vulnerability on an internet-facing asset: 72-hour deadline.")

    needs_validation = asset["vendor_validation_required"]
    fix_ok = vuln["patch_available"] and (not needs_validation or vuln["vendor_validated"])
    window_ok = asset["next_window_days"] <= sla
    no_downtime = asset["downtime_tolerance"] == "none" and not asset["redundancy"]
    change_type = "none"

    if not fix_ok:
        if not vuln["patch_available"]:
            reasons.append("No vendor patch is available yet.")
        else:
            reasons.append("Patch exists but is not validated by the medical device manufacturer (POL-04 §2).")
            refs.append("POL-04 §2")
        if tier in ("Critical", "High") and asset["can_isolate"]:
            decision, options = "ISOLATE", ["ISOLATE", "DEFER_WITH_CONTROLS"]
            reasons.append(f"{tier} risk with no usable fix: partially isolate to cut exposure until a fix is released.")
            refs += ["POL-06 §2", "POL-04 §3"]
        elif tier in ("Critical", "High"):
            decision, options = "DEFER_WITH_CONTROLS", ["DEFER_WITH_CONTROLS"]
            reasons.append(f"{tier} risk, no usable fix and the asset cannot be isolated without patient-care impact.")
            refs += ["POL-05 §2", "POL-06 §5"]
        elif tier == "Medium":
            decision, options = "DEFER_WITH_CONTROLS", ["DEFER_WITH_CONTROLS", "MONITOR"]
            reasons.append("Medium risk with no usable fix: keep compensating controls and track vendor release.")
            refs += ["POL-05 §2"]
        else:
            decision, options = "MONITOR", ["MONITOR"]
            reasons.append("Low risk: track and bundle into routine maintenance once a fix exists.")
    else:
        if tier == "Critical":
            if window_ok:
                decision, options, change_type = "PATCH", ["PATCH"], "normal"
                reasons.append(f"Critical risk and the next patch window ({asset['next_window_days']} days) is inside the {sla}-day SLA.")
            elif no_downtime:
                decision, options = "ISOLATE", ["ISOLATE", "PATCH"]
                reasons.append("Critical risk, window is beyond SLA, and the system has no downtime tolerance and no failover: "
                               "isolate now, patch in the next approved window.")
                refs += ["POL-03 §3", "POL-06 §2"]
            else:
                decision, options, change_type = "PATCH", ["PATCH", "ISOLATE"], "emergency"
                reasons.append(f"Critical risk and the next window ({asset['next_window_days']} days) misses the {sla}-day SLA: emergency change.")
                refs += ["POL-02 §3"] + (["POL-03 §4"] if asset["redundancy"] else [])
        elif tier == "High":
            if window_ok:
                decision, options, change_type = "PATCH", ["PATCH"], "normal"
                reasons.append(f"High risk, fix available, next window in {asset['next_window_days']} days is within the {sla}-day SLA.")
            else:
                decision, options = "DEFER_WITH_CONTROLS", ["DEFER_WITH_CONTROLS", "PATCH"]
                reasons.append(f"High risk but the next safe window ({asset['next_window_days']} days) is beyond the {sla}-day SLA: "
                               "documented risk acceptance with controls until the window.")
                refs += ["POL-05 §1", "POL-05 §2"]
        elif tier == "Medium":
            decision, options, change_type = "PATCH", ["PATCH", "MONITOR"], "standard"
            reasons.append("Medium risk with a fix available: patch in the routine window.")
            refs.append("POL-03 §2")
        else:
            decision, options = "MONITOR", ["MONITOR", "PATCH"]
            reasons.append("Low risk: bundle into routine maintenance and track.")

    if asset["category"] == "patient_care_device":
        refs.append("POL-04 §1")
    approval_required, approvers, approval_refs = _approval(decision, change_type, asset, tier)

    return {
        "risk": risk,
        "decision": decision,
        "allowed_options": options,
        "change_type": change_type,
        "sla_days": sla,
        "due_in_days": sla,
        "reasons": reasons,
        "approval_required": approval_required,
        "approvers": approvers,
        "policy_refs": sorted(set(refs + approval_refs)),
    }
