"""Synthetic hospital asset inventory + asset/CVE records generator.

All data is fictional ("Northbridge Regional Hospital"). No real hospital, patient, or
employee data is used. Seeded so every team member gets identical data.

Usage:  python scripts/generate_data.py --assets 70 --seed 42
Output: data/assets.csv, data/asset_vulns.csv
"""
import argparse
import csv
import json
import random
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.config import ASSETS_CSV, VULNS_CSV, CVE_INTEL_JSON  # noqa: E402

# 8 asset categories. Each defines realistic ranges for the fields that matter to patching.
CATEGORIES = {
    "clinical_workstation": dict(
        prefix="CWS", label="Clinical workstation (nursing station / bedside)",
        os=["Windows 10 22H2", "Windows 11 23H2"],
        depts=["ICU", "Emergency", "Med-Surg", "Pediatrics", "Oncology"],
        exposure=["internal", "segmented"], psi=(2, 3), opc=(2, 3), life=0.0,
        downtime=["medium"], windows=[("Weekly Sun 02:00-05:00", (1, 7))],
        vendor_val=0.0, redundancy=0.9, isolate=0.9,
        controls=["edr", "allowlisting", "segmentation"],
        cves=["CVE-2021-34527", "CVE-2022-30190", "CVE-2023-23397", "CVE-2023-36884", "CVE-2016-2183", "CVE-2023-48795"]),
    "medical_imaging": dict(
        prefix="IMG", label="Medical imaging (PACS server / CT & MRI modality console)",
        os=["Windows 7 Embedded", "Windows Server 2012 R2", "Windows 10 IoT LTSC"],
        depts=["Radiology", "Cardiology", "Emergency"],
        exposure=["internal", "segmented"], psi=(4, 4), opc=(4, 5), life=0.2,
        downtime=["low"], windows=[("Monthly vendor window (2nd Sat)", (8, 35))],
        vendor_val=1.0, redundancy=0.3, isolate=0.7,
        controls=["segmentation", "ips", "allowlisting"],
        cves=["CVE-2019-0708", "CVE-2017-0144", "CVE-2021-44228", "CVE-2019-11687", "CVE-2016-2183"]),
    "patient_care_device": dict(
        prefix="PCD", label="Patient-care device gateway (infusion pump server / central monitoring station)",
        os=["VxWorks 6.9", "Embedded Linux", "Windows XP Embedded"],
        depts=["ICU", "NICU", "Emergency", "Operating Rooms"],
        exposure=["segmented", "isolated", "internal"], psi=(5, 5), opc=(5, 5), life=1.0,
        downtime=["none"], windows=[("Quarterly biomed visit", (20, 90))],
        vendor_val=1.0, redundancy=0.2, isolate=0.5,
        controls=["segmentation", "ips"],
        cves=["CVE-2019-12256", "CVE-2020-11896", "CVE-2017-0144", "CVE-2023-48795"]),
    "ehr_clinical_app": dict(
        prefix="EHR", label="EHR / clinical application server",
        os=["RHEL 8", "RHEL 9", "Ubuntu 22.04"],
        depts=["Clinical IT"], exposure=["internal", "dmz"], psi=(4, 5), opc=(5, 5), life=0.0,
        downtime=["low"], windows=[("Monthly Sun 01:00-04:00 (failover)", (3, 30))],
        vendor_val=0.3, redundancy=0.8, isolate=0.2,
        controls=["edr", "segmentation", "waf"],
        cves=["CVE-2021-44228", "CVE-2022-22965", "CVE-2021-4034", "CVE-2024-6387", "CVE-2014-0160", "CVE-2022-0778", "CVE-2023-38545"]),
    "lab_pharmacy": dict(
        prefix="LAB", label="Laboratory (LIS) / pharmacy dispensing system",
        os=["Windows Server 2016", "Windows 10 LTSC", "RHEL 8"],
        depts=["Laboratory", "Pharmacy"], exposure=["internal", "segmented"], psi=(4, 4), opc=(3, 4), life=0.0,
        downtime=["low", "medium"], windows=[("Bi-weekly Sat 23:00-02:00", (1, 14))],
        vendor_val=0.6, redundancy=0.5, isolate=0.6,
        controls=["edr", "segmentation"],
        cves=["CVE-2021-44228", "CVE-2017-0144", "CVE-2023-48795", "CVE-2021-34527", "CVE-2022-0778"]),
    "identity_infra": dict(
        prefix="IDN", label="Identity & core infrastructure (AD domain controller / vCenter)",
        os=["Windows Server 2019", "Windows Server 2022", "VMware vCenter 7"],
        depts=["IT Infrastructure"], exposure=["internal"], psi=(3, 3), opc=(5, 5), life=0.0,
        downtime=["low"], windows=[("Weekly Wed 22:00-23:00 (rolling)", (1, 7))],
        vendor_val=0.0, redundancy=1.0, isolate=0.0,
        controls=["edr", "mfa", "segmentation"],
        cves=["CVE-2020-1472", "CVE-2021-34527", "CVE-2021-21972", "CVE-2021-22005", "CVE-2021-4034"]),
    "network_perimeter": dict(
        prefix="NET", label="Network perimeter (VPN / firewall / remote access gateway)",
        os=["FortiOS 7.0", "PAN-OS 10.2", "Citrix ADC 13", "Cisco IOS XE 17"],
        depts=["Network Operations"], exposure=["internet"], psi=(3, 3), opc=(5, 5), life=0.0,
        downtime=["low"], windows=[("Weekly Thu 01:00-02:00 (HA pair)", (1, 7))],
        vendor_val=0.0, redundancy=0.9, isolate=0.3,
        controls=["mfa", "ips"],
        cves=["CVE-2024-3400", "CVE-2022-40684", "CVE-2024-21762", "CVE-2019-19781", "CVE-2023-20198", "CVE-2023-44487"]),
    "admin_business": dict(
        prefix="ADM", label="Administrative / business system (billing, HR, file transfer, wiki, email)",
        os=["Windows Server 2019", "Ubuntu 20.04", "Windows Server 2016"],
        depts=["Finance", "HR", "Admin IT", "Communications"], exposure=["internal", "dmz", "internet"],
        psi=(1, 2), opc=(2, 3), life=0.0,
        downtime=["high", "medium"], windows=[("Weekly Sat 20:00-23:00", (1, 7))],
        vendor_val=0.0, redundancy=0.4, isolate=0.8,
        controls=["edr", "waf"],
        cves=["CVE-2023-34362", "CVE-2022-26134", "CVE-2021-26855", "CVE-2023-23397", "CVE-2023-44487", "CVE-2016-2183", "CVE-2022-0778", "CVE-2023-48795"]),
}

CATEGORY_SHARE = {  # roughly what a mid-size hospital inventory looks like
    "clinical_workstation": 0.20, "medical_imaging": 0.13, "patient_care_device": 0.13,
    "ehr_clinical_app": 0.12, "lab_pharmacy": 0.10, "identity_infra": 0.08,
    "network_perimeter": 0.08, "admin_business": 0.16,
}


def pick_controls(rng, pool):
    k = rng.randint(0, len(pool))
    return ";".join(sorted(rng.sample(pool, k)))


def make_assets(n, rng):
    assets = []
    counts = {c: max(2, round(n * s)) for c, s in CATEGORY_SHARE.items()}
    i = 0
    for cat, cnt in counts.items():
        spec = CATEGORIES[cat]
        for _ in range(cnt):
            i += 1
            dept = rng.choice(spec["depts"])
            window_name, (lo, hi) = rng.choice(spec["windows"])
            life = rng.random() < spec["life"]
            assets.append({
                "asset_id": f"A-{i:04d}",
                "hostname": f"{spec['prefix']}-{dept[:3].upper()}-{rng.randint(1, 99):02d}",
                "category": cat,
                "description": spec["label"],
                "department": dept,
                "os": rng.choice(spec["os"]),
                "exposure": rng.choice(spec["exposure"]),
                "patient_safety_impact": rng.randint(*spec["psi"]),
                "operational_criticality": rng.randint(*spec["opc"]),
                "life_critical": life,
                "downtime_tolerance": "none" if life else rng.choice(spec["downtime"]),
                "patch_window": window_name,
                "next_window_days": rng.randint(lo, hi),
                "vendor_validation_required": rng.random() < spec["vendor_val"],
                "redundancy": rng.random() < spec["redundancy"],
                "can_isolate": rng.random() < spec["isolate"],
                "controls": pick_controls(rng, spec["controls"]),
                "owner_team": "Clinical Engineering" if cat in ("medical_imaging", "patient_care_device") else
                              "Clinical IT" if cat in ("ehr_clinical_app", "lab_pharmacy", "clinical_workstation") else
                              "IT Infrastructure",
            })
    return assets


def make_vulns(assets, rng, today):
    rows = []
    r = 0
    for a in assets:
        pool = CATEGORIES[a["category"]]["cves"]
        for cve in rng.sample(pool, rng.randint(1, min(4, len(pool)))):
            r += 1
            patch_available = rng.random() < (0.55 if a["category"] == "patient_care_device" else 0.92)
            vendor_validated = (not a["vendor_validation_required"]) or (patch_available and rng.random() < 0.45)
            rows.append({
                "record_id": f"R-{r:04d}",
                "asset_id": a["asset_id"],
                "cve_id": cve,
                "patch_available": patch_available,
                "vendor_validated": bool(vendor_validated and patch_available),
                "detected_date": (today - timedelta(days=rng.randint(1, 60))).isoformat(),
            })
    return rows


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--assets", type=int, default=70)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    known = set(json.loads(CVE_INTEL_JSON.read_text())["cves"])
    for c in CATEGORIES.values():
        missing = set(c["cves"]) - known
        assert not missing, f"CVE(s) missing from cve_intel.json: {missing}"

    assets = make_assets(args.assets, rng)
    vulns = make_vulns(assets, rng, date(2026, 10, 1))
    write_csv(ASSETS_CSV, assets)
    write_csv(VULNS_CSV, vulns)
    print(f"Wrote {len(assets)} assets -> {ASSETS_CSV.name}, {len(vulns)} asset/CVE records -> {VULNS_CSV.name}")


if __name__ == "__main__":
    main()
