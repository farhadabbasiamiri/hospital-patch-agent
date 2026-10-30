"""Refresh data/cve_intel.json with LIVE values from public sources.

Run on a machine with internet access (your laptop):  python scripts/refresh_intel.py
  - NVD CVE API 2.0       -> CVSS v3.x base score
  - CISA KEV JSON feed    -> known-exploited flag + date added
  - FIRST EPSS API        -> exploitation probability + percentile
Optional: set NVD_API_KEY env var for higher NVD rate limits (never commit the key).
Only public vulnerability metadata is fetched; no scanning of any system happens.
"""
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.config import CVE_INTEL_JSON  # noqa: E402

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"


def nvd_cvss(cve_id, headers):
    r = requests.get(NVD, params={"cveId": cve_id}, headers=headers, timeout=30)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        return None
    metrics = vulns[0]["cve"].get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            primary = [m for m in metrics[key] if m.get("type") == "Primary"] or metrics[key]
            return primary[0]["cvssData"]["baseScore"]
    return None


def main():
    data = json.loads(CVE_INTEL_JSON.read_text())
    ids = list(data["cves"])
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {}

    print("Fetching CISA KEV catalog...")
    kev = {v["cveID"]: v for v in requests.get(KEV, timeout=60).json()["vulnerabilities"]}

    print("Fetching EPSS scores...")
    epss = {}
    for i in range(0, len(ids), 50):
        r = requests.get(EPSS, params={"cve": ",".join(ids[i:i + 50])}, timeout=30)
        for row in r.json().get("data", []):
            epss[row["cve"]] = (float(row["epss"]), float(row["percentile"]))

    print("Fetching NVD CVSS (rate limited)...")
    for cve_id in ids:
        rec = data["cves"][cve_id]
        try:
            score = nvd_cvss(cve_id, headers)
            if score is not None:
                rec["cvss"] = score
        except requests.RequestException as e:
            print(f"  NVD failed for {cve_id}: {e} (kept snapshot value)")
        rec["kev"] = cve_id in kev
        rec["kev_date_added"] = kev[cve_id]["dateAdded"] if cve_id in kev else None
        if cve_id in epss:
            rec["epss"], rec["epss_percentile"] = epss[cve_id]
        time.sleep(0.7 if headers else 6.5)  # NVD public limit: 5 requests / 30 s
        print(f"  {cve_id}: cvss={rec['cvss']} kev={rec['kev']} epss={rec.get('epss')}")

    data["_meta"]["source"] = "live_refresh"
    data["_meta"]["refreshed_at"] = datetime.now(timezone.utc).isoformat()
    CVE_INTEL_JSON.write_text(json.dumps(data, indent=2))
    print(f"Updated {CVE_INTEL_JSON}")


if __name__ == "__main__":
    main()
