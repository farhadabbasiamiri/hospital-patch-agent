# Data Card

## Summary
| Item | Value |
|---|---|
| Organization | Northbridge Regional Hospital (fictional) |
| Assets | 70 (seed 42), 8 categories |
| Asset/CVE findings | ~175 (brief requires 100-300) |
| CVEs | 30 real, public CVE IDs |
| Generator | `scripts/generate_data.py --assets 70 --seed 42` (deterministic) |
| Personal data | None. No patients, employees or real hospitals. |

## Files
**`data/assets.csv`**: one row per asset

| Field | Meaning |
|---|---|
| asset_id, hostname, department, os, owner_team | identity (fictional) |
| category | clinical_workstation, medical_imaging, patient_care_device, ehr_clinical_app, lab_pharmacy, identity_infra, network_perimeter, admin_business |
| exposure | internet, dmz, internal, segmented, isolated |
| patient_safety_impact | 1-5, harm to patients if the system fails or is compromised |
| operational_criticality | 1-5, impact on hospital operations |
| life_critical | supports life-sustaining care |
| downtime_tolerance | none, low, medium, high (POL-03 §1) |
| patch_window, next_window_days | recorded window and days until the next one |
| vendor_validation_required | regulated medical device; manufacturer must validate patches (POL-04 §2) |
| redundancy | tested failover exists |
| can_isolate | can be segmented without unacceptable care impact |
| controls | semicolon list: edr, segmentation, allowlisting, ips, waf, mfa |

**`data/asset_vulns.csv`**: one row per finding: `record_id, asset_id, cve_id, patch_available, vendor_validated, detected_date`

**`data/cve_intel.json`**: per CVE: `title, product, cvss, kev, epss` (+ `kev_date_added`, `epss_percentile` after a refresh)

## How realism was built in
- Each category has realistic ranges. For example, patient-care devices are life-critical, have no downtime tolerance, need vendor validation, get quarterly patch windows, and have only a 55% chance that a patch exists.
- CVEs are matched to plausible platforms: EternalBlue and BlueKeep on legacy Windows imaging and devices, URGENT/11 and Ripple20 on embedded devices, Log4Shell and Spring4Shell on EHR Java servers, Fortinet, PAN-OS and Citrix on the perimeter, MOVEit, Exchange and Confluence on admin systems.
- The category mix roughly matches a mid-size hospital: 20% workstations, 13% imaging, 13% devices, and so on.

## Intel provenance and limits
The shipped `cve_intel.json` is an **approximate offline snapshot** (`_meta.source = offline_snapshot`). Run `scripts/refresh_intel.py` to replace it with live NVD, CISA KEV and FIRST EPSS values, then re-run the evaluation. EPSS changes daily, so record the refresh date in your report.

## Known limitations
- Asset attributes are synthetic and correlated by design (category templates), so real inventories will be messier.
- One CVE per finding. Real scanners report many findings per host plus duplicates.
- The policies are written for this project. They follow common hospital practice but are not any real institution's rules.
