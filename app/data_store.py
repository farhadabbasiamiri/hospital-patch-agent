"""Loads the synthetic inventory, asset/CVE records and the vulnerability intel snapshot."""
import json
from functools import lru_cache

import pandas as pd

from app.config import ASSETS_CSV, VULNS_CSV, CVE_INTEL_JSON

BOOL_COLS_ASSETS = ["life_critical", "vendor_validation_required", "redundancy", "can_isolate"]
BOOL_COLS_VULNS = ["patch_available", "vendor_validated"]


def _to_bool(s):
    return s.astype(str).str.lower().isin(["true", "1", "yes"])


@lru_cache(maxsize=1)
def load_assets() -> pd.DataFrame:
    df = pd.read_csv(ASSETS_CSV, keep_default_na=False)
    for c in BOOL_COLS_ASSETS:
        df[c] = _to_bool(df[c])
    return df


@lru_cache(maxsize=1)
def load_vulns() -> pd.DataFrame:
    df = pd.read_csv(VULNS_CSV, keep_default_na=False)
    for c in BOOL_COLS_VULNS:
        df[c] = _to_bool(df[c])
    return df


@lru_cache(maxsize=1)
def load_intel() -> dict:
    return json.loads(CVE_INTEL_JSON.read_text())


def get_asset(asset_id: str) -> dict | None:
    df = load_assets()
    row = df[df.asset_id == asset_id]
    if row.empty:
        return None
    a = row.iloc[0].to_dict()
    a["controls"] = [c for c in str(a["controls"]).split(";") if c]
    return a


def get_record(record_id: str) -> dict | None:
    df = load_vulns()
    row = df[df.record_id == record_id]
    return None if row.empty else row.iloc[0].to_dict()


def get_cve(cve_id: str) -> dict | None:
    rec = load_intel()["cves"].get(cve_id.strip().upper())
    if rec is None:
        return None
    return {"cve_id": cve_id.strip().upper(), **rec, "intel_source": load_intel()["_meta"]["source"]}
