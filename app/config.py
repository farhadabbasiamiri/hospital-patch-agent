"""Central configuration. Every number that drives a decision lives here so it can be
explained in the report and changed in one place."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
POLICY_DIR = ROOT / "policies"
LOG_DIR = ROOT / "logs"

ASSETS_CSV = DATA_DIR / "assets.csv"
VULNS_CSV = DATA_DIR / "asset_vulns.csv"
CVE_INTEL_JSON = DATA_DIR / "cve_intel.json"
APPROVALS_DB = DATA_DIR / "approvals.db"
EVENT_LOG = LOG_DIR / "agent_events.jsonl"

# ---- LLM runtime (local Ollama, no cloud) ---------------------------------
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")  # good tool-calling at 7B
LLM_TIMEOUT_S = int(os.getenv("LLM_TIMEOUT_S", "120"))
AGENT_MAX_STEPS = 8

# ---- Policy RAG ------------------------------------------------------------
# "tfidf" works everywhere with no downloads; "embeddings" uses sentence-transformers.
RAG_BACKEND = os.getenv("RAG_BACKEND", "tfidf")
EMBED_MODEL = os.getenv("EMBED_MODEL", "BAAI/bge-small-en-v1.5")

# ---- Transparent risk score (max 100 before controls) ---------------------
WEIGHTS = {
    "severity_max": 20,        # CVSS base / 10 * 20
    "kev_bonus": 15,           # listed in CISA KEV = known exploited
    "epss_max": 10,            # EPSS probability * 10
    "patient_safety_max": 25,  # patient-safety impact (1-5) / 5 * 25
    "operational_max": 15,     # operational criticality (1-5) / 5 * 15
}
EXPOSURE_POINTS = {"internet": 15, "dmz": 10, "internal": 6, "segmented": 3, "isolated": 0}

# Compensating controls subtract points; capped so controls never hide a KEV exploit.
CONTROL_CREDITS = {
    "segmentation": 4,   # only when not internet-facing
    "edr": 3,
    "allowlisting": 3,
    "ips": 2,
    "waf": 3,            # only when internet/dmz
    "mfa": 2,            # only for identity / perimeter
}
CONTROL_CAP = 12

TIERS = [(78, "Critical"), (62, "High"), (45, "Medium"), (0, "Low")]
SAFETY_FLOOR_CVSS = 9.0  # life-critical asset + CVSS >= this -> tier is at least High

# Remediation SLA in days per tier (policy POL-01 section 3)
SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 90, "Low": 180}
KEV_INTERNET_SLA_DAYS = 3

DECISIONS = ["PATCH", "ISOLATE", "MONITOR", "DEFER_WITH_CONTROLS"]
