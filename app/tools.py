"""The four agent tools. Each is a plain Python function plus a JSON schema the LLM sees.

1. get_asset_context        - inventory, exposure, patient impact, patch window, controls
2. get_vulnerability_intel  - NVD CVSS, CISA KEV and FIRST EPSS (local snapshot)
3. search_patch_policy      - policy RAG over hospital change/downtime/medical-device rules
4. compute_risk_and_options - transparent risk score + policy engine decision options

All tools are READ-ONLY. None of them changes any system.
"""
import json

from app.data_store import get_asset, get_cve, get_record
from app.decision import decide
from app.monitoring import log_event, Timer
from app.rag import get_index


def get_asset_context(asset_id: str) -> dict:
    a = get_asset(asset_id)
    if a is None:
        return {"error": f"Unknown asset_id '{asset_id}'."}
    return a


def get_vulnerability_intel(cve_id: str) -> dict:
    c = get_cve(cve_id)
    if c is None:
        return {"error": f"CVE '{cve_id}' not found in local intel snapshot."}
    return c


def search_patch_policy(query: str, k: int = 3) -> dict:
    if not query or not query.strip():
        return {"error": "Empty policy query."}
    hits = get_index().search(query, k=int(k))
    return {"query": query, "results": [
        {"citation": h["chunk_id"], "heading": h["heading"], "text": h["text"], "relevance": h["score"]} for h in hits]}


def compute_risk_and_options(record_id: str) -> dict:
    rec = get_record(record_id)
    if rec is None:
        return {"error": f"Unknown record_id '{record_id}'."}
    asset, cve = get_asset(rec["asset_id"]), get_cve(rec["cve_id"])
    out = decide(asset, rec, cve)
    out["record"] = rec
    return out


TOOL_FUNCS = {
    "get_asset_context": get_asset_context,
    "get_vulnerability_intel": get_vulnerability_intel,
    "search_patch_policy": search_patch_policy,
    "compute_risk_and_options": compute_risk_and_options,
}


def _schema(name, desc, props, required):
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": props, "required": required}}}


TOOL_SCHEMAS = [
    _schema("get_asset_context",
            "Look up a hospital asset: category, department, exposure, patient-safety impact (1-5), "
            "life-critical flag, downtime tolerance, next patch window, vendor validation requirement, controls.",
            {"asset_id": {"type": "string", "description": "e.g. A-0012"}}, ["asset_id"]),
    _schema("get_vulnerability_intel",
            "Get vulnerability intelligence for a CVE: NVD CVSS base score, CISA KEV known-exploited flag, FIRST EPSS probability.",
            {"cve_id": {"type": "string", "description": "e.g. CVE-2019-0708"}}, ["cve_id"]),
    _schema("search_patch_policy",
            "Search the hospital's patching, emergency change, clinical downtime, medical device and isolation policies. "
            "Returns policy sections with citation ids like 'POL-04 §2'.",
            {"query": {"type": "string"}, "k": {"type": "integer", "description": "number of sections, default 3"}}, ["query"]),
    _schema("compute_risk_and_options",
            "Compute the transparent risk score and the policy engine's remediation decision, allowed options, "
            "SLA and required human approvers for an asset/CVE record.",
            {"record_id": {"type": "string", "description": "e.g. R-0042"}}, ["record_id"]),
]


def execute_tool(name: str, args: dict) -> tuple[dict, dict]:
    """Runs a tool safely. Returns (result, trace_entry). Never raises."""
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    fn = TOOL_FUNCS.get(name)
    with Timer() as t:
        if fn is None:
            result = {"error": f"Unknown tool '{name}'."}
        else:
            try:
                result = fn(**(args or {}))
            except TypeError as e:
                result = {"error": f"Bad arguments for {name}: {e}"}
            except Exception as e:  # tool failure must not crash the agent
                result = {"error": f"{name} failed: {type(e).__name__}: {e}"}
    ok = "error" not in result
    log_event("tool_call", tool=name, ok=ok, latency_ms=t.ms)
    return result, {"tool": name, "args": args, "ok": ok, "latency_ms": t.ms, "result": result}
