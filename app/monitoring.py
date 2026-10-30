"""Lightweight monitoring: every agent run, tool call, error and approval is appended to a
JSONL event log. No secrets or free-text analyst notes beyond 200 chars are stored."""
import json
import time
from datetime import datetime, timezone

from app.config import EVENT_LOG


def log_event(event: str, **fields):
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": event}
    for k, v in fields.items():
        rec[k] = v[:200] if isinstance(v, str) else v
    with open(EVENT_LOG, "a") as f:
        f.write(json.dumps(rec, default=str) + "\n")


def read_events(limit: int | None = None) -> list[dict]:
    if not EVENT_LOG.exists():
        return []
    lines = EVENT_LOG.read_text().splitlines()
    if limit:
        lines = lines[-limit:]
    return [json.loads(l) for l in lines if l.strip()]


def summary() -> dict:
    ev = read_events()
    runs = [e for e in ev if e["event"] == "agent_run"]
    tools = [e for e in ev if e["event"] == "tool_call"]
    lat = [e["latency_ms"] for e in runs if "latency_ms" in e]
    return {
        "agent_runs": len(runs),
        "llm_runs": sum(1 for e in runs if e.get("mode") == "llm"),
        "offline_runs": sum(1 for e in runs if e.get("mode") == "offline"),
        "avg_latency_ms": round(sum(lat) / len(lat)) if lat else 0,
        "p95_latency_ms": sorted(lat)[int(0.95 * (len(lat) - 1))] if lat else 0,
        "tool_calls": len(tools),
        "tool_errors": sum(1 for e in tools if not e.get("ok", True)),
        "guardrail_overrides": sum(len(e.get("guardrail_flags", [])) for e in runs),
        "approvals_submitted": sum(1 for e in ev if e["event"] == "approval_submitted"),
        "approvals_decided": sum(1 for e in ev if e["event"] == "approval_decided"),
    }


class Timer:
    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *a):
        self.ms = round((time.perf_counter() - self.t0) * 1000)
