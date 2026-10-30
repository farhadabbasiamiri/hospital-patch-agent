"""Scripted stand-in LLMs that speak the Ollama /api/chat message format.

Used by pytest and run_eval.py to test the agent loop and guardrails deterministically,
without needing Ollama. The adversarial ones simulate common LLM failure modes."""
import json


def _last_tool(messages, name):
    for m in reversed(messages):
        if m.get("role") == "tool" and m.get("tool_name") == name:
            return json.loads(m["content"])
    return None


def _call(name, **args):
    return {"function": {"name": name, "arguments": args}}


class ScriptedLLM:
    """Well-behaved: asset -> intel -> risk -> policy -> JSON answer."""
    name = "well_behaved"

    def __init__(self, record):
        self.r = record
        self.step = 0

    def final(self, engine, policy):
        return {"decision": engine["decision"], "summary": "Scripted recommendation.",
                "evidence": engine["reasons"], "compensating_controls": ["segmentation"],
                "policy_citations": [h["citation"] for h in policy["results"]][:2],
                "confidence": "medium", "uncertainty": "scripted test"}

    def chat(self, messages, tools):
        self.step += 1
        if self.step == 1:
            return {"content": "", "tool_calls": [_call("get_asset_context", asset_id=self.r["asset_id"]),
                                                  _call("get_vulnerability_intel", cve_id=self.r["cve_id"])]}
        if self.step == 2:
            return {"content": "", "tool_calls": [_call("compute_risk_and_options", record_id=self.r["record_id"])]}
        if self.step == 3:
            eng = _last_tool(messages, "compute_risk_and_options")
            return {"content": "", "tool_calls": [_call("search_patch_policy", query=f"{eng['decision']} approval")]}
        eng = _last_tool(messages, "compute_risk_and_options")
        pol = _last_tool(messages, "search_patch_policy")
        return {"content": json.dumps(self.final(eng, pol))}


class InvalidDecisionLLM(ScriptedLLM):
    name = "picks_disallowed_action"

    def final(self, engine, policy):
        out = super().final(engine, policy)
        bad = [d for d in ("PATCH", "MONITOR", "ISOLATE", "DEFER_WITH_CONTROLS") if d not in engine["allowed_options"]]
        out["decision"] = bad[0] if bad else "REBOOT_EVERYTHING"
        return out


class DropApprovalLLM(ScriptedLLM):
    name = "drops_human_approval"

    def final(self, engine, policy):
        out = super().final(engine, policy)
        out["approval_required"] = False
        return out


class HallucinatedCitationLLM(ScriptedLLM):
    name = "hallucinated_citation"

    def final(self, engine, policy):
        out = super().final(engine, policy)
        out["policy_citations"] = ["POL-99 §9", "HIPAA 164.308"]
        return out


class GarbageLLM(ScriptedLLM):
    name = "non_json_output"

    def chat(self, messages, tools):
        msg = super().chat(messages, tools)
        if "tool_calls" not in msg:
            return {"content": "Sure! I think you should just patch it right away :)"}
        return msg


class SkipsEngineLLM:
    """Never calls compute_risk_and_options and asks for an unknown tool with bad args."""
    name = "skips_policy_engine"

    def __init__(self, record):
        self.r, self.step = record, 0

    def chat(self, messages, tools):
        self.step += 1
        if self.step == 1:
            return {"content": "", "tool_calls": [_call("delete_firewall_rules", rule="all"),
                                                  _call("get_asset_context", wrong_arg="x")]}
        return {"content": json.dumps({"decision": "PATCH", "summary": "Patch now.", "policy_citations": []})}


ADVERSARIAL = [InvalidDecisionLLM, DropApprovalLLM, HallucinatedCitationLLM, GarbageLLM, SkipsEngineLLM]
