"""Gradio web interface: Patch Plan Dashboard, Agent Investigation, Approval Queue,
Policy Q&A, Monitoring, About & Safety.   Run:  python -m app.ui"""
import json
from datetime import datetime

import gradio as gr
import pandas as pd

from app import approvals
from app.agent import OllamaLLM, run_agent, answer_policy_question
from app.config import OLLAMA_MODEL, LOG_DIR
from app.data_store import load_intel
from app.monitoring import summary, read_events
from app.plan import build_plan

PLAN = build_plan()
DECISION_ICON = {"PATCH": "🩹", "ISOLATE": "🧱", "MONITOR": "👁️", "DEFER_WITH_CONTROLS": "⏸️"}
REVIEWER_ROLES = ["CISO", "Emergency CAB (ECAB)", "IT Change Advisory Board (CAB)", "Clinical Engineering",
                  "Clinical Lead", "Clinical Systems Lead", "Asset clinical/business owner",
                  "Owner team manager", "Security Operations"]

CSS = """
.kpi {border:1px solid var(--border-color-primary); border-radius:10px; padding:12px 14px; text-align:center}
.kpi b {font-size:1.6em; display:block}
.banner {padding:8px 12px; border-radius:8px; background:var(--background-fill-secondary); font-size:0.9em}
"""


def llm_status() -> str:
    up = OllamaLLM().available()
    intel = load_intel()["_meta"]["source"]
    llm = f"🟢 LLM agent: Ollama `{OLLAMA_MODEL}` connected" if up else \
        f"🟠 LLM agent: Ollama `{OLLAMA_MODEL}` not reachable, so runs use the offline planner (same tools, template text)"
    src = "🟢 live refresh" if intel == "live_refresh" else "🟠 offline snapshot (run scripts/refresh_intel.py)"
    return f"<div class='banner'>{llm} &nbsp;|&nbsp; Vulnerability intel: {src} &nbsp;|&nbsp; " \
           f"Synthetic data only. The agent recommends; humans approve. Nothing is executed.</div>"


# ------------------------------------------------------------------ dashboard
def kpis(df: pd.DataFrame) -> str:
    pending = len(approvals.list_approvals("PENDING"))
    cards = [("Asset/CVE findings", len(df)), ("Critical", int((df.tier == "Critical").sum())),
             ("KEV-listed", int(df.kev.sum())), ("Emergency changes", int((df.change_type == "emergency").sum())),
             ("Life-critical deferrals/isolations", int(df[df.category == "patient_care_device"].decision
                                                         .isin(["ISOLATE", "DEFER_WITH_CONTROLS"]).sum())),
             ("Pending approvals", pending)]
    cells = "".join(f"<div class='kpi'><b>{v}</b>{k}</div>" for k, v in cards)
    return f"<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px'>{cells}</div>"


def filter_plan(categories, tiers, decisions):
    df = PLAN
    if categories:
        df = df[df.category.isin(categories)]
    if tiers:
        df = df[df.tier.isin(tiers)]
    if decisions:
        df = df[df.decision.isin(decisions)]
    show = df[["rank", "record_id", "hostname", "category", "department", "cve_id", "cvss", "kev", "epss",
               "exposure", "patient_impact", "risk_score", "tier", "decision", "change_type", "due_in_days",
               "approvers"]]
    return kpis(df), show


def export_plan(categories, tiers, decisions):
    _, df = filter_plan(categories, tiers, decisions)
    LOG_DIR.mkdir(exist_ok=True)
    path = LOG_DIR / f"patch_plan_{datetime.now():%Y%m%d_%H%M%S}.csv"
    df.to_csv(path, index=False)
    return str(path)


def tier_chart_df():
    return PLAN.groupby(["category", "decision"]).size().reset_index(name="findings")


# ------------------------------------------------------------------ agent tab
def record_choices():
    return [(f"#{r.rank} · {r.record_id} · {r.hostname} · {r.cve_id} · {r.risk_score} {r.tier}", r.record_id)
            for r in PLAN.itertuples()]


def render_recommendation(rec: dict) -> str:
    if "error" in rec:
        return f"❌ {rec['error']}"
    status = "⏳ **Pending human approval**" if rec["approval_required"] else "ℹ️ Informational (no approval needed)"
    lines = [
        f"## {DECISION_ICON.get(rec['decision'], '')} {rec['decision'].replace('_', ' ')}  ·  {rec['hostname']}  ·  {rec['cve_id']}",
        f"**Risk {rec['risk_score']} ({rec['tier']})** · change type: `{rec['change_type']}` · "
        f"due within **{rec['due_in_days']} days** · {status}", "",
        f"**Required approvers:** {', '.join(rec['approvers'])}",
        "", f"> {rec['summary']}", "", "**Evidence**", *[f"- {e}" for e in rec["evidence"]],
        "", "**Compensating controls**", *[f"- {c}" for c in rec["compensating_controls"]],
        "", f"**Policy citations:** {', '.join(rec['policy_citations'])}", "",
        f"**Confidence:** {rec['confidence']} · **Uncertainty:** {rec['uncertainty'] or 'none stated'}", "",
        f"<sub>Mode: {rec['mode']} · model: {rec['model']} · engine default: {rec['engine_decision']} · "
        f"allowed: {', '.join(rec['allowed_options'])} · {rec['latency_ms']} ms</sub>",
    ]
    return "\n".join(lines)


def render_trace(rec: dict) -> str:
    if "error" in rec:
        return ""
    out = ["| # | Tool | Chosen by | Args | OK | ms |", "|---|---|---|---|---|---|"]
    for i, t in enumerate(rec["trace"], 1):
        out.append(f"| {i} | `{t['tool']}` | {t['chosen_by']} | `{json.dumps(t['args'])}` | "
                   f"{'✅' if t['ok'] else '❌'} | {t['latency_ms']} |")
    flags = rec["guardrail_flags"]
    out += ["", "**Guardrail flags:** " + ("none ✅" if not flags else ""), *[f"- ⚠️ {f}" for f in flags]]
    return "\n".join(out)


def investigate(record_id, note, force_offline):
    if not record_id:
        return "Pick a finding first.", "", None, {}, None
    rec = run_agent(record_id, analyst_note=note, force_offline=force_offline)
    comp = pd.DataFrame([{"component": k, "points": v} for k, v in rec.get("risk_components", {}).items()])
    raw = {k: v for k, v in rec.items() if k != "trace"}
    raw["trace"] = [{k: v for k, v in t.items() if k != "result"} for t in rec.get("trace", [])]
    return render_recommendation(rec), render_trace(rec), comp, raw, rec


def submit_for_approval(rec):
    if not rec or "error" in rec:
        return "Run an investigation first."
    if not rec["approval_required"]:
        return "ℹ️ MONITOR needs no approval. The finding is tracked for routine maintenance."
    aid = approvals.submit(rec)
    return f"✅ Submitted as approval **#{aid}**. Open the Approval Queue tab. Required: {', '.join(rec['approvers'])}."


# ------------------------------------------------------------------ approvals tab
def queue_tables():
    return approvals.list_approvals("PENDING"), approvals.list_approvals()


def decide_approval(approval_id, reviewer, role, note, approve: bool):
    try:
        if approval_id is None:
            raise ValueError("Enter the approval id from the pending table.")
        pend = approvals.list_approvals("PENDING")
        row = pend[pend.id == int(approval_id)]
        if not row.empty and role and role.split(" (")[0] not in row.iloc[0].required_approvers:
            raise ValueError(f"Role '{role}' is not an authorized approver for this change "
                             f"(required: {row.iloc[0].required_approvers}).")
        status = approvals.review(int(approval_id), approve, reviewer, role, note)
        msg = f"✅ Approval #{int(approval_id)} → **{status}** by {reviewer} ({role})."
    except ValueError as e:
        msg = f"❌ {e}"
    p, h = queue_tables()
    return msg, p, h


def export_approved():
    df = approvals.list_approvals("APPROVED")
    LOG_DIR.mkdir(exist_ok=True)
    path = LOG_DIR / f"approved_change_plan_{datetime.now():%Y%m%d_%H%M%S}.csv"
    df.to_csv(path, index=False)
    return str(path)


# ------------------------------------------------------------------ policy + monitoring
def policy_qa(q):
    if not q or not q.strip():
        return "Type a question.", None
    res = answer_policy_question(q)
    hits = pd.DataFrame([{"citation": h["chunk_id"], "section": h["heading"], "relevance": h["score"],
                          "text": h["text"][:300]} for h in res["hits"]])
    return f"{res['answer']}\n\n<sub>mode: {res['mode']}</sub>", hits


def monitoring_view():
    s = summary()
    md = "\n".join(f"- **{k.replace('_', ' ')}**: {v}" for k, v in s.items())
    ev = pd.DataFrame(read_events(50)[::-1])
    return md, ev


AUTHORS = ("[@luishsantos100](https://github.com/luishsantos100), "
            "[@pandyasaniya710](https://github.com/pandyasaniya710), "
            "[@Akashpatel2509](https://github.com/Akashpatel2509), "
            "[@RenishPatell](https://github.com/RenishPatell), "
            "[@helikapatel89](https://github.com/helikapatel89)")

ABOUT = f"""
### Healthcare / Critical Systems Patch Prioritization Agent (Group 4B)
**Authors.** {AUTHORS}

**Problem.** Hospitals cannot patch everything immediately: downtime on imaging, infusion or EHR systems can harm
patients. Ranking by CVSS alone ignores exploitation evidence, patient-safety impact and downtime constraints.

**What this MVP does.** Ranks every asset/CVE finding for a *synthetic* hospital with a transparent risk score
(CVSS + KEV + EPSS + exposure + patient safety + operations − compensating controls), and recommends
**PATCH / ISOLATE / MONITOR / DEFER-WITH-CONTROLS**, citing the hospital's change, downtime and medical-device policies.

**How the agent works.** A local LLM (Ollama) chooses among 4 read-only tools, reads the evidence, and drafts a JSON
recommendation. Guardrails then enforce that the decision is within the policy engine's allowed options, citations exist,
and the approval requirement is never lowered. A named human approves or rejects in the Approval Queue.

**Safety boundaries.** Synthetic data only, no scanning, no real systems, no automatic changes, no live malware.
Vulnerability metadata is public (NVD, CISA KEV, FIRST EPSS).
"""


def build_app() -> gr.Blocks:
    with gr.Blocks(title="Hospital Patch Prioritization Agent") as demo:
        gr.Markdown("# 🏥 Hospital Patch Prioritization Agent\nNorthbridge Regional Hospital *(fictional)* · Group 4B MVP\n\n"
                    f"**Authors:** {AUTHORS}")
        status = gr.HTML(llm_status())

        with gr.Tab("1 · Patch Plan Dashboard"):
            with gr.Row():
                f_cat = gr.Dropdown(sorted(PLAN.category.unique()), multiselect=True, label="Category")
                f_tier = gr.Dropdown(["Critical", "High", "Medium", "Low"], multiselect=True, label="Tier")
                f_dec = gr.Dropdown(list(DECISION_ICON), multiselect=True, label="Decision")
            kpi_html = gr.HTML()
            plan_tbl = gr.Dataframe(interactive=False, wrap=True, max_height=480, label="Ranked remediation plan")
            with gr.Row():
                export_btn = gr.Button("⬇️ Export filtered plan (CSV)")
                export_file = gr.File(label="Download", interactive=False)
            gr.BarPlot(tier_chart_df(), x="category", y="findings", color="decision",
                       title="Recommended action by asset category", x_label_angle=-30)
            for comp in (f_cat, f_tier, f_dec):
                comp.change(filter_plan, [f_cat, f_tier, f_dec], [kpi_html, plan_tbl])
            export_btn.click(export_plan, [f_cat, f_tier, f_dec], export_file)
            demo.load(filter_plan, [f_cat, f_tier, f_dec], [kpi_html, plan_tbl])

        with gr.Tab("2 · Agent Investigation"):
            gr.Markdown("Pick a finding. The agent chooses tools, gathers evidence, and drafts a recommendation. "
                        "The **tool trace** shows every call so reviewers can verify the workflow.")
            with gr.Row():
                rec_dd = gr.Dropdown(record_choices(), label="Finding (ranked)", scale=3)
                offline = gr.Checkbox(label="Force offline planner (no LLM)", value=False, scale=1)
            note = gr.Textbox(label="Analyst context (optional)", lines=2, max_length=500,
                              placeholder="e.g. Vendor says a validated patch ships next month; ICU census is high this week.")
            run_btn = gr.Button("🔎 Run agent investigation", variant="primary")
            with gr.Row():
                with gr.Column(scale=3):
                    rec_md = gr.Markdown()
                with gr.Column(scale=2):
                    comp_tbl = gr.Dataframe(label="Risk score breakdown", interactive=False)
            trace_md = gr.Markdown(label="Tool trace")
            with gr.Accordion("Raw agent output (JSON)", open=False):
                raw_json = gr.JSON()
            rec_state = gr.State()
            submit_btn = gr.Button("📨 Submit recommendation for human approval")
            submit_msg = gr.Markdown()
            run_btn.click(investigate, [rec_dd, note, offline], [rec_md, trace_md, comp_tbl, raw_json, rec_state],
                          show_progress="full")
            submit_btn.click(submit_for_approval, rec_state, submit_msg)

        with gr.Tab("3 · Approval Queue"):
            gr.Markdown("**Human-in-the-loop checkpoint.** Only an authorized role from the required-approver list can "
                        "approve. Approval records the decision in the change plan. Nothing is executed.")
            pend_tbl = gr.Dataframe(label="Pending", interactive=False)
            with gr.Row():
                a_id = gr.Number(label="Approval id", precision=0)
                a_name = gr.Textbox(label="Reviewer name")
                a_role = gr.Dropdown(REVIEWER_ROLES, label="Reviewer role")
            a_note = gr.Textbox(label="Review note (rollback plan, downtime procedure, conditions)", lines=2)
            with gr.Row():
                ok_btn = gr.Button("✅ Approve", variant="primary")
                no_btn = gr.Button("❌ Reject", variant="stop")
                refresh_q = gr.Button("🔄 Refresh")
            a_msg = gr.Markdown()
            hist_tbl = gr.Dataframe(label="All decisions (audit trail)", interactive=False)
            with gr.Row():
                exp_ap = gr.Button("⬇️ Export approved change plan")
                exp_ap_file = gr.File(interactive=False)
            ok_btn.click(lambda *a: decide_approval(*a, approve=True), [a_id, a_name, a_role, a_note],
                         [a_msg, pend_tbl, hist_tbl])
            no_btn.click(lambda *a: decide_approval(*a, approve=False), [a_id, a_name, a_role, a_note],
                         [a_msg, pend_tbl, hist_tbl])
            refresh_q.click(queue_tables, None, [pend_tbl, hist_tbl])
            exp_ap.click(export_approved, None, exp_ap_file)
            demo.load(queue_tables, None, [pend_tbl, hist_tbl])

        with gr.Tab("4 · Policy Q&A (RAG)"):
            q = gr.Textbox(label="Ask about hospital patching policy",
                           placeholder="Can we patch an infusion pump server outside its window?")
            gr.Examples(["Who must approve an emergency change on a life-critical system?",
                         "Can we install an OS update on a CT scanner that the vendor has not validated?",
                         "How long can a critical vulnerability be deferred?",
                         "What is the deadline for a KEV vulnerability on an internet-facing VPN?"], q)
            ask = gr.Button("Ask", variant="primary")
            ans = gr.Markdown()
            hits_tbl = gr.Dataframe(label="Retrieved policy sections", interactive=False, wrap=True)
            ask.click(policy_qa, q, [ans, hits_tbl])

        with gr.Tab("5 · Monitoring"):
            mon_md = gr.Markdown()
            mon_tbl = gr.Dataframe(label="Recent events (logs/agent_events.jsonl)", interactive=False, wrap=True)
            mon_btn = gr.Button("🔄 Refresh")
            mon_btn.click(monitoring_view, None, [mon_md, mon_tbl])
            mon_btn.click(llm_status, None, status)
            demo.load(monitoring_view, None, [mon_md, mon_tbl])

        with gr.Tab("6 · About & Safety"):
            gr.Markdown(ABOUT)
    return demo


if __name__ == "__main__":
    build_app().launch(server_name="0.0.0.0", server_port=7860, css=CSS, theme=gr.themes.Soft())
