# Week-by-Week Build Guide: Group 4B Hospital Patch Prioritization Agent

This guide walks through the project one SDLC stage at a time. It follows the course's 8-week schedule, using Farhad's SDLC guide for the stages and the Group 4B brief for the content. Each week covers:

- **why** that stage exists
- **what** was built and where it lives
- **step-by-step** instructions to reproduce or extend it
- **who** does what
- **how to check** it works
- the **deliverable** to show the instructor
- **questions** you should be able to answer at the demo

> Calendar (Mondays): W1 Oct 5 · W2 Oct 12 · W3 Oct 19 · W4 Oct 26 · W5 Nov 2 · W6 Nov 9 · W7 Nov 16 · W8 Nov 23 · Presentations early December.
> You are in **Week 2** now. The code is complete, so use the remaining weeks to understand it, run it, extend it and own it. Each role has an "extend it" task so every member contributes real code.

---

## Week 1: Planning and Requirements (SDLC stages 1-2)

**Why.** Instructors grade whether you solved *one clear problem* for *one clear user*. A vague scope is the most common reason capstones fail.

**What we decided**
| Question | Answer |
|---|---|
| Problem | Hospitals can't patch immediately. Downtime and vendor validation constraints make CVSS-only ranking unsafe. |
| User | Vulnerability analyst preparing the weekly CAB / Clinical Engineering patch plan |
| Input | One finding (asset + CVE) + optional analyst context |
| Output | PATCH / ISOLATE / MONITOR / DEFER_WITH_CONTROLS + score, evidence, citations, approvers |
| Data | Synthetic inventory + public CVE intel (NVD, KEV, EPSS) + synthetic policies |
| Labels | 12 policy-labeled scenarios + 12 policy questions |
| Safety | Synthetic only, read-only tools, human approval, nothing executed |

**Step by step**
1. Read the 4B brief and underline the required elements: 5-8 asset categories, 100-300 records, NVD/KEV/EPSS enrichment, policy RAG, transparent scoring, human approval, scenario tests.
2. Write the one-page proposal. It's done in `docs/PROPOSAL.md`; edit it with your names.
3. Draw the first architecture sketch (final version in `docs/ARCHITECTURE.md`).
4. Agree the safety boundaries and write them in the README.
5. Create the GitHub repo, add all 5 members, and protect `main` (pull requests only).

**Roles this week**
- S1: owns the proposal and sets up the repo.
- S2: researches CVSS vs KEV vs EPSS (how they differ).
- S3: researches Ollama tool calling and picks a model.
- S4: sketches the UI on paper (6 tabs).
- S5: drafts the acceptance criteria and safety list.

**Deliverable.** Approved proposal + architecture sketch.

**Be ready to answer.** Why not just sort by CVSS? *(It ignores exploitation evidence (KEV/EPSS), exposure, patient impact and downtime limits. Our evaluation shows 14 of the CVSS top-25 would be unsafe to patch immediately.)*

---

## Week 2: System Design + Data Pipeline (SDLC stage 3)

**Why.** The brief's Week 2 is the dataset; the SDLC guide's Week 2 is design. Do both. Good synthetic data is what makes the demo believable.

**What was built**
- `scripts/generate_data.py` creates 70 assets in **8 categories**: clinical workstations, medical imaging, patient-care devices, EHR servers, lab/pharmacy, identity infrastructure, network perimeter and admin systems. It produces ~175 findings, seeded so everyone gets identical data.
- Each category template sets realistic constraints. For example, patient-care devices are life-critical, have no downtime tolerance, need vendor validation, and get quarterly windows.
- `data/cve_intel.json` holds 30 real CVEs matched to plausible platforms (EternalBlue on legacy Windows devices, Log4Shell on EHR Java, Fortinet/PAN-OS/Citrix on the perimeter).
- `scripts/refresh_intel.py` pulls live NVD CVSS, CISA KEV and FIRST EPSS values.
- `app/data_store.py` loads everything. `docs/DATA_CARD.md` documents it.
- `policies/` holds 6 synthetic hospital policies: SLA, change approval, clinical downtime, medical devices, risk acceptance and isolation.

**Step by step**
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python scripts/generate_data.py            # -> data/assets.csv, data/asset_vulns.csv
python scripts/refresh_intel.py            # on your laptop (needs internet), ~4 min due to NVD rate limit
```
Open both CSVs in Excel and sanity-check them. Do life-critical devices have downtime "none"? Are perimeter devices internet-facing?

**Roles**
- S1: runs and explains the generator, finalizes the data card.
- S2: runs `refresh_intel.py` and records the refresh date.
- S3: designs the tool list and JSON output schema.
- S4: builds the UI layout.
- S5: reviews the policies for realism and writes 3 extra policy questions.

**Extend it (S1).** Add a 9th field, `clinical_season_risk` (e.g., flu-season ICU load), or bump to `--assets 100`. Re-run the tests.

**Deliverable.** Dataset + schema + data card + architecture diagram + UI sketch.

**Be ready to answer.** Why synthetic data? *(Course rule: no real hospital data. A seeded generator makes results reproducible, and each realistic constraint is documented.)*

---

## Week 3: Core Components, Scoring + RAG Baseline (SDLC stage 4, part 1)

**Why.** Build and test each tool *before* adding the LLM (SDLC guide §8: "Build and test individual tools before adding LLM orchestration").

**What was built**
- `app/scoring.py` is the transparent 0-100 score: severity (20) + threat KEV/EPSS (25) + exposure (15) + patient safety (25) + operational (15) − controls (cap 12). Every component is returned, so anyone can recompute it by hand.
- `app/decision.py` is the policy engine. It decides PATCH / ISOLATE / MONITOR / DEFER, plus the SLA, change type (standard / normal / emergency) and the exact approvers. It is the **safety authority**.
- `app/rag.py` is the policy RAG. Policies are split per section with citation ids (`POL-04 §2`). TF-IDF works offline, and `RAG_BACKEND=embeddings` switches to BGE-small.
- `app/plan.py` ranks all findings.

**Step by step**
```bash
python -c "from app.plan import build_plan; print(build_plan().head(10).to_string())"
python -c "from app.rag import get_index; print(get_index().search('vendor validation medical device', 3))"
```
Hand-check 3 rows against the formula in `ARCHITECTURE.md`.

**Roles**
- S2: owns scoring + RAG. Tries `RAG_BACKEND=embeddings` and compares hit@3.
- S3: owns the decision engine and walks through every branch on paper.
- S5: writes the first scenario tests (`eval/scenarios.json`), labeling the **expected answer from the policies, not from the code**.

**Extend it (S2).** Add a Chroma or FAISS backend to `rag.py` (the brief lists them), then compare TF-IDF vs embeddings in the report.

**Deliverable.** Working backend components + first evaluation set.

**Be ready to answer.** Why can compensating controls never reduce the score by more than 12? *(Per POL-01 §2, controls must never hide a known-exploited flaw.)*

---

## Week 4: AI Agent Development (SDLC stage 4, part 2)

**Why.** The SDLC guide's definition of an agent: an LLM that **selects and executes tools**, interprets the evidence and responds. A classifier with a UI does not count.

**What was built**
- `app/tools.py` defines 4 read-only tools with JSON schemas. `execute_tool` never crashes: unknown tool, bad arguments and exceptions all come back as `{"error": ...}`, and every call is logged.
- `app/agent.py` contains:
  - **The loop:** system prompt + task → Ollama `/api/chat` with tools → run the tool calls → feed results back → repeat (max 8 steps) → final JSON.
  - **Guardrails (`apply_guardrails`):** decision ∈ engine's `allowed_options`; approval can never be dropped; citations must exist in retrieved text; the engine runs even if the LLM skips it; invalid JSON falls back to the engine plus a template explanation.
  - **Offline planner:** the same tools in a fixed order when Ollama is down, so the demo never dies.
  - **Prompt-injection hygiene:** analyst notes are wrapped as data, capped at 500 chars, and the prompt says tool output is data, not instructions.

**Step by step**
```bash
# install Ollama from https://ollama.com
ollama pull qwen2.5:7b          # 4.7 GB; llama3.1:8b also works (OLLAMA_MODEL=llama3.1:8b)
python -c "from app.agent import run_agent; import json; r=run_agent('R-0064'); print(r['mode'], r['decision'], [t['tool'] for t in r['trace']], r['guardrail_flags'])"
```
Run it 5 times on different records. Note when the LLM calls tools in a different order. That's the "agentic" behavior to show.

**Roles**
- S3: owns the agent and prompt, and tests 2 models.
- S2: makes sure tool outputs are compact (they're truncated at 6,000 chars).
- S5: writes the adversarial fake LLMs (`eval/fake_llms.py`).

**Extend it (S3).** Let the analyst note change the outcome within the allowed options. For example, "vendor patch validated yesterday" should lead the agent to pick an allowed alternative, which the guardrail then flags for CISO review. Or add a 5th tool, `get_vendor_patch_status`.

**Deliverable.** Working agent prototype with structured JSON output.

**Be ready to answer.** What stops the LLM from recommending an unsafe patch? *(The guardrail: the decision must be in the engine's allowed options, and for unvalidated devices PATCH is never allowed. Shown in tests and in the red-team table.)*

---

## Week 5: Gradio Integration (SDLC stage 4, part 3)

**Why.** Farhad's email: the MVP must be presented in **Gradio**, not deployed to the cloud.

**What was built (`app/ui.py`, 6 tabs)**
1. **Patch Plan Dashboard**: KPI cards, filters, ranked table, CSV export, chart.
2. **Agent Investigation**: pick a finding, run the agent, then see the recommendation card, risk breakdown, **tool trace (who chose each tool)**, guardrail flags and raw JSON. Ends with "Submit for human approval".
3. **Approval Queue**: role-checked approve/reject with reviewer name and note, plus audit trail and export (`app/approvals.py`, SQLite).
4. **Policy Q&A (RAG)**: retrieved sections, plus a grounded LLM answer when Ollama is up.
5. **Monitoring**: runs, LLM vs offline, latency, tool errors, guardrail overrides.
6. **About & Safety**.

**Step by step**
```bash
python -m app.ui      # http://localhost:7860
```
Walk the full flow: Dashboard → investigate the #7 device (ISOLATE) → submit → try to approve as "IT CAB" (refused) → approve as "Clinical Engineering".

**Roles**
- S4: owns the UI and approvals.
- S3: helps wire the agent output.
- S5: tests invalid inputs (empty selection, wrong role, double approval).

**Extend it (S4).** Turn the approval into **multi-signature**: the change becomes APPROVED only after *all* required roles sign. Store signatures as JSON in `approvals.db`.

**Deliverable.** End-to-end local MVP.

---

## Week 6: Testing and Evaluation (SDLC stage 5)

**Why.** The brief asks for accuracy, explanation quality, demo success rate, human-in-the-loop behavior and safety.

**What was built**
- `tests/test_core.py` has 26 pytest tests covering data size, scoring math, safety rules (never patch unvalidated devices, isolate no-downtime systems), approval coverage, RAG, tool failures, the agent loop and approvals.
- `eval/run_eval.py` runs 6 evaluations and writes `eval/results/eval_report.md`:

| # | Evaluation | Result |
|---|---|---|
| 1 | 12 policy-labeled scenarios | 100% decision / approval / approver |
| 2 | End-to-end runs, 10 diverse cases | 100% (offline + scripted LLM; run `--llm` for Ollama) |
| 3 | Guardrail red-team: LLM picks a forbidden action, drops approval, invents citations, outputs garbage, skips the engine | 100% safe, 100% flagged |
| 4 | Baseline vs CVSS-only (top 25) | 14/25 CVSS picks unsafe to patch now; never-exploited flaws: 4 vs 0 |
| 5 | Weight sensitivity ±20% | Kendall τ 0.97 → rankings are stable |
| 6 | RAG retrieval | hit@1 83%, hit@3 100% |

- `eval/rubric_template.csv` is for **manual** explanation scoring (clear / evidence-based / actionable / safe, 1-5). Two team members should rate 5 LLM explanations each.

**The story to tell (real, it happened during this build).** The first evaluation run scored scenario S04 wrong. A CVSS 10.0 Ripple20 flaw on a life-critical patient monitor with no patch came out as *Medium*, because EPSS was low and the device was segmented, so it went to the wrong approver. We added a documented **patient-safety floor** (life-critical + CVSS ≥ 9 → at least High) in `scoring.py`. Accuracy went from 92% to 100%. That's exactly what Week 6 is for.

**Step by step**
```bash
pytest -q
python eval/run_eval.py --llm        # with Ollama running
```

**Roles**
- S5 owns all of this.
- Everyone rates explanations.
- S3 fixes any LLM failure modes the `--llm` run reveals (e.g., the model not citing policy).

**Extend it (S5).** Add 5 more scenarios, including a tricky one where you *disagree* with the engine. Report it honestly as a limitation or fix it.

**Deliverable.** Evaluation report.

---

## Week 7: Deployment and Monitoring (SDLC stages 6-7)

**Why.** "Deployed" here means **reproducibly runnable locally**, since there's no cloud per Farhad. Monitoring means you can show what the agent did and how fast.

**What was built**
- `requirements.txt`, `Dockerfile` (Ollama on the host), and the seeded generator. The README quick start runs in under 5 minutes.
- `app/monitoring.py` logs every run, tool call, error, latency and approval to `logs/agent_events.jsonl`, shown in Tab 5. No secrets; free text is capped.
- No API keys in the code. Ollama is local.

**Step by step**
1. Clone the repo fresh into a new folder and follow the README exactly. Fix any step that fails.
2. `docker build -t patch-agent . && docker run -p 7860:7860 patch-agent`
3. Take screenshots of every tab for the README (examples are in `docs/screenshots/`).

**Roles**
- S4: Docker and a fresh-clone test on Windows **and** Mac.
- S5: monitoring review (p95 latency with the LLM).
- S1: README polish.

**Deliverable.** Accessible, reproducible MVP + logs.

---

## Week 8: Improvement and Rehearsal (SDLC stage 8)

**Step by step**
1. Fix critical bugs from Week 6-7. Refine the system prompt if the LLM explanations score below 4 on the rubric.
2. Write the report using `docs/REPORT_TEMPLATE.md`.
3. Rehearse with `docs/DEMO_SCRIPT.md` three times. Time it to 7-10 minutes.
4. Record a **backup video** of the full demo with Ollama running.
5. Write each member's contribution paragraph (required in the submission package).

**Deliverable.** Final MVP, slides, report, backup video.

---

## Early December: Presentation
Problem → data → dashboard → **live agent with tool trace** → human approval → evaluation numbers → the S04 lesson → limitations and future work. Every member must be able to explain the *whole* system, not just their part. The questions at the end of each week above are your Q&A prep.

### Likely instructor questions
- *Is this really an agent?* Yes. The LLM chooses tools; see the "Chosen by: LLM" column. The offline mode is only a fallback.
- *What if the LLM hallucinates?* Guardrails remove invented citations, block out-of-policy actions and keep approvals. That's shown in red-team eval §3.
- *Why should a hospital trust the score?* It's fully transparent and tested for stability (τ 0.97), and a human approves every action.
- *What's missing for production?* Real scanner/CMDB import, multi-signature approval, live intel scheduling, SSO for approvers, and validation with real clinical engineers.
