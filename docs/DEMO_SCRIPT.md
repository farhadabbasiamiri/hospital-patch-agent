# Demo Script (8-9 minutes, 5 speakers)

**Before you start:** `ollama serve` is running, `ollama pull qwen2.5:7b` is done, and `python -m app.ui` is open in the browser. Check that the banner shows 🟢. Keep `docs/screenshots/` and a recorded backup video open in another tab.

| Time | Speaker | What to show / say |
|---|---|---|
| 0:00-1:00 | Student 1 | **Problem.** "Hospitals can't patch everything right away, because downtime on an infusion server can harm patients." Show the About tab. Name the user: the vulnerability analyst preparing the CAB plan. |
| 1:00-2:00 | Student 1 | **Data.** 70 synthetic assets in 8 categories, ~175 findings, real CVE IDs, KEV/EPSS intel. Mention the data card. |
| 2:00-3:15 | Student 2 | **Dashboard.** KPIs, ranked plan, filter on *patient_care_device*, then the chart. Explain the risk formula using the breakdown table. "CVSS alone would rank 4 never-exploited flaws in the top 25; ours ranks 0." |
| 3:15-5:30 | Student 3 | **Agent live.** Tab 2 → pick the patient-care device with EternalBlue (ISOLATE). Run it and walk the **tool trace** ("the LLM chose these tools"). Then the decision, evidence and citations: POL-04 §2 says no unvalidated patches, POL-06 §3 says who approves isolation. Run a second case: a perimeter VPN with an emergency PATCH. |
| 5:30-6:30 | Student 4 | **Human in the loop.** Submit for approval. In the Approval Queue, try to approve as the "IT CAB" role, which is refused because it's not an authorized approver. Approve as Clinical Engineering with a note. Show the audit trail and export. Show the Policy Q&A tab with one question. |
| 6:30-8:00 | Student 5 | **Evaluation.** Open `eval/results/eval_report.md`: scenario accuracy, red-team (an LLM trying to drop approval gets caught), "14 of the CVSS top-25 would be unsafe to patch now", sensitivity τ 0.97, RAG hit@3. Show the Monitoring tab. Tell the S04 story: evaluation found a safety gap, and the team added the patient-safety floor. |
| 8:00-9:00 | Student 5 | **Limitations and future work.** Synthetic data, single-approver MVP (multi-signature next), snapshot intel, no real CMDB/scanner integration yet. Close with the value: safer, faster, auditable patch planning. |

**If the LLM is slow or fails during the demo:** tick "Force offline planner". The same tools run and the same guardrails apply. Say so openly, because it shows the system degrades gracefully.

**Good findings to pre-select:** the top-ranked perimeter record (emergency PATCH), the first `patient_care_device` with ISOLATE, a DEFER_WITH_CONTROLS record, and a MONITOR record (to show that no approval is needed).
