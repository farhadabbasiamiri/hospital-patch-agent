# Project Proposal: Group 4B Healthcare / Critical Systems Patch Prioritization Agent
*(Week 1 deliverable, one page)*

**Authors.** [@luishsantos100](https://github.com/luishsantos100), [@pandyasaniya710](https://github.com/pandyasaniya710), [@Akashpatel2509](https://github.com/Akashpatel2509), [@RenishPatell](https://github.com/RenishPatell)

**Problem.** Hospitals carry hundreds of open vulnerabilities but can't patch them all right away. Downtime on imaging, infusion or EHR systems can delay care, and regulated medical devices can only take vendor-validated patches. Ranking by CVSS alone ignores whether a flaw is being exploited, how exposed the system is, and what patching would do to patients.

**Target user.** A hospital vulnerability-management / security analyst who prepares the weekly patch plan for the Change Advisory Board and Clinical Engineering.

**MVP goal.** A local Gradio app that ranks every asset/CVE finding for a synthetic hospital. An AI agent recommends **PATCH, ISOLATE, MONITOR or DEFER-WITH-CONTROLS** for each finding, explains why with evidence and policy citations, and routes it to the right human approvers.

**Inputs and outputs.**
- Input: a finding (asset + CVE) and optional analyst context.
- Output: decision, risk score with its components, due date, change type, evidence, compensating controls, policy citations, required approvers, confidence and uncertainty.

**Data.**
- Synthetic inventory: 70 assets in 8 categories and about 175 findings, from a seeded generator.
- Public vulnerability intel: NVD CVSS, CISA KEV, FIRST EPSS.
- Six synthetic hospital policies, used as the RAG corpus.

**Labels.** 12 scenario test cases labeled from the policies (expected decision, approval and approver), plus 12 policy questions with expected citations.

**Architecture.** Gradio → agent (Ollama LLM, tool calling) → 4 tools (asset context, vulnerability intel, policy RAG, risk + policy engine) → guardrails → approval queue. See `ARCHITECTURE.md`.

**Acceptance criteria.**
1. All findings ranked with a transparent score.
2. The agent visibly selects tools.
3. 100% of non-MONITOR recommendations require approval.
4. Scenario decision accuracy ≥ 90%.
5. Guardrails block 100% of adversarial outputs.
6. Five or more end-to-end demo cases run reliably.

**Safety boundaries.** Synthetic data only. No scanning, no real systems, no malware, no automatic changes. Humans approve every action.

**Team roles.**
1. Data/Project Lead
2. AI/RAG Lead
3. Agent Lead
4. App Lead
5. Evaluation/Security Lead
