# Final Technical Report Outline (aim for 12-18 pages)

1. **Introduction**: the hospital patching problem, why CVSS-only fails, target user, contributions.
2. **Background**: CVSS, CISA KEV, FIRST EPSS, NIST CSF (Identify/Protect/Respond), medical device patching constraints, AI agents and RAG.
3. **Requirements**: functional and non-functional requirements, safety boundaries, acceptance criteria (copy from PROPOSAL.md and the SDLC guide).
4. **Data**: summarize DATA_CARD.md. Include the generator design, category table and intel provenance (snapshot vs refresh date).
5. **System design**: architecture diagram (ARCHITECTURE.md), tool table, why an engine plus an LLM plus a human.
6. **Risk scoring and decision policy**: formula table, tiers, SLAs, decision rules, the patient-safety floor and how evaluation motivated it.
7. **Agent implementation**: prompt, tool-calling loop, guardrails, offline fallback, error handling.
8. **User interface**: one screenshot per tab with a caption.
9. **Evaluation**: paste eval_report.md tables.
   - 9.1 Scenario accuracy
   - 9.2 End-to-end success (offline, scripted, Ollama)
   - 9.3 Guardrail red-team
   - 9.4 Baseline vs CVSS-only
   - 9.5 Sensitivity
   - 9.6 RAG retrieval
   - 9.7 Explanation rubric (human ratings)
   - 9.8 Latency (Monitoring tab)
10. **Security, safety and ethics**: HITL design, least privilege (read-only tools), prompt-injection handling, no real data, model license (Qwen/Llama), limits of AI advice in clinical settings.
11. **Limitations**
12. **Future work**: multi-signature approvals, CMDB/scanner import (e.g., Nessus or OpenVAS CSV), EPSS trend alerts, vendor patch-status tracking, SBOM linkage, MCP server version of the tools.
13. **Team contributions**: one paragraph per student, with the files and features each person owns.

Appendix: setup steps, test list (`pytest -v` output), sample agent JSON outputs.
