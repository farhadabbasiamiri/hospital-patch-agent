"""MITRE ATT&CK and NIST CSF 2.0 mapping for each finding.

Deterministic lookup from data/framework_mapping.json (the team's analyst mapping). It is
attached outside the LLM, so a model can never invent a technique or control identifier.
"""
import json
from functools import lru_cache

from app.config import FRAMEWORK_JSON


@lru_cache(maxsize=1)
def load_mapping() -> dict:
    return json.loads(FRAMEWORK_JSON.read_text(encoding="utf-8"))


def map_finding(cve_id: str, decision: str, controls: list[str] | None = None) -> dict:
    """ATT&CK techniques for the CVE, mitigations (applied by the decision and already in
    place) and NIST CSF 2.0 subcategories for the decision. Unknown CVEs get no techniques."""
    m = load_mapping()
    cve = m["cves"].get(cve_id, {})
    in_place = sorted({m["control_mitigations"][c] for c in controls or [] if c in m["control_mitigations"]})

    def named(ids):
        return [{"id": i, "name": m["mitigations"][i]} for i in ids]

    return {
        "attack_techniques": [{"id": t, **m["techniques"][t]} for t in cve.get("techniques", [])],
        "attack_rationale": cve.get("rationale", "No ATT&CK mapping for this CVE yet."),
        "mitigations_applied": named(m["decision_mitigations"].get(decision, [])),
        "mitigations_in_place": named(in_place),
        "nist_csf": [{"id": i, "outcome": m["csf"][i]}
                     for i in m["csf_common"] + m["decision_csf"].get(decision, [])],
    }
