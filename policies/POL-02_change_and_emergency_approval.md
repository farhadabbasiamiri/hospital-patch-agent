# POL-02 Change Management and Emergency Approval
Northbridge Regional Hospital (fictional). Synthetic policy for teaching use only.

## §1 Change types
Standard change: pre-approved, low-risk, executed in the asset's normal patch window. Normal change: reviewed by the IT Change Advisory Board (CAB) at its weekly meeting. Emergency change: required when remediation cannot wait for the next patch window; reviewed by the Emergency CAB (ECAB).

## §2 Who approves
Normal patching changes on systems with medium or high downtime tolerance are approved by the IT CAB. Any change on a system with low or no downtime tolerance also requires approval from the Clinical Systems Lead for the affected department. Changes to patient-care devices or medical imaging require sign-off from Clinical Engineering (Biomed).

## §3 Emergency change approval
An emergency change requires ECAB approval and the Chief Information Security Officer (CISO). If the asset is life-critical or supports direct patient care, the on-call Clinical Lead (charge nurse manager or medical director) must also approve and confirm that downtime procedures are in place before work begins.

## §4 Required information in a change request
Each request must state the asset, the vulnerability, the risk score and its components, the proposed action, the planned window, the rollback plan, the clinical downtime procedure that will be used, and the evidence supporting urgency (for example KEV listing or EPSS probability).

## §5 Post-change verification
After patching or isolation, the owner team verifies service health and Clinical Engineering verifies device function before the change is closed. Failed changes are rolled back and reported to ECAB within 24 hours.
