# POL-03 Clinical Downtime and Patch Windows
Northbridge Regional Hospital (fictional). Synthetic policy for teaching use only.

## §1 Downtime tolerance classes
None: the system supports life-sustaining care and cannot be interrupted without a clinical workaround (for example infusion pump servers and central patient monitoring). Low: interruption delays care (EHR, imaging, laboratory, pharmacy, identity). Medium: interruption is inconvenient and workarounds exist (clinical workstations). High: no direct care impact (billing, HR, wiki).

## §2 Approved patch windows
Each asset has a recorded patch window. Systems with redundancy or failover are patched one node at a time so service continues. Medical imaging and patient-care devices are patched during vendor-supported windows, typically monthly or during quarterly Clinical Engineering visits.

## §3 Patching systems with no downtime tolerance
Systems classed as no downtime tolerance must not be patched outside an approved window unless the Clinical Lead confirms that paper downtime procedures or alternate equipment are in place. If the risk cannot wait for the window, isolate the system first to reduce exposure, then patch in the next approved window.

## §4 Redundant systems
Where an asset has a tested failover partner, patching may proceed in the next window without clinical service interruption, and emergency patching is permitted with ECAB approval.

## §5 Communication
Planned clinical downtime must be announced to affected units at least 24 hours in advance, except for emergency changes approved under POL-02 §3.
