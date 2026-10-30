# POL-06 Network Isolation Procedure for Clinical Systems
Northbridge Regional Hospital (fictional). Synthetic policy for teaching use only.

## §1 Purpose
Isolation reduces exposure of a vulnerable or suspected-compromised system while preserving patient care where possible.

## §2 Isolation options
Partial isolation restricts the asset to only the flows it needs for clinical function (for example a modality may still send images to PACS). Full isolation disconnects the asset from the network. Partial isolation is preferred for clinical systems.

## §3 Approval to isolate
Isolating a clinical, imaging or patient-care system requires approval from the CISO and Clinical Engineering, plus the Clinical Lead of the affected unit, who confirms the downtime or workaround procedure. Isolating a non-clinical system requires the owner team manager and Security Operations.

## §4 Execution and rollback
Network Operations executes the isolation change. A rollback contact and the expected impact on clinical workflow must be recorded. Isolation is reviewed every 7 days until the vulnerability is remediated.

## §5 Assets that cannot be isolated
If an asset cannot be isolated without unacceptable patient-care impact, the finding must follow POL-05 with heightened monitoring and executive notification.
