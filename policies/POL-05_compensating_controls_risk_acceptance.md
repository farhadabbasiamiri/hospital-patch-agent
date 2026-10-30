# POL-05 Compensating Controls and Risk Acceptance
Northbridge Regional Hospital (fictional). Synthetic policy for teaching use only.

## §1 When deferral is allowed
Remediation may be deferred only when patching is not possible within the SLA, for example because no validated patch exists, the next safe window is beyond the SLA, or patching would interrupt patient care without an acceptable workaround.

## §2 Required compensating controls
A deferred finding must have at least two active compensating controls appropriate to the threat, chosen from: network segmentation or access control lists, endpoint detection and response (EDR), application allowlisting, intrusion prevention or detection (IPS/IDS) signatures for the vulnerability, web application firewall rules, multi-factor authentication for administrative access, and disabling the vulnerable service or protocol.

## §3 Risk acceptance approval
Deferral of a Critical or High finding requires written risk acceptance from the CISO and the business or clinical owner of the asset. Deferral of a Medium finding requires the owner team manager.

## §4 Maximum deferral period
Risk acceptance expires after 90 days for Critical and High findings and 180 days for Medium findings. It must be re-reviewed before expiry. Known exploited (KEV) vulnerabilities must be re-reviewed every 30 days.

## §5 Monitoring during deferral
The Security Operations Center adds detection rules for exploitation attempts against deferred vulnerabilities and reviews alerts for the affected assets daily.
