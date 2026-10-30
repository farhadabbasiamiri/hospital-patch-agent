# POL-04 Medical Device Security and Patching
Northbridge Regional Hospital (fictional). Synthetic policy for teaching use only.

## §1 Scope
Applies to regulated medical devices and the systems that run them: infusion pump servers, patient monitoring central stations, imaging modalities (CT, MRI, X-ray consoles) and PACS components supplied by medical device manufacturers.

## §2 Vendor validation requirement
Patches, operating system updates or configuration changes must not be applied to a regulated medical device unless the manufacturer has validated and released the update for that device model. Applying an unvalidated patch can void regulatory clearance and may cause device malfunction affecting patient safety.

## §3 When no validated patch exists
If no validated patch is available, Clinical Engineering must apply compensating controls: place the device in a dedicated medical device VLAN, restrict traffic to required clinical systems only, block remote access protocols such as SMB and RDP at the segment boundary, and enable intrusion detection monitoring. The finding is tracked as DEFER_WITH_CONTROLS or ISOLATE until the vendor releases a validated fix.

## §4 Legacy operating systems
Devices running unsupported operating systems (for example Windows XP Embedded or Windows 7 Embedded) are treated as permanently higher risk and must stay segmented. Replacement planning is raised with the capital equipment committee.

## §5 Vendor coordination
Clinical Engineering requests a patch status statement from the manufacturer within 10 business days of a critical or KEV-listed finding and records the expected release date.
