# MITRE ATT&CK and NIST CSF 2.0 mapping

This is the **team's analyst mapping**, not an official MITRE or NIST mapping. Identifiers and names were checked on 2026-11-25 against [attack.mitre.org](https://attack.mitre.org/) (ATT&CK content v20.1) and [NIST CSWP 29](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf). Which technique fits which CVE is a judgement made from the vulnerability description.

The source of truth is `data/framework_mapping.json`; `app/frameworks.py` attaches it to every finding. The LLM never writes these identifiers.

## Decision to NIST CSF 2.0

Every finding maps to ID.RA-01, ID.RA-05, ID.RA-06 (identify, prioritize, plan the response), plus:

| Decision | CSF subcategories | ATT&CK mitigations applied |
|---|---|---|
| PATCH | PR.PS-02, ID.RA-07 | M1051 Update Software |
| ISOLATE | PR.IR-01, ID.RA-07 | M1030 Network Segmentation |
| DEFER_WITH_CONTROLS | ID.RA-07, PR.IR-01, DE.CM-09 | M1030 Network Segmentation, M1031 Network Intrusion Prevention |
| MONITOR | DE.CM-01, DE.CM-09 | none (tracking only) |

| CSF id | Outcome |
|---|---|
| ID.RA-01 | Vulnerabilities in assets are identified, validated, and recorded |
| ID.RA-05 | Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization |
| ID.RA-06 | Risk responses are chosen, prioritized, planned, tracked, and communicated |
| ID.RA-07 | Changes and exceptions are managed, assessed for risk impact, recorded, and tracked |
| PR.PS-02 | Software is maintained, replaced, and removed commensurate with risk |
| PR.IR-01 | Networks and environments are protected from unauthorized logical access and usage |
| DE.CM-01 | Networks and network services are monitored to find potentially adverse events |
| DE.CM-09 | Computing hardware and software, runtime environments, and their data are monitored to find potentially adverse events |

## Compensating control to ATT&CK mitigation

| Control in inventory | ATT&CK mitigation |
|---|---|
| segmentation | M1030 Network Segmentation |
| ips | M1031 Network Intrusion Prevention |
| mfa | M1032 Multi-factor Authentication |
| allowlisting | M1038 Execution Prevention |
| edr | M1040 Behavior Prevention on Endpoint |
| waf | M1050 Exploit Protection |

## CVE to ATT&CK technique

| CVE | Technique(s) | Why |
|---|---|---|
| CVE-2014-0160 | T1190 Exploit Public-Facing Application; T1212 Exploitation for Credential Access | Crafted heartbeat requests to an exposed TLS service leak memory that can hold credentials and keys. |
| CVE-2016-2183 | T1040 Network Sniffing; T1557 Adversary-in-the-Middle | An attacker positioned on the network collects long 64-bit block cipher traffic to recover plaintext. |
| CVE-2017-0144 | T1210 Exploitation of Remote Services | Remote code execution over SMBv1, used to move between hosts. |
| CVE-2019-0708 | T1210 Exploitation of Remote Services | Pre-authentication remote code execution over Remote Desktop. |
| CVE-2019-11687 | T1027.009 Obfuscated Files or Information: Embedded Payloads; T1204.002 User Execution: Malicious File | An executable hidden in a DICOM file preamble runs if the file is executed. |
| CVE-2019-12256 | T1210 Exploitation of Remote Services | Network-reachable stack overflow in the embedded device TCP/IP stack. |
| CVE-2019-19781 | T1190 Exploit Public-Facing Application; T1133 External Remote Services | Unauthenticated code execution on an internet-facing remote access gateway. |
| CVE-2020-11896 | T1210 Exploitation of Remote Services | Network-reachable remote code execution in the embedded Treck TCP/IP stack. |
| CVE-2020-1472 | T1068 Exploitation for Privilege Escalation; T1210 Exploitation of Remote Services | A Netlogon flaw lets a network attacker take domain administrator privileges. |
| CVE-2021-21972 | T1190 Exploit Public-Facing Application; T1210 Exploitation of Remote Services | Remote code execution against the vCenter management interface. |
| CVE-2021-22005 | T1190 Exploit Public-Facing Application; T1210 Exploitation of Remote Services | Arbitrary file upload leading to code execution on vCenter. |
| CVE-2021-26855 | T1190 Exploit Public-Facing Application | Server-side request forgery on an exposed Exchange server. |
| CVE-2021-34527 | T1068 Exploitation for Privilege Escalation; T1210 Exploitation of Remote Services | Print Spooler allows privilege escalation and remote code execution. |
| CVE-2021-4034 | T1068 Exploitation for Privilege Escalation | Local privilege escalation to root through pkexec. |
| CVE-2021-44228 | T1190 Exploit Public-Facing Application; T1210 Exploitation of Remote Services | A JNDI lookup gives remote code execution in services that log attacker input. |
| CVE-2022-0778 | T1499.004 Endpoint Denial of Service: Application or System Exploitation | A crafted certificate causes an infinite loop and denial of service. |
| CVE-2022-22965 | T1190 Exploit Public-Facing Application | Remote code execution in a web application through data binding. |
| CVE-2022-26134 | T1190 Exploit Public-Facing Application | Unauthenticated OGNL injection on a Confluence server. |
| CVE-2022-30190 | T1566.001 Phishing: Spearphishing Attachment; T1204.002 User Execution: Malicious File; T1203 Exploitation for Client Execution | A malicious document invokes MSDT to run code on the client. |
| CVE-2022-40684 | T1190 Exploit Public-Facing Application; T1133 External Remote Services | Authentication bypass on the firewall or VPN administrative interface. |
| CVE-2023-20198 | T1190 Exploit Public-Facing Application | An exposed web UI lets an unauthenticated attacker create a privileged account. |
| CVE-2023-23397 | T1187 Forced Authentication | A crafted Outlook item makes the client send its NTLM hash to an attacker. |
| CVE-2023-34362 | T1190 Exploit Public-Facing Application | SQL injection on an exposed file transfer application. |
| CVE-2023-36884 | T1566.001 Phishing: Spearphishing Attachment; T1203 Exploitation for Client Execution | A crafted Office document delivered by phishing executes code. |
| CVE-2023-38545 | T1203 Exploitation for Client Execution | A malicious server response overflows a buffer in the curl client. |
| CVE-2023-44487 | T1499.004 Endpoint Denial of Service: Application or System Exploitation | HTTP/2 stream resets exhaust server resources. |
| CVE-2023-48795 | T1557 Adversary-in-the-Middle | A man-in-the-middle truncates the SSH handshake to weaken the session. |
| CVE-2024-21762 | T1190 Exploit Public-Facing Application; T1133 External Remote Services | Out-of-bounds write on the internet-facing SSL VPN. |
| CVE-2024-3400 | T1190 Exploit Public-Facing Application; T1133 External Remote Services | Command injection on the internet-facing GlobalProtect gateway. |
| CVE-2024-6387 | T1190 Exploit Public-Facing Application; T1210 Exploitation of Remote Services | A race condition gives remote code execution in the SSH server. |

## Limitations

- Techniques describe how a flaw could be used. They are not evidence of observed attacks.
- ATT&CK for ICS and medical-device-specific frameworks are not mapped.
- A control listed as in place is not claimed to stop every technique of a given CVE.
- Re-check identifiers when ATT&CK releases a new version.
