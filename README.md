# Microsoft Sentinel RDP Brute-Force Detection Lab

## Overview

I'm Hakim Fakhar, a Cybersecurity Engineering student at ENSA (Cybersecurity & Embedded Systems track), working toward a SOC analyst role. This lab rebuilds the detection side of my earlier [Wazuh RDP Intrusion Detection Lab](https://github.com/hakimfakhar/Wazuh-RDP-Intrusion-Detection-Lab) inside **Microsoft Sentinel**, using the same target VM and the same attack (an RDP brute-force with Hydra) but a completely different detection stack: Azure Monitor Agent, Sysmon, Log Analytics, KQL hunting queries, and a Sentinel Analytics Rule instead of Wazuh/Suricata/Chainsaw.

The goal was to see the same attack through a different SOC toolset end to end — connect the data, hunt manually first, then turn what I found into a real scheduled detection, confirm it fires, investigate it, and automate the response — and document the whole process the way I would for a real SOC engagement. The [full report](Report/sentinel-lab-report.pdf) covers all of this in depth, including two findings that mattered as much as anything that worked cleanly: a `LogonType` filtering mistake that made the first version of the detection unusable, and an honest note about which MITRE ATT&CK coverage is actually this lab's own versus inherited from content-hub template rules.

## Environment

- **Target**: the same Windows 10 VM (VirtualBox, hostname `DESKTOP-8C93D80`) used in the original RDP lab, onboarded to Azure via **Azure Arc** to keep this project at effectively zero cost
- **Workspace**: Log Analytics workspace `law-sentinel-lab`, resource group `rg-sentinel-lab`, North Europe
- **Data connectors**: Microsoft Sentinel content hub solution *Windows Security Events*, collected via **AMA (Azure Monitor Agent)** through two Data Collection Rules — `dcr-windows-security-sysmon-lab` (Windows Security Events, common set) and `dcr-sysmon-events-lab` (Sysmon events via Windows Event Logs)
- **Attacker**: Kali Linux, Hydra v9.6

## Attack Chain

1. **RDP brute-force from Kali** using Hydra against the target's RDP service — two dictionary runs failed at the connection layer, a targeted single-credential guess got in
2. **Recon on the target**, once on the box — `whoami`, `systeminfo`, `net user`, `net localgroup`, `Get-Process`
3. Re-ran the brute-force across two sessions to confirm the detection fires consistently, not just on a lucky first pass

## Detection Engineering (KQL)

All hunting and detection logic runs against the `SecurityEvent` and `Event` (Sysmon) tables in Log Analytics:

| Purpose | Table / Logic |
|---|---|
| Failed RDP logons | `SecurityEvent \| where EventID == 4625` |
| Successful RDP logons | `SecurityEvent \| where EventID == 4624 and LogonType == 10` |
| Recon command detection | `Event` (Sysmon EventID 1) filtered on `whoami`, `systeminfo`, `net user`, `net localgroup` |
| Suspicious PowerShell parent process | `Event` (Sysmon EventID 1) filtered on `powershell` in the process tree |
| **Brute-force detection logic** | failed network logons (`EventID == 4625`, `LogonType == 3`) grouped by source IP and host in 1-minute bins, alerting at **5+ failures/minute** |

Full queries are in [`Detection-Rules/kql-hunting-queries.md`](Detection-Rules/kql-hunting-queries.md).

## Analytics Rule

The brute-force hunting query was turned into a scheduled Analytics Rule:

- **Name**: *Possible RDP Brute Force -- Multiple Failed Logons*
- **Severity**: High
- **MITRE ATT&CK**: Credential Access (Brute Force, T1110) / Lateral Movement (Remote Services, T1021)
- **Frequency**: runs every 5 minutes over the last 5 minutes of data

The rule fired for real: a second Hydra run against the target's RDP service eventually landed a valid credential pair, and the same brute-force pattern in the logs before that success triggered **Possible RDP Brute Force -- Multiple Failed Logons** as a High-severity incident.

## Incident Investigation

Once the incident fired, I opened it in the investigation graph: the alert node connects to the target host (`desktop-8c93d80`) and the source IP (`192.168.1.56`), matching exactly what the hunting queries had already surfaced manually. The entity timeline for the host also shows the alert spike against an otherwise flat baseline over the investigation window.

## Workbook

I built a custom Workbook, *RDP Intrusion -- Detection Summary*, on top of the same KQL used for hunting:
- A recon-commands table (`whoami`, `systeminfo`, `net user`, `net localgroup`) pulled from the Sysmon query
- A `SecurityIncident | summarize TotalIncidents = dcount(IncidentNumber)` stat tile
- A bar chart of failed-logon volume from the attacker IP over time, showing two distinct attack windows (12 events on 9/6, 49 total by 9/7) that line up with the two separate Hydra runs

## MITRE ATT&CK Coverage

The Sentinel MITRE ATT&CK view maps the active rules against the framework: **Brute Force (T1110)** shows the highest hit count from the analytics rule, alongside **Command and Scripting Interpreter**, **Account Discovery**, **Account Manipulation**, and **Exploit Public-Facing Application** from the rest of the content-hub rule set (mostly simulated/template coverage rather than this lab's own detections), plus **Valid Accounts (T1078)** reflecting the successful RDP logon once Hydra found working credentials.

## Automation (SOAR)

Built a Logic App playbook (`pb-rdp-bruteforce-notify2`) triggered on **Microsoft Sentinel incident**, with a single **Send an email (V2)** action (subject "Sentinel Alert: RDP Brute Force Detected"). Wired it in with an Automation Rule (*Notify on RDP Brute Force*) that fires "When incident is created" and matches on the analytics rule name, so any future trigger of this detection sends an automatic notification — no manual polling of the Incidents page needed.

## Repository Structure

```
Screenshots/
  01-Setup/                 Log Analytics workspace, content hub solution
  02-Data-Connectors/       AMA + DCR configuration (Windows Security Events + Sysmon)
  03-Attack-Chain/          Recon commands, Hydra brute-force runs (including the successful one)
  04-KQL-Hunting/           Manual hunting queries and results
  05-Analytics-Rule/        Scheduled rule creation and active rules list
  06-Incident-Investigation/  Incident triage, entity timeline, investigation graph
  07-Workbook/              Custom Workbook build and results
  08-MITRE-ATTCK/           MITRE ATT&CK coverage view
  09-Automation-Playbook/   Logic App playbook + automation rule wiring
Configuration/               Workspace / DCR / connector setup notes
Detection-Rules/             KQL queries and MITRE mapping
Report/                     Full LaTeX writeup sentinel-lab-report.pdf
```

## Status

Lab complete end to end: data ingestion, manual KQL hunting, the Analytics Rule, a real triggered Incident, the investigation graph, a custom Workbook, MITRE ATT&CK coverage, and an automated email notification via a Logic App playbook.

## Related Projects

- [Wazuh RDP Intrusion Detection Lab](https://github.com/hakimfakhar/Wazuh-RDP-Intrusion-Detection-Lab) — the original detection lab this project rebuilds in a different stack
- [Cloud-IAM-Compromise-Lab](https://github.com/hakimfakhar/Cloud-IAM-Compromise-Lab) — a simulated leaked IAM key attack/detection project on AWS

---
Cybersecurity engineering student working toward a SOC analyst role.
