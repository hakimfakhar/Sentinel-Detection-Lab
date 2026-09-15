# KQL Hunting & Detection Queries

## 1. Failed RDP logons (recon / hunt)
```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, IpAddress, LogonType, TargetUserName
| order by TimeGenerated desc
| take 20
```
Surfaces every failed logon on the box, regardless of logon type — a first, broad pass before narrowing to network logons.

## 2. Successful RDP logons
```kql
SecurityEvent
| where EventID == 4624 and LogonType == 10
| project TimeGenerated, Account, IpAddress, Computer
```
`LogonType == 10` isolates RemoteInteractive (RDP) sessions specifically, separate from console/network logons.

## 3. Sysmon — recon command detection
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| where EventData has_any ("whoami", "systeminfo", "net user", "net localgroup")
| parse EventData with * "CommandLine" * ">" CommandLine "<" *
| project TimeGenerated, Computer, CommandLine
```
Catches the process-creation events for the classic post-compromise recon commands, parsed out of the raw Sysmon XML.

## 4. Sysmon — PowerShell parent process
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| where EventData has "powershell"
| project TimeGenerated, Computer, EventData
```
Broader net_1 sweep confirming `net.exe` (Remote System Discovery, T1018) spawned with `WindowsPowerShell\v1.0\powershell.exe` as its parent — ties the recon activity back to an interactive PowerShell session.

## 5. Brute-force detection logic (used in the Analytics Rule)
```kql
SecurityEvent
| where EventID == 4625 and LogonType == 3
| summarize FailedAttempts = count() by IpAddress, Computer, bin(TimeGenerated, 1m)
| where FailedAttempts >= 5
```
`LogonType == 3` (Network) is what Hydra's RDP module generates rather than LogonType 10, since the failed attempts never complete a full RDP session — this is the detail that makes the threshold logic work. Bucketing into 1-minute bins and alerting at 5+ failures/minute is what became the scheduled Analytics Rule.

## MITRE ATT&CK Mapping

| Technique | ID | Where it shows up |
|---|---|---|
| Brute Force | T1110 | Hydra RDP dictionary attack → Query 5 |
| Remote Services (RDP) | T1021.001 | Query 2, successful RDP logon |
| System Owner/User Discovery | T1033 | `whoami` → Query 3 |
| System Information Discovery | T1082 | `systeminfo` → Query 3 |
| Remote System Discovery | T1018 | `net user` / `net localgroup` / `net.exe` → Query 3, 4 |
| Process Discovery | T1057 | `Get-Process` |

| Valid Accounts | T1078 | Successful RDP logon once Hydra found working credentials |

The Sentinel MITRE ATT&CK view (Screenshots/08-MITRE-ATTCK/) confirms Brute Force as the highest-hit technique from the active rule set, with Valid Accounts lighting up once the brute-force run succeeded.

## Workbook Query

Used in the *RDP Intrusion -- Detection Summary* Workbook to surface total triggered incidents at a glance:
```kql
SecurityIncident
| summarize TotalIncidents = dcount(IncidentNumber)
```
