# Environment Setup Notes

## Log Analytics Workspace
- Name: `law-sentinel-lab`
- Resource group: `rg-sentinel-lab`
- Region: North Europe (West Europe rejected new accounts at the time)

## Microsoft Sentinel
- Enabled on top of `law-sentinel-lab`
- Content hub solution installed: **Windows Security Events**

## Data Connector — AMA
- Connector: *Windows Security Events via AMA*
- Target resource: `desktop-8c93d80` (Windows Machines — Azure Arc), the same VirtualBox VM from the original Wazuh RDP lab, onboarded via Azure Arc
- Enables System Assigned Managed Identity on the machine, installs the Azure Monitor Agent automatically

## Data Collection Rules
Two DCRs feed the workspace from the same Arc-onboarded machine:

| DCR | Data collected | Purpose |
|---|---|---|
| `dcr-windows-security-sysmon-lab` | Microsoft-SecurityEvent (Common event set) | Windows Security log (4624/4625 logon events) |
| `dcr-sysmon-events-lab` | Windows Event Logs | Sysmon operational log (process creation, EventID 1) |

Both route to `law-sentinel-lab` in `rg-sentinel-lab`, region North Europe, telemetry type "Agent-based - Windows".

## Attack Tooling
- Kali Linux, Hydra v9.6
- `hydra -L Users.txt -P passwords.txt rdp://<target-ip>`
- Two separate attack runs on different days to confirm consistent detection, not a one-off
