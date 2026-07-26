# Project 3 — Microsoft Sentinel SIEM Setup
**SOC Analyst Home Lab**  
**Author:** Shachin P R | **Date:** 2026-07-26  
**GitHub:** github.com/shachinpr29 | **YouTube:** @CyberShachin

---

## Objective

Set up Microsoft Sentinel as a cloud-native SIEM to ingest Windows Security and Sysmon telemetry from a local Windows 11 VM via Azure Arc + Azure Monitor Agent (AMA). This forms the detection engineering foundation for Project 3 — simulating MITRE ATT&CK techniques and building KQL-based analytics rules.

---

## Lab Architecture

```
Windows 11 VM (VirtualBox — "Target")
        │
        ▼
Azure Arc Agent (v1.66.03466.3076)
        │
        ▼
Azure Monitor Agent — AMA (v1.43.0.0)
        │
        ▼
Data Collection Rule (dcr-sentinel-windows)
        │
        ▼
Log Analytics Workspace (soc-lab-workspace2 — Central India)
        │
        ▼
Microsoft Sentinel
```

**Resource Group:** soc-lab-rg  
**Region:** Central India  
**OS:** Windows 11 Pro (VirtualBox VM)

---

## Data Sources Configured

| Stream | Channel | Key Event IDs |
|---|---|---|
| SecurityEvent | Windows Security | 4624, 4625, 4648, 4672, 4688, 4698, 4720, 4726 |
| WindowsEvent | Microsoft-Windows-Sysmon/Operational | 1, 3, 7, 10, 11, 12, 13 |
| WindowsEvent | Microsoft-Windows-PowerShell/Operational | 4103, 4104 |
| WindowsEvent | System | 7034, 7045 |

---

## Setup Steps

### Step 1 — Prepare the Windows VM

Before installing any Azure agent, two blockers had to be resolved:

**Disk space:** C: drive had only ~260 MB free — not enough for the Arc MSI (~427 MB required). Freed ~4.6 GB by running DISM component cleanup:

```powershell
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
```

Also cleared Windows Update download cache and old Edge versions:

```powershell
Stop-Service wuauserv -Force
Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force
Start-Service wuauserv
```

**Tamper Protection:** Windows Defender Tamper Protection was ON, which silently reverted any Defender exclusions added via Settings or PowerShell. Disabled via:

```
Windows Security → Virus & threat protection → Manage settings → Tamper Protection → OFF
```

Verified it was truly off (not enforced by Intune/ATP):

```powershell
(Get-MpComputerStatus).TamperProtectionSource  # Returns: UI
(Get-MpComputerStatus).IsTamperProtected        # Returns: False
```

Added persistent Defender exclusions for Arc/AMA paths:

```powershell
Add-MpPreference -ExclusionPath "C:\ProgramData\GuestConfig"
Add-MpPreference -ExclusionPath "C:\ProgramData\AzureConnectedMachineAgent"
Add-MpPreference -ExclusionPath "C:\WindowsAzure"
```

---

### Step 2 — Clean Up Stale Azure Arc Resource

A previous broken Arc registration was stuck in Azure with a ghost AMA extension in `"Failed"` state. Portal delete was unavailable, CLI delete didn't propagate. Force-deleted via ARM REST API:

```bash
az rest \
  --method DELETE \
  --url "https://management.azure.com/subscriptions/<SUB_ID>/resourceGroups/soc-lab-rg/providers/Microsoft.HybridCompute/machines/Target?api-version=2023-10-03-preview"
```

Confirmed deletion:

```bash
az connectedmachine show --name Target --resource-group soc-lab-rg
# Returns: ResourceNotFound ✅
```

---

### Step 3 — Install Azure Arc Agent

Generated a fresh onboarding script from:  
**Azure Portal → Azure Arc → Machines → Onboard existing machines → Single server → Generate script**

Verified the `TENANT_ID` in the script matched the Azure tenant before running:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\OnboardingScript.ps1
```

Script downloaded and installed the Arc MSI, then opened a browser for device-code authentication. Signed in with the correct Azure account (tenant match is critical — a mismatch was the root cause of previous failures).

**Result:**
```
INFO    Connected machine to Azure
INFO    Machine overview page: https://portal.azure.com/...
```

Arc agent confirmed connected in portal: **Azure Arc → Machines → Target → Status: Connected**

---

### Step 4 — Install Azure Monitor Agent (AMA) via CLI

Installed the `connectedmachine` CLI extension first:

```bash
az extension add --name connectedmachine --allow-preview true
```

Deployed AMA using `--no-wait` to avoid shell timeout issues:

```bash
az connectedmachine extension create \
  --name AzureMonitorWindowsAgent \
  --publisher Microsoft.Azure.Monitor \
  --type AzureMonitorWindowsAgent \
  --machine-name Target \
  --resource-group soc-lab-rg \
  --location centralindia \
  --enable-auto-upgrade true \
  --no-wait
```

Checked status after 3-4 minutes:

```bash
az connectedmachine extension show \
  --name AzureMonitorWindowsAgent \
  --machine-name Target \
  --resource-group soc-lab-rg \
  --query "{status:properties.provisioningState, message:properties.instanceView}"
```

**Result:**
```json
{
  "status": "Succeeded",
  "message": {
    "status": {
      "code": "0",
      "level": "Information",
      "message": "Extension Message: ExtensionOperation:enable. Status:Success"
    },
    "typeHandlerVersion": "1.43.0.0"
  }
}
```

---

### Step 5 — Create Data Collection Rule (DCR)

Created DCR via Azure CLI to avoid portal payload validation issues:

```bash
az monitor data-collection rule create \
  --name "dcr-sentinel-windows" \
  --resource-group "soc-lab-rg" \
  --location "centralindia" \
  --data-flows '[{"streams":["Microsoft-SecurityEvent","Microsoft-WindowsEvent"],"destinations":["sentinel-workspace"]}]' \
  --destinations '{"logAnalytics":[{"workspaceResourceId":"/subscriptions/<SUB_ID>/resourceGroups/soc-lab-rg/providers/Microsoft.OperationalInsights/workspaces/soc-lab-workspace2","name":"sentinel-workspace"}]}' \
  --data-sources '{"windowsEventLogs":[{"name":"security-events","streams":["Microsoft-SecurityEvent"],"xPathQueries":["Security!*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4698 or EventID=4720 or EventID=4726)]]"]},{"name":"sysmon-events","streams":["Microsoft-WindowsEvent"],"xPathQueries":["Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1 or EventID=3 or EventID=7 or EventID=10 or EventID=11 or EventID=12 or EventID=13)]]","Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4103 or EventID=4104)]]","System!*[System[(EventID=7045 or EventID=7034)]]"]}]}'
```

Associated DCR to the Target VM:

```bash
az monitor data-collection rule association create \
  --name "dcr-sentinel-windows-association" \
  --rule-id "/subscriptions/<SUB_ID>/resourceGroups/soc-lab-rg/providers/Microsoft.Insights/dataCollectionRules/dcr-sentinel-windows" \
  --resource "/subscriptions/<SUB_ID>/resourceGroups/soc-lab-rg/providers/Microsoft.HybridCompute/machines/Target"
```

Both returned `"provisioningState": "Succeeded"`.

---

### Step 6 — Verify Log Ingestion

Ran KQL queries in **Microsoft Sentinel → Logs**:

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| take 10
```

```kql
WindowsEvent
| where TimeGenerated > ago(30m)
| take 10
```

**Result:** Both queries returned live events from `Computer: Target` ✅

- SecurityEvent: Windows Security logs (NT AUTHORITY\SYSTEM, EID 4624 etc.)
- WindowsEvent: Sysmon events (Provider: Microsoft-Windows-Sysmon)

---

## Troubleshooting Reference

| Problem | Root Cause | Fix |
|---|---|---|
| Arc MSI install fails (error 1603) | C: drive full — only 260 MB free | DISM component cleanup + clear SoftwareDistribution cache |
| Defender exclusions not persisting | Tamper Protection ON | Disable via UI, verify with `IsTamperProtected` |
| AMA extension stuck "Failed" / HCRP409 | Ghost extension from failed attempt | Force delete via ARM REST API |
| Arc agent binary not found | Agent was never actually installed | Fresh onboarding script after cleaning stale Azure resource |
| DCR portal deployment fails (InvalidPayload) | Workspace not selected in destination UI | Create DCR via Azure CLI instead |
| Cloud Shell hangs 20+ min | CLI extension auto-install blocking | Pre-install `connectedmachine` extension, use `--no-wait` |

---

## Key Lessons

**Why MMA (Log Analytics Agent) was NOT used:** Microsoft retired MMA in August 2024. Data uploads were paused in January 2026 as a deprecation test and the legacy backend was shut down in March 2026. Building on MMA would mean silently broken telemetry with no warning — AMA is the only supported path.

**Tamper Protection vs. Exclusions:** Adding Defender exclusions via the Settings UI or `Add-MpPreference` is silently reverted when Tamper Protection is ON. Always verify with `(Get-MpComputerStatus).IsTamperProtected` before assuming exclusions are working.

**ARM REST API as a last resort:** When the Azure portal and CLI both fail to delete a stuck resource, a direct `DELETE` to the ARM REST API endpoint bypasses higher-level validation layers and forces cleanup.

**DCR via CLI over portal:** The portal DCR wizard has validation bugs where an empty destination causes `InvalidPayload` with no useful error. The CLI is more reliable and produces auditable, repeatable commands.

---

## Next Steps — Project 3 Detection Engineering

With the pipeline confirmed working, the next phase is:

1. Simulate MITRE ATT&CK techniques on the Target VM using Atomic Red Team
2. Write KQL analytics rules in Sentinel to detect each technique
3. Validate alerts fire in Sentinel Incidents
4. Document detections with MITRE mapping, KQL, and triage notes

**Planned technique coverage:**
- T1053.005 — Scheduled Task Persistence
- T1547.001 — Registry Run Key Persistence  
- T1070.001 — Event Log Clearing (Defense Evasion)
- T1562.001 — Disabling Windows Defender (Defense Evasion)

---

*Part of the  SOC Analyst Home Lab series.*  
*Project 1: Splunk SIEM Detection Engineering — github.com/shachinpr29/siem-home-lab*
