

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/mannyaguirre/Threat-Hunting-Scenario-Tor-Browser/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

## Step 1 ##
**The hunt began with a broad review of file creation activity over the last 24 hours using DeviceFileEvents:**


Query used to locate events:

```kql
DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| sort by Timestamp desc
```
<img width="1082" height="463" alt="image" src="https://github.com/user-attachments/assets/4c814a1d-5426-4934-9b70-6e7ecbec97f3" />



**This query returned 46,264 file creation events.**

## Step 2 ##
**To focus on TOR, results were filtered for “tor.exe”:**



```kql
DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| where FileName contains "tor.exe"
| sort by Timestamp desc
```
**This reduced the dataset to 97 events within the last 24 hours.**

<img width="1081" height="458" alt="image" src="https://github.com/user-attachments/assets/409020a7-c255-4fd0-9d1c-f1e8869d41d7" />

## Step 3 ##
**Next, a check was performed to confirm whether a file named exactly “tor.exe” was created:**

```kql
DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| where FileName == "tor.exe"
| sort by Timestamp desc
```

**This returned 1 result, confirming that tor.exe was created within the last 24 hours.**

<img width="1039" height="545" alt="image" src="https://github.com/user-attachments/assets/c1caec8e-6bed-42d9-8613-43487fe32218" />

## Step 4 ##
**To see which user and which device were tied to that file creation, the account and device fields were shown:**

```kql
DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| where FileName == "tor.exe"
| sort by Timestamp desc
| project Timestamp, FileName, DeviceName, RequestAccountName, RequestAccountDomain
```

<img width="682" height="202" alt="image" src="https://github.com/user-attachments/assets/f1a64ae4-2a03-4fd0-a4e7-29be01722c1b" />

**The user tied to the activity was “mannyuser” and the device was “manny-vm.”**

```kql
DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| where FileName == "tor.exe"
| sort by Timestamp desc
| project Timestamp, DeviceName, FileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine
```
<img width="956" height="224" alt="image" src="https://github.com/user-attachments/assets/1f333cbd-605d-4e9a-b942-44191941ea4b" />

## Step 5 ##
**Next, process activity was checked to see how “tor.exe” was run:**

```kql
DeviceProcessEvents
| where Timestamp >= ago(24h)
| where DeviceName == "manny-vm"
| where FileName == "tor.exe"
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName
```
<img width="704" height="196" alt="image" src="https://github.com/user-attachments/assets/6f2cbf73-09fd-4ced-942b-552f2d07fb01" />

**This showed that “tor.exe” ran on “manny-vm,” and it was launched by “firefox.exe.” In plain terms: Tor was started from Firefox.**

## Step 6 ##
**After that, other TOR-related files created on the same device were reviewed:**

```kql
DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| where DeviceName == "manny-vm"
| where FileName contains "tor"
| sort by Timestamp desc
```
<img width="984" height="90" alt="image" src="https://github.com/user-attachments/assets/86b936d6-bfae-4efa-9429-9e72741692f3" />

**Two related files were found:**

-tor-shopping-list.txt.lnk

-tor-shopping-list.txt.txt

**These were created about one second apart on Jan 15, 2026.**

## Step 7 ##
**DeviceNetworkEvents confirmed TOR-related connections from manny-vm; tor.exe connected outbound over port 9001 to external IPs, and firefox.exe. The following query was used to identify these events**

```kql
DeviceNetworkEvents
| where Timestamp >= ago(24h)
| where DeviceName == "manny-vm"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

<img width="939" height="227" alt="image" src="https://github.com/user-attachments/assets/b0e7a5b1-0e95-44f9-a081-f5fa114451eb" />

---

## Chronological Event Timeline 

### 1. File Download – TOR Installer
**Timestamp:** Jan 15, 2026 2:00:46 PM

**Event:** The user “mannyuser” downloaded the TOR Browser installer named tor-browser-windows-x86_64-portable-15.0.4.exe to the Downloads folder on manny-vm. 

**Action:** File download detected (installer file created in Downloads with a TOR Project origin URL). 

**File Path:** C:\Users\mannyuser\Downloads\tor-browser-windows-x86_64-portable-15.0.4.exe 

### 2. Process Execution – TOR Browser Installation (Silent Mode)
**Timestamp:** Jan 15, 2026 2:07:17 PM

**Event:** The TOR Browser installer tor-browser-windows-x86_64-portable-15.0.4.exe executed in silent mode (/S) and began installing/extracting TOR Browser components.

**Action:** Silent installation activity observed (file creation tied to installer running with /S).

**Command:** tor-browser-windows-x86_64-portable-15.0.4.exe /S

**Parent Process:** cmd.exe

**Installer Path:** C:\Users\mannyuser\Downloads\tor-browser-windows-x86_64-portable-15.0.4.exe

### 3. File Creation – TOR Executable 

**Timestamp:** Jan 15, 2026 2:07:17 PM

**Event:** The TOR executable tor.exe was created on manny-vm as part of the TOR Browser install/extraction.

**Action:** File creation detected.

**File Path:** C:\Users\mannyuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

### 4. Process Execution – TOR Launched

**Timestamp:** Jan 15, 2026 2:08:01 PM

**Event:** tor.exe executed on manny-vm, and the initiating process was firefox.exe (TOR Browser’s bundled Firefox).

**Action:** TOR execution detected.

**File Path:** C:\Users\mannyuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

### 5. Network Connection – TOR Network Activity Confirmed

**Timestamp:** Jan 15, 2026 2:09:19 PM

**Event:** tor.exe established an outbound connection to an external IP over port 9001, confirming TOR network activity.

**Action:** Connection success.

**Remote IP / Port:** 185.120.16.176:9001

### 6 File Creation – TOR Shopping List Files

**Timestamp #1:** Jan 15, 2026 3:06:46 PM

**Event:** A file named tor-shopping-list.txt.txt was created on the Desktop.

**Action:** File creation detected.

**File Path:** C:\Users\mannyuser\Desktop\tor-shopping-list.txt.txt


**Timestamp #2:** Jan 15, 2026 3:06:47 PM

**Event:** A shortcut named tor-shopping-list.txt.lnk was created in the Windows “Recent” items folder

**Action:** File creation detected.

**File Path:** C:\Users\mannyuser\AppData\Roaming\Microsoft\Windows\Recent\tor-shopping-list.txt.lnk

---

## Summary
---
In the last 24 hours, file creation logs were reviewed and narrowed down from 46,264 events to TOR-related activity. A file named tor.exe was confirmed as created on the device manny-vm, and the associated user was mannyuser based on the request account fields. Process logs showed that tor.exe executed on manny-vm, with firefox.exe listed as the initiating process, meaning Tor was launched from Firefox. Additional TOR-related files were also created on the same device: tor-shopping-list.txt.lnk and tor-shopping-list.txt.txt, created about one second apart; the .lnk file is a Windows shortcut that can be used to disguise a link/launcher as a harmless document. Network logs then confirmed TOR-related connections: tor.exe made outbound connections over port 9001 to external IP addresses, and firefox.exe connected to a local TOR proxy on 127.0.0.1:9150. Based on confirmed TOR-related file creation, execution, and network activity, the device was isolated in Microsoft Defender for Endpoint and management was notified per the lab scenario

## Response Taken

Since TOR-related files were found and tor.exe was run on “manny-vm,” the device was isolated in Microsoft Defender for Endpoint and management was notified as required by the lab.

<img width="1576" height="914" alt="image" src="https://github.com/user-attachments/assets/60ce662b-186b-45fd-ba6e-2b93e62ad50a" />


---
