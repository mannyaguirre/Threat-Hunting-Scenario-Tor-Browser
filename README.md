# Threat-Hunting-Scenario-Tor-Browser
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/mannyaguirre/Threat-Hunting-Scenario-Tor-Browser/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

**tor-shopping-list.txt.lnk**

**tor-shopping-list.txt.txt**

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

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary
---
In the last 24 hours, file creation logs were reviewed and narrowed down from 5,194 events to TOR-related activity. A file named tor.exe was confirmed as created on the device manny-vm, and the associated user was mannyuser based on the request account fields. Process logs showed that tor.exe executed on manny-vm, with firefox.exe listed as the initiating process, meaning Tor was launched from Firefox. Additional TOR-related files were also created on the same device: tor-shopping-list.txt.lnk and tor-shopping-list.txt.txt, created about one second apart; the .lnk file is a Windows shortcut that can be used to disguise a link/launcher as a harmless document. Network logs then confirmed TOR-related connections: tor.exe made outbound connections over port 9001 to external IP addresses, and firefox.exe connected to a local TOR proxy on 127.0.0.1:9150. Based on confirmed TOR-related file creation, execution, and network activity, the device was isolated in Microsoft Defender for Endpoint and management was notified per the lab scenario

## Response Taken

Since TOR-related files were found and tor.exe was run on “manny-vm,” the device was isolated in Microsoft Defender for Endpoint and management was notified as required by the lab.

<img width="1576" height="914" alt="image" src="https://github.com/user-attachments/assets/60ce662b-186b-45fd-ba6e-2b93e62ad50a" />


---
