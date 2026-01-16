# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites. For example:
   - **WARNING: The links to onion sites change a lot and these have changed. However if you connect to Tor and browse around normal sites a bit, the necessary logs should still be created:**
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   
6. Create a folder on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// 1) Baseline view: show ALL files created in the last 24 hours
// Purpose: get a “big picture” of file creation activity before filtering.

DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| sort by Timestamp desc


// 2) Broad TOR filter: look for any file creations where the filename includes “tor.exe”
// Purpose: quickly narrow to TOR-related file creation activity.

DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| where FileName contains "tor.exe"
| sort by Timestamp desc


// 3) Exact confirmation: confirm whether tor.exe itself was created
// Purpose: prove that tor.exe appeared on disk (strong indicator of TOR presence).

DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| where FileName == "tor.exe"
| sort by Timestamp desc


// 4) Attribute the tor.exe creation to a user and host
// Purpose: identify which account/device is tied to tor.exe being created.

DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| where FileName == "tor.exe"
| sort by Timestamp desc
| project Timestamp, FileName, DeviceName, RequestAccountName, RequestAccountDomain


// 5) Identify how tor.exe was created (installer / silent execution clues)
// Purpose: capture the “parent process” and command line tied to the creation of tor.exe.

DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| where FileName == "tor.exe"
| sort by Timestamp desc
| project Timestamp, DeviceName, FileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine


// 6) Identify other TOR-related files created on the same device
// Purpose: find additional artifacts (installers, shortcuts, notes, etc.) related to TOR on manny-vm.

DeviceFileEvents
| where Timestamp >= ago(24h)
| where ActionType == "FileCreated"
| where DeviceName == "manny-vm"
| where FileName contains "tor"
| sort by Timestamp desc


// 7) Confirm TOR-related network activity (ports commonly associated with TOR 9001, 9030, 9040, 9050, 9051, 9150)
// Purpose: validate whether TOR traffic occurred

DeviceNetworkEvents
| where Timestamp >= ago(24h)
| where DeviceName == "manny-vm"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

```

---

## Created By:
- **Author Name**: Manny Aguirre
- **Author Contact**: https://www.linkedin.com/in/mannyaguirre/
- **Date**: January 15th, 2026


## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `January  15th, 2026`  | `Manny Aguirre`   
