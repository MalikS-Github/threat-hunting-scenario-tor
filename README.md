
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/MalikS-Github/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “malik: downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at: 2026-04-12T23:38:03.8380496Z'.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "malik-vm-threat"
| where InitiatingProcessAccountName == "malik"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-04-12T23:38:03.8380496Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="677" height="349" alt="image" src="https://github.com/user-attachments/assets/2854df5c-04a7-4b78-bbd6-0deb21077688">


---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contains the string “tor-browser-windows-x86_64-portable-15.0.9.exe” Based on the logs returned, at around 7:39 PM on April 12, 2026, a user named malik on the virtual machine malik-vm-threat downloaded a file called tor-browser-windows-x86_64-portable-15.0.9.exe directly into their Downloads folder.

Shortly after, that same file was executed, meaning the user launched the program on the system.

This file is a portable version of the Tor Browser, a tool designed to let users browse the internet anonymously by routing their traffic through multiple encrypted servers, making it difficult to trace their activity or identify their real location.

Because it’s a portable executable, it does not require installation and can run immediately, which makes it convenient—but also harder to track or control in an enterprise environment.
.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "malik-vm-threat"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="692" height="246" alt="image" src="https://github.com/user-attachments/assets/d520209e-1e67-4b7c-97dc-c7fc4f3eba93">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “malik” actually opened the tor browser. There was evidence that they opened it at 2026-04-12T23:40:33.0505199Z.There were several other instances of firefox.exe(Tor)as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "malik-vm-threat"
| where FileName has_any ("tor-browser-windows-x86_64-portable-<version>.exe", "Start Tor Browser.exe", "firefox.exe", "tor.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="758" height="367" alt="image" src="https://github.com/user-attachments/assets/1c616a55-3ef9-40b2-bd99-596ae8d9bf3b">


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports 
At approximately 7:40 PM on April 12, 2026, the user malik on the virtual machine malik-vm-threat initiated a successful network connection using the program tor.exe, which is part of the Tor Browser.

The system connected to an external IP address (195.218.16.136) over port 9001, a port commonly associated with Tor relay communication. This indicates that the Tor application was actively communicating with the Tor network.

The process originated from a directory on the user’s desktop where the Tor Browser is installed, confirming that this activity was generated by a locally executed Tor instance rather than a system process.
There were a few other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "malik-vm-threat"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9050","9150","9001","9030","9040","9051","443","80")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="757" height="380" alt="image" src="https://github.com/user-attachments/assets/72b3e6ab-8748-45a6-b6a9-d507e41b06fb">

---

## Chronological Event Timeline 


# Threat Hunt Report: Unauthorized TOR Browser Usage

## Executive Summary
On April 12, 2026, a threat hunt was conducted on device **malik-vm-threat** following alerts for suspicious network activity. The investigation confirmed that the user **malik** downloaded, installed, and utilized the TOR Browser to establish an anonymized connection to external relay nodes. During this session, the user created a document titled `tor-shopping-list.txt` on the desktop, suggesting intentional use of the software for specific tasks.

---

## Detailed Timeline of Events

### 1. File Download - TOR Installer
* **Timestamp:** `2026-04-12T19:38:03.8380496Z`
* **Event:** The user "malik" downloaded the file `tor-browser-windows-x86_64-portable-15.0.9.exe` to the Downloads folder.
* **Action:** File download detected.
* **File Path:** `C:\Users\malik\Downloads\tor-browser-windows-x86_64-portable-15.0.9.exe`

### 2. Process Execution - TOR Browser Installation
* **Timestamp:** `2026-04-12T19:39:51.4484567Z`
* **Event:** The user "malik" executed the file `tor-browser-windows-x86_64-portable-15.0.9.exe` in silent mode, initiating a background extraction and setup of the TOR Browser.
* **Action:** Process creation detected.
* **Command:** `tor-browser-windows-x86_64-portable-15.0.9.exe /S`
* **File Path:** `C:\Users\malik\Downloads\tor-browser-windows-x86_64-portable-15.0.9.exe`

### 3. Process Execution - TOR Browser Launch
* **Timestamp:** `2026-04-12T19:40:10.6357935Z`
* **Event:** User "malik" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
* **Action:** Process creation of TOR browser-related executables detected.
* **File Path:** `C:\Users\malik\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network
* **Timestamp:** `2026-04-12T19:40:31.1246358Z`
* **Event:** A network connection to IP `195.218.16.136` on port `9001` by user "malik" was established using `tor.exe`, confirming TOR browser network activity.
* **Action:** Connection success.
* **Process:** `tor.exe`
* **File Path:** `C:\Users\malik\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity
* **Timestamps:** * `2026-04-12T19:40:34Z` - Connected to external IP on port `443`.
    * `2026-04-12T19:40:36Z` - Local connection to `127.0.0.1` on port `9150`.
* **Event:** Additional TOR network connections were established, indicating ongoing activity by user "malik" through the TOR browser.
* **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List
* **Timestamp:** `2026-04-12T19:48:06.7259964Z`
* **Event:** The user "malik" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
* **Action:** File creation detected.
* **File Path:** `C:\Users\malik\Desktop\tor-shopping-list.txt`

---

## Summary

*In a span of approximately 10 minutes on the evening of April 12, 2026, the user malik successfully bypassed standard browsing protocols by downloading and running a portable TOR Browser. The logs clearly show the transition from downloading the installer to executing it in silent mode, followed by the browser establishing a verified connection to a TOR relay node (195.218.16.136). The presence of a "shopping list" file created immediately following this activity suggests the user was utilizing the anonymity of TOR to research or facilitate specific acquisitions, concluding the activity by saving these notes directly to their desktop.*


## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
