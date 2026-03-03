# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/OSAOGBEB/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “bishopxpress” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop. These events began at: 2026-02-24T21:19:58.890422Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "bishxvm"
| where InitiatingProcessAccountName == "bishopxpress"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-02-24T21:19:58.890422Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FolderPath,SHA256, Account = InitiatingProcessAccountName

```
<img width="825" height="721" alt="image" src="https://github.com/user-attachments/assets/0d32f351-003d-46f4-81e5-1c246266dfab" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandline that contained the string “tor-browser-windows-x86_64-portable-15.0.7.exe”. Based on the logs returned, at 2026-02-24T21:19:27.4056348Z, an employee on the computer named bishxvm device, ran the file tor-browser-windows-x86_64-portable-15.0.7.exe from their Downloads folder using a command that triggered a silent installation.


**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName  == "bishxvm"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1232" height="620" alt="image" src="https://github.com/user-attachments/assets/a9480083-89b3-49ea-b770-2b48c3c8c0b6" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using the known tor ports.


**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql


DeviceNetworkEvents
| where DeviceName == "bishxvm"
| where InitiatingProcessAccountName != "system"
| where  InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051","9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc

```
<img width="1221" height="678" alt="image" src="https://github.com/user-attachments/assets/16cdb13e-aead-4990-9ba6-04b24cc3a612" />


---
Chronological Events
Below is your activity rewritten in a formal SOC Incident Report format, strictly scoped to Tor Browser–related findings.

Security Operations Center (SOC) Incident Report
Incident Title: Unauthorized Tor Browser Installation and Usage
Incident ID: SOC-2026-02-24-TOR-01
Date of Activity: February 24, 2026
Report Date: February 25, 2026
Severity: Medium (Policy Violation / Potential Defense Evasion)
Status: Investigation Completed – Awaiting Response Decision

1. Executive Summary
On February 24, 2026, the user bishopxpress on device bishxvm downloaded, executed, and actively used the portable version of Tor Browser (v15.0.7).
Within seconds of execution, the Tor environment was extracted to the desktop, multiple Tor-related processes were launched, and outbound network connections were established over known Tor relay ports (including port 9001) and HTTPS (443).
The activity demonstrates successful deployment and active use of anonymized internet routing software.

2. Affected Asset Information
Field
Value
Device Name
bishxvm
User Account
bishopxpress
Operating System
Windows (64-bit)
File Executed
tor-browser-windows-x86_64-portable-15.0.7.exe
SHA256
958626901dbe17fc003ed671b61b3656375e6f0bc06c9dff60bd2f80d4ace21b


3. Timeline of Events (Chronological)
21:19:27.4056348Z
Event Type: Process Creation
Details:
User executed:
C:\Users\BishopXpress\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe


This marks the initial execution of the Tor portable installer.

21:19:58.8788558Z
Event Type: Process Creation
Details:
Tor Browser was launched.
Observed processes included:
firefox.exe (Tor Browser instance)
tor.exe (Tor service process)
Processes executed from:
C:\Users\bishopxpress\desktop\torbrowser\



21:19:58.890422Z and After
Event Type: File Creation / File Copy
Multiple Tor-related files were written to the Desktop directory as part of the extraction and runtime process.
Notable file observed:
C:\Users\bishopxpress\Desktop\tor-shopping-list.txt



16:21 Local Time (Approx. 21:21Z)
Event Type: Network Connection Success
Outbound connection established:
Field
Value
Initiating Process
tor.exe
Process Path
C:\Users\bishopxpress\desktop\torbrowser\browser\torbrowser\tor\tor.exe
Remote IP
159.195.63.213
Remote Port
9001
Remote URL
https://www.dcuirywzxdbn2omkemxbfpr.com
Action
ConnectionSuccess

Additional outbound connections were observed over port 443 initiated by:
tor.exe
firefox.exe
Port 9001 is commonly associated with Tor relay traffic.

4. Detection Methodology
The following telemetry sources were reviewed:
DeviceProcessEvents – To identify execution of Tor installer and Tor-related processes
DeviceFileEvents – To identify Tor-related file extraction and file creation
DeviceNetworkEvents – To confirm outbound Tor network communication
Detection queries focused on:
File names containing “tor”
Known Tor executable names (tor.exe, firefox.exe under Tor path)
Known Tor ports (9001, 9030, 9040, 9050, 9051, 9150)
HTTPS traffic initiated by Tor processes

5. Analysis
Findings confirm:
Tor portable installer was executed.
Tor environment was extracted to the desktop.
Tor processes were successfully launched.
Outbound connections consistent with Tor relay traffic were established.
Additional encrypted connections over HTTPS were observed.
A user-created file (tor-shopping-list.txt) was generated during activity.
There is no evidence within this scope of:
Privilege escalation
Lateral movement
Malware deployment
Persistence mechanisms
However, Tor usage introduces:
Network visibility reduction
Potential defense evasion
Policy compliance concerns

6. MITRE ATT&CK Mapping
Technique
Description
T1090
Proxy (Use of anonymization network)
T1071.001
Web Protocols (HTTPS communications)
T1204.002
User Execution (User initiated executable)


7. Risk Assessment
Risk Level: Medium
While Tor usage alone is not inherently malicious, it presents:
Reduced network visibility
Potential data exfiltration channel
Bypass of enterprise monitoring controls
Violation of acceptable use policies (if applicable)

8. Recommended Actions
Confirm whether Tor usage is authorized under company policy.
Interview the user to determine the business justification.
Review browser activity and file access during the Tor session.
Consider blocking Tor traffic at the firewall or proxy level if prohibited.
Implement alerting for future Tor process execution.





Summary
On February 24, 2026, user bishopxpress successfully installed and actively used Tor Browser on device bishxvm.
The activity included executable launch, file extraction, Tor process execution, and outbound network communications over Tor-associated ports and HTTPS.
No additional malicious behavior was identified within the scope of this investigation.


Response Taken
TOR usage was confirmed on endpoint bishxvm. The device was isolated and the user's direct manager was notified.

