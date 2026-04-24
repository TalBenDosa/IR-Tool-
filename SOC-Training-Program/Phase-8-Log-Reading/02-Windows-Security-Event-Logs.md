# Lesson 8.2 — Windows Security Event Logs (Complete Analysis)

**Phase:** 8 — Log Reading and Analysis
**Prerequisite:** Lesson 8.1
**Time to complete:** 50 minutes

---

## Overview

Windows Security event logs are the most important log source in most enterprise environments. They record authentication events, privilege use, policy changes, process creation, and object access.

Every Windows computer and server generates security events. Domain Controllers generate the most critical events — all domain authentication flows through them.

---

## Understanding the Event Log Structure

Every Windows Security event has:

EventID: Numeric code identifying the event type
TimeCreated: When the event occurred
Computer: Which system generated the event
Level: Informational, Warning, Error, Critical
UserID: The SID of the user in the event
Keywords: Audit Success or Audit Failure

You access the event log through:
- Event Viewer (GUI) — for manual investigation
- PowerShell: Get-WinEvent -LogName Security -FilterHashTable @{Id=4624}
- SIEM — for automated collection and alerting

---

## Authentication Events — The Most Critical Category

### Event ID 4624 — Logon Success

This fires every time a user (or system) successfully authenticates.

Complete 4624 log entry:
```
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
EventID:       4624
Level:         Information
Keywords:      Audit Success
Computer:      DC01.company.com
TimeCreated:   2024-03-15T09:00:01.123Z

An account was successfully logged on.

Subject:
    Security ID:         SYSTEM
    Account Name:        DC01$
    Account Domain:      COMPANY
    Logon ID:            0x3E7

Logon Information:
    Logon Type:          3
    Restricted Admin Mode: No
    Virtual Account:     No
    Elevated Token:      No

New Logon:
    Security ID:         S-1-5-21-1234567890-1234567890-1234567890-1105
    Account Name:        john.smith
    Account Domain:      COMPANY
    Logon ID:            0x2B4C5D
    Linked Logon ID:     0x0
    Network Account Name:-
    Network Account Domain:-
    Logon GUID:         {00000000-0000-0000-0000-000000000000}

Process Information:
    Process ID:          0x578
    Process Name:        C:\Windows\System32\winlogon.exe

Network Information:
    Workstation Name:    LAPTOP-JSMITH
    Source Network Address: 192.168.1.55
    Source Port:         0

Detailed Authentication Information:
    Logon Process:       Kerberos
    Authentication Package: Kerberos
    Transited Services:  -
    Package Name (NTLM only): -
    Key Length:          0
```

### CRITICAL FIELD: Logon Type

The Logon Type tells you HOW the person authenticated:

Type 2 — Interactive:
Physical keyboard login at the computer.
Or Remote Desktop (when workstation is locked).
Normal for users sitting at their computers.

Type 3 — Network:
Accessing a shared resource over the network (file share, printer).
Or authenticating to a web service.
Most common type — seen constantly.

Type 4 — Batch:
Scheduled task or batch job ran as this user.
Normal if scheduled tasks exist. Suspicious if new.

Type 5 — Service:
A Windows service started as this user.
Normal for service accounts.

Type 7 — Unlock:
Workstation was unlocked (password entered after screensaver).
Normal during working hours.

Type 8 — NetworkCleartext:
Network login with credentials sent in cleartext (older protocols).
Suspicious — may indicate plaintext credentials being used.

Type 9 — NewCredentials:
Process launched with different credentials (runas command).
Normal for admins. Suspicious if seen from non-admin accounts.

Type 10 — RemoteInteractive:
RDP (Remote Desktop) login.
CRITICAL to monitor — check source IP, time, user account.

Type 11 — CachedInteractive:
Logged in using cached domain credentials (domain controller unreachable).
Normal in some scenarios. Suspicious if offline use is unexpected.

SOC patterns:
- Type 10 from unexpected external IP = RDP attack
- Type 3 at 3 AM for a regular user = unusual network access
- Type 9 from a non-admin account = privilege abuse

### Event ID 4625 — Logon Failure

```
EventID:   4625
Time:      2024-03-15 03:00:01
Computer:  DC01.company.com
Keywords:  Audit Failure

An account failed to log on.

Account For Which Logon Failed:
    Account Name:     administrator
    Account Domain:   COMPANY

Failure Information:
    Failure Reason:   Unknown user name or bad password
    Status:           0xC000006D
    Sub Status:       0xC0000064

Process Information:
    Process Name:     C:\Windows\System32\lsass.exe

Network Information:
    Workstation Name: -
    Source Network Address: 185.220.101.47
    Source Port: 52441

Detailed Authentication Information:
    Logon Process:    NtLmSsp
    Authentication Package: NTLM
    Transited Services: -
```

Key fields to analyze in 4625:
- Account Name: What account is being targeted?
  Many different accounts = credential stuffing
  Same account = targeted brute force
- Source Network Address: Where is it coming from?
  External IP = internet-based attack
  Internal IP = internal threat or compromised machine
- Failure Reason / Status code:
  0xC000006D: Unknown username or bad password
  0xC0000064: User name does not exist
  0xC0000234: Account is locked out
  0xC000006A: Password is correct but account requirements not met

SOC alert logic:
More than 5 failures for the same account in 2 minutes = brute force
More than 20 different accounts failing in 2 minutes from same source = credential stuffing
4625 from an external IP in countries you do not operate in = external attack

### Event ID 4648 — Logon with Explicit Credentials

```
EventID:   4648
Account Name: john.smith
Target Account: DA-admin
Target Servername: DC01
```

This fires when someone runs a process as a DIFFERENT user (runas, net use /user:, etc.)
Normal: Admins using runas to perform admin tasks.
Suspicious: Regular users running processes as other accounts (possible Pass-the-Hash indicator).

### Event ID 4634 — Account Logoff

```
EventID:   4634
Account Name: john.smith
Logon ID:     0x2B4C5D
Logon Type:   3
```

Pairing 4624 (logon) with 4634 (logoff) using the same Logon ID tells you the duration of a session.

Very short sessions (logon and immediate logoff) from unusual IPs may indicate automated credential testing.

---

## Process Creation — Event ID 4688

Requires audit policy to be enabled and process creation auditing turned on.

```
EventID:   4688
Time:      2024-03-15 14:22:47
Computer:  LAPTOP-JSMITH

A new process has been created.

Subject:
    Security ID:     COMPANY\john.smith
    Account Name:    john.smith
    Account Domain:  COMPANY
    Logon ID:        0x2B4C5D

Process Information:
    New Process ID:  0x1E8C
    New Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    Token Elevation Type: TokenElevationTypeLimited (3)
    Mandatory Label:  Mandatory Label\Medium Mandatory Level
    Creator Process ID: 0x1234
    Creator Process Name: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
    Process Command Line: powershell.exe -exec bypass -w hidden -enc JABjAGwAaQBlAG4AdA...
```

Critical fields:
- Creator Process Name: Who started this process? (Parent)
- New Process Name: What process was created? (Child)
- Process Command Line: What exactly was executed?

Suspicious parent-child relationships:
- Word (winword.exe) → PowerShell or cmd — malicious macro
- Excel (excel.exe) → PowerShell or cmd — malicious macro
- Browser (chrome.exe, iexplore.exe) → cmd or PowerShell — browser exploit or download
- explorer.exe → net.exe with unusual commands — hands-on attacker
- mshta.exe → PowerShell — HTA file execution (common malware delivery)
- wscript.exe → PowerShell — JavaScript/VBScript malware
- regsvr32.exe → network connection — Squiblydoo attack (bypasses AppLocker)

Suspicious command line patterns:
- -enc or -e flag (encoded command): hides what is being run
- -exec bypass or -ExecutionPolicy Bypass: bypasses script execution restrictions
- -w hidden or -WindowStyle Hidden: hides the window
- IEX or Invoke-Expression: executes a string as code
- DownloadString, DownloadFile, WebClient: downloads from internet
- Net.WebClient or New-Object: creates web connection objects

---

## Account Management Events

### Event ID 4720 — User Account Created
```
EventID:   4720
Time:      2024-03-15 03:14:22
Computer:  DC01.company.com

A user account was created.

Subject:
    Account Name:    SYSTEM  ← Created by SYSTEM (not a human!) — suspicious
    Account Domain:  COMPANY

New Account:
    Account Name:    support_admin
    Account Domain:  COMPANY
```
New account created by SYSTEM at 3 AM — almost certainly a backdoor.

### Event ID 4732 — Member Added to Local Group
```
EventID:   4732
Time:      2024-03-15 03:14:23
Computer:  LAPTOP-JSMITH

A member was added to a security-enabled local group.

Subject:
    Account Name: john.smith

Member:
    Account Name: support_admin

Group Name: Administrators
```
The new account was immediately added to Administrators — backdoor with full local admin.

### Event ID 4728 / 4756 — Member Added to Domain Group
```
EventID:   4728
Group Name: Domain Admins
Member:     support_admin
Actor:      SYSTEM
```
New account added to Domain Admins = full domain compromise.

---

## Privilege Use Events

### Event ID 4672 — Special Privileges Assigned
```
EventID:   4672
Account Name: john.smith
Privileges:   SeDebugPrivilege
              SeImpersonatePrivilege  
              SeTcbPrivilege
```
This fires when a user logs in with special privileges.
SeDebugPrivilege: Can debug any process (used by Mimikatz)
SeImpersonatePrivilege: Can impersonate other users (used for privilege escalation)
SeTakeOwnershipPrivilege: Can take ownership of any object

If a regular user account gets these privileges, it is suspicious.

---

## Object Access Events

### Event ID 4663 — Object Access
```
EventID:   4663
Time:      2024-03-15 14:22:31
Computer:  FILESERVER01

An attempt was made to access an object.

Subject:
    Account Name: john.smith

Object:
    Object Server: Security
    Object Type:   File
    Object Name:   C:\ConfidentialReports\Q1-Financial.xlsx
    Handle ID:     0x3A4

Access Request Information:
    Accesses: READ_DATA/LIST_DIRECTORY
    Access Mask: 0x1
```

### Event ID 5140 — Network Share Access
```
EventID:   5140
Account Name: john.smith
Share Name: \\FILESERVER01\Confidential
Share Path: E:\ConfidentialReports
Source Address: 192.168.1.55
```
Accessing the C$ (admin share) or shares with sensitive data outside business hours is suspicious.

---

## Scheduled Task Events

### Event ID 4698 — Scheduled Task Created
```
EventID:   4698
Time:      2024-03-15 03:14:44
Computer:  DC01.company.com

A scheduled task was created.

Subject:
    Account Name: SYSTEM

Task Information:
    Task Name: \Microsoft\Windows\WindowsUpdate\UpdateHelper
    Task Content:
        <Actions>
        <Exec>
            <Command>C:\Windows\Temp\payload.exe</Command>
        </Exec>
        </Actions>
        <Triggers>
            <CalendarTrigger>
                <StartBoundary>2024-03-15T03:15:00</StartBoundary>
                <Repetition>
                    <Interval>PT1M</Interval>  ← Every 1 minute
                </Repetition>
            </CalendarTrigger>
        </Triggers>
```
SYSTEM creates a scheduled task named to look like Windows Update, running payload.exe every minute = persistence mechanism.

---

## Log Clearing Event

### Event ID 1102 — Audit Log Cleared
```
EventID:   1102
Time:      2024-03-15 03:55:22
Computer:  DC01.company.com

The audit log was cleared.

Subject:
    Account Name: DA-admin
    Logon ID:     0x5C7A3B
```
An attacker cleared the logs at 3:55 AM after their operations. DA-admin is the compromised domain admin account. This event itself proves the logs were cleared — and is typically one of the last events before everything goes dark.

---

## Log Analysis Lab — Putting It Together

### Complete Attack Sequence in Windows Logs

Read this sequence and follow the attacker's journey:

```
03:00:01 EventID 4625 Failure  User: administrator  Source: 185.220.101.47  (Auth failure)
03:00:02 EventID 4625 Failure  User: administrator  Source: 185.220.101.47
03:00:03 EventID 4625 Failure  User: administrator  Source: 185.220.101.47
[3,247 more failures]
03:54:22 EventID 4624 Success  User: administrator  Source: 185.220.101.47  Type: 10 (RDP)

03:54:30 EventID 4672          User: administrator  Privileges: SeDebugPrivilege, SeBackupPrivilege

03:55:01 EventID 4720          Actor: administrator  New Account: backdoor_svc

03:55:02 EventID 4728          Member: backdoor_svc  Group: Domain Admins

03:55:11 EventID 4688          Creator: explorer.exe  
                               New Process: C:\Windows\Temp\mimikatz.exe
                               Command: mimikatz.exe "sekurlsa::logonpasswords" exit

03:55:40 EventID 4688          Creator: C:\Windows\Temp\mimikatz.exe
                               New Process: cmd.exe
                               Command: cmd.exe /c vssadmin.exe delete shadows /all /quiet

03:55:44 EventID 1102          Actor: administrator  "The audit log was cleared"
```

Analysis:
- 03:00:01 to 03:54:22 — 54-minute RDP brute force attack. 3,248+ attempts. Succeeded.
- 03:54:30 — Special privileges logged (attacker has debug and backup privileges — will use for credential dumping)
- 03:55:01 — Backdoor account created
- 03:55:02 — Backdoor account added to Domain Admins
- 03:55:11 — Mimikatz run to dump all credentials from memory
- 03:55:40 — Shadow copies deleted (preparing for ransomware or removing recovery options)
- 03:55:44 — Event logs cleared (final cleanup)

Timeline: 55 minutes 43 seconds from first brute force attempt to full domain compromise.

---

## Summary

Windows Security Event Log is the primary evidence source for Windows investigations.
Critical Event IDs: 4624 (success logon), 4625 (failed logon), 4688 (process created), 4720 (account created), 4728 (added to group), 4698 (scheduled task), 1102 (log cleared).
Logon Types tell you HOW authentication happened — Type 10 (RDP) and Type 3 (network) are most investigated.
Process creation (4688) with parent-child relationships reveals attack techniques.
4625 patterns: many accounts = credential stuffing; same account = brute force; external IP = internet attack.
Log clearing (1102) is itself logged — but proves evidence was destroyed.

---

## Practice Exercises

**Exercise 1:**
What does this sequence tell you?
```
03:00:00 4625  User: sarah.jones  Source: 192.168.1.55  Status: 0xC000006D  (12 times)
03:00:24 4624  User: sarah.jones  Source: 192.168.1.55  Logon Type: 3
03:00:25 5140  User: sarah.jones  Share: \\DC01\SYSVOL
03:00:26 4688  Creator: explorer.exe  Process: mimikatz.exe  Path: C:\Windows\Temp\
```

**Exercise 2:**
A 4624 event shows: Account Name: DA-admin, Source IP: 185.220.101.47, Logon Type: 10. What three things are immediately suspicious?

**Exercise 3:**
You see Event ID 4698 (scheduled task created) at 3 AM. The task name is "\Microsoft\Windows\Defender\MpUpdate" and runs "C:\ProgramData\temp\svc.exe". Is this suspicious? Why?
