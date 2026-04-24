# Scenario Labs — Level 1: Simple Single-Event Scenarios

**Purpose:** Practice basic triage and TP/FP decisions on single log entries.
**Difficulty:** Beginner
**Skills:** Read a log, identify suspicious indicators, make initial decision.

---

## How to Use These Scenarios

For each scenario:
1. Read the story (1-2 sentences of context)
2. Read the single log entry
3. Answer the questions before reading the answer
4. Compare your thinking with the provided analysis

---

## Scenario 1 — The Late Night Login

**Story:** Your SOC team has a rule that alerts on any successful login between 1 AM and 5 AM. An alert fired.

**Log:**
```
EventID: 4624
Time: 2024-03-15T03:22:14Z
Computer: DC01.company.com
Account Name: john.smith
Account Domain: COMPANY
Logon Type: 3 (Network)
Source Network Address: 192.168.1.55
Authentication Package: Kerberos
```

**Questions:**
1. Is this a domain controller login or a workstation login?
2. What type of logon is this?
3. Is the source IP internal or external?
4. What would make this more suspicious? What would make it more benign?

**Analysis:**
This alert is from the Domain Controller (DC01). The logon is Type 3 (network logon — accessing a network resource). Source is internal (192.168.1.55).

Factors making it suspicious: 3:22 AM is outside normal work hours. Accessing the DC at night is unusual for regular users.

Factors that might make it benign: A scheduled script or service might be doing a network logon. An IT admin doing scheduled maintenance. A batch job.

Next steps: Check what john.smith's normal schedule is. Check what happened after this logon — was any files accessed, any commands run? Is 192.168.1.55 john.smith's known computer?

Verdict: Unable to determine from single log. INVESTIGATE FURTHER.

---

## Scenario 2 — The Failed Login

**Story:** The SIEM alerts on "Multiple Failed Logins."

**Log:**
```
EventID: 4625
Time: 2024-03-15T09:15:22Z
Computer: WORKSTATION-SLEE
Account Name: sarah.lee
Account Domain: COMPANY
Failure Reason: Unknown user name or bad password
Source Network Address: 192.168.1.100
Logon Type: 2 (Interactive)
```

**Questions:**
1. What type of logon failure is this?
2. Is this internal or external?
3. Is a single failed login suspicious?
4. What would change your assessment?

**Analysis:**
This is one failed interactive logon (Type 2 — at the keyboard). Internal source.

A single failed interactive logon on a workstation at 9:15 AM is NOT suspicious. This is almost certainly sarah.lee mistyping her password when she arrived at work in the morning.

This is a FALSE POSITIVE. Document as: "Single failed interactive login by the account owner on their own workstation during work hours — password mistype."

Verdict: FALSE POSITIVE. Close with documentation.

---

## Scenario 3 — The PowerShell Execution

**Story:** EDR detects a PowerShell execution.

**Log:**
```
EDR Alert: PowerShell Execution Detected
Time: 2024-03-15T14:22:47Z
Device: LAPTOP-AGARCIA
User: a.garcia@company.com
Process: powershell.exe
Parent: explorer.exe
Command Line: powershell.exe Get-ChildItem -Path "C:\Users\agarcia\Documents"
Location: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Questions:**
1. Who started PowerShell?
2. What is it doing?
3. Is the parent process (explorer.exe) normal for launching PowerShell?
4. Is the command suspicious?

**Analysis:**
Explorer.exe (the Windows desktop/shell) started PowerShell — the user clicked or ran PowerShell from the taskbar or Start menu. This is normal.

The command "Get-ChildItem" is simply listing files in the Documents folder — equivalent to "dir" in cmd.exe.

Nothing suspicious here. An IT-savvy user or IT admin ran a PowerShell command to list files.

Verdict: FALSE POSITIVE. Close with documentation.

---

## Scenario 4 — The External Connection

**Story:** Firewall alert on outbound connection to an unusual port.

**Log:**
```
Firewall Log:
Time: 2024-03-15T14:33:22Z
Action: ALLOW
Source IP: 192.168.1.77
Source Port: 54321
Destination IP: 185.220.101.47
Destination Port: 4444
Protocol: TCP
Direction: Outbound
Bytes Sent: 1,024
```

**Questions:**
1. Is the destination IP internal or external?
2. What is port 4444 commonly associated with?
3. Is this suspicious?
4. What would you do next?

**Analysis:**
185.220.101.47 is external. Port 4444 is the default Metasploit reverse shell listener port.

An internal computer making an outbound connection to an external IP on port 4444 is HIGHLY suspicious. This pattern is almost always a reverse shell callback from malware to an attacker's Metasploit listener.

Next steps: Identify which device has IP 192.168.1.77 (DHCP logs). Check EDR on that device for what process is making the connection. Check if the destination IP is known malicious (threat intel). Block the connection at the firewall immediately.

Verdict: TRUE POSITIVE — High Severity. Escalate to Tier 2.

---

## Scenario 5 — The New Admin Account

**Story:** Your SIEM detects a new account creation event.

**Log:**
```
EventID: 4720
Time: 2024-03-15T09:30:00Z
Computer: DC01.company.com
Actor: IT-Admin\setup.script
New Account: svc-monitoring
New Account Domain: COMPANY
```

**Questions:**
1. What happened?
2. When did it happen?
3. Who created the account?
4. What additional information would you need?

**Analysis:**
A new account was created at 9:30 AM by "IT-Admin\setup.script" — this appears to be an automated script running as an IT admin account. The timing (9:30 AM) is during business hours.

This MAY be legitimate — IT departments regularly create service accounts for monitoring tools. However, it may also be suspicious.

Key question: Is there a change request for this? Was the IT team expecting to create a "svc-monitoring" account today?

Without change management context: UNCERTAIN — investigate.
With change management confirmation: FALSE POSITIVE.
Without any record: Follow up with IT immediately.

---

## Scenario 6 — The Suspicious Email

**Story:** Email security system flagged an incoming email.

**Log:**
```
Email Security Alert:
Time: 2024-03-15T08:44:22Z
From: "Microsoft Security" <security@microsoft-account-verify.net>
To: j.wilson@company.com
Subject: Your Microsoft Account Has Been Compromised
SPF: Fail
DKIM: Fail
DMARC: Fail (action: none)
Attachment: None
URL: https://microsoft-account-verify.net/verify
URL Analysis: Domain registered 1 day ago. Category: Uncategorized.
Action: Delivered to inbox
```

**Questions:**
1. Is this email from Microsoft?
2. What do the authentication results tell you?
3. Why was it delivered despite failing all checks?
4. What should you do?

**Analysis:**
This is definitively NOT from Microsoft. "microsoft-account-verify.net" is NOT a Microsoft domain. All three authentication checks fail. The domain was registered one day ago (classic phishing domain).

The email was delivered because the company's DMARC policy is p=none (monitoring only, no enforcement). This is a configuration gap.

Actions: Remove the email from the user's inbox immediately. Block the domain at the email gateway. Check if the user clicked the link (proxy logs). If they clicked: check if credentials were entered (check for successful login from unusual IP). Report the domain to threat intelligence. Recommend DMARC policy be changed to p=quarantine or p=reject.

Verdict: TRUE POSITIVE — Phishing email. Remove and contain.

---

## Answers Summary

1. Investigate further (requires more context)
2. FALSE POSITIVE (single failed interactive login during work hours)
3. FALSE POSITIVE (normal user running benign PowerShell command)
4. TRUE POSITIVE — HIGH (Metasploit port 4444 callback)
5. Uncertain — check change management records
6. TRUE POSITIVE — Phishing email (remove and contain)
