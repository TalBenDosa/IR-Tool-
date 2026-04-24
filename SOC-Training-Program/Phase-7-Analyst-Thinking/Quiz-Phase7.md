# Phase 7 Quiz — Analyst Thinking

**Time limit:** 20 minutes
**Total questions:** 10
**Passing score:** 8/10

---

**Question 1 (1 point):**
Which of the following is NOT a sign that an activity is suspicious?

A) A login at 3 AM from a country where the company has no employees
B) A user accessing the same files they access every day at 9 AM
C) A PowerShell command with -enc (encoded) flag spawned from Word
D) 50,000 files modified in 2 minutes on a file server

---

**Question 2 (1 point):**
What is the most dangerous outcome in security monitoring?

A) A false positive (benign event treated as a threat)
B) A slow investigation (taking 30 minutes instead of 15)
C) A false negative (a real threat that is missed and not alerted)
D) An escalation to Tier 2 that turns out to be a false positive

---

**Question 3 (1 point):**
"Alert fatigue" occurs when:

A) Analysts are tired from working night shifts
B) A very high volume of false positive alerts causes analysts to become desensitized and start missing real threats
C) The SIEM is overloaded with too many log sources
D) Network bandwidth is saturated by security tool traffic

---

**Question 4 (1 point):**
A user who always logs in from London, England suddenly logs in from Moscow, Russia at 2 AM. The username and password are correct. What should you do FIRST?

A) Immediately disable the account and notify the user
B) Check if this is a known VPN exit node or if the user is traveling
C) Close the alert — correct credentials were used
D) Reset the password without notifying anyone

---

**Question 5 (2 points):**
Analyze this scenario and give your TP/FP decision with reasoning:
```
Alert: Admin PowerShell Execution
User: helpdesk-admin@company.com
Time: Tuesday 14:30
System: 192.168.5.22 (helpdesk workstation)
Command: Get-ADUser -Filter {Enabled -eq $true} | Export-Csv C:\Temp\users.csv
Parent: powershell.exe (launched from Task Scheduler)
```
Additional context: The helpdesk team runs this script every Tuesday at 14:30 to update their user directory listing. You verify this in the change management system.

Is this TP or FP? Explain.

---

**Question 6 (2 points):**
Analyze this scenario and give your TP/FP decision with reasoning:
```
Alert: Admin PowerShell Execution
User: sarah.jones@company.com (finance analyst — no admin role)
Time: Saturday 03:22
System: LAPTOP-SJONES
Command: Get-ADUser -Filter * | Select SamAccountName,PasswordLastSet | Export-Csv C:\Temp\all_users.csv
Parent: powershell.exe (launched from cmd.exe, launched from winword.exe)
```
Additional context: Sarah Jones is in the Finance department with no administrative access. She does not work weekends.

Is this TP or FP? Explain.

---

**Question 7 (1 point):**
During an investigation, you discover that the SIEM alert is accurate but you cannot determine if the activity is authorized or a mistake. What should you do?

A) Close as FP — the SIEM might be wrong
B) Close as TP — always assume the worst
C) Contact the user to ask if they authorized the activity, document all findings, and escalate to Tier 2 if needed
D) Wait 24 hours to see if more alerts fire

---

**Question 8 (1 point):**
What does "pivoting" mean in the context of security investigation?

A) Changing your shift schedule
B) Using an indicator from one alert (like an IP address) to search for related events across other log sources
C) Switching from SIEM to EDR in your investigation tool
D) Escalating an alert to Tier 2

---

**Answer Key:**

1. B — A user accessing the same files every day at 9 AM is normal, expected behavior.

2. C — A false negative is the most dangerous because the threat goes undetected. A false positive wastes time but causes no security damage.

3. B — Alert fatigue from excessive false positives causes analysts to stop investigating carefully.

4. B — Check context first before taking action. This could be a VPN exit node (privacy VPN from London exit point), the user is traveling, or it could be a compromise. Context determines the action. Never reset without first understanding the situation (the reset might tip off the attacker).

5. (2 points) FALSE POSITIVE. This is authorized and expected behavior:
- The user is helpdesk-admin (has appropriate role)
- The time is Tuesday 14:30 (normal work hours, matches the weekly schedule)
- The command is a routine AD export (common helpdesk task)
- The parent is Task Scheduler (scheduled automation — this is explicitly configured)
- Verified in change management system (formally approved)
Close as FP and document: "Authorized weekly helpdesk user export script, verified in change management system."

6. (2 points) TRUE POSITIVE — this is highly suspicious and almost certainly malicious.
Every element is suspicious:
- sarah.jones has no admin access but is running an AD enumeration command
- Time is 3:22 AM on a Saturday — completely outside working hours
- Parent process chain: winword.exe → cmd.exe → powershell.exe (classic macro malware delivery chain — Word opened a malicious document that ran a macro)
- The command dumps all user accounts and password ages — reconnaissance for privilege escalation or planning a targeted attack
- A finance analyst with no AD access should never be running AD queries
This is almost certainly a case where Sarah's laptop was compromised via a malicious Word document. Escalate immediately.

7. C — Contact the user (if appropriate), document thoroughly, escalate to Tier 2 if uncertain.

8. B — Pivoting means using one indicator to find related events across other sources.
