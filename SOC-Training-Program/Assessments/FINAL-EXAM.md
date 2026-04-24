# FINAL EXAM — SOC Analyst Training Program

**This exam covers the entire course: Phases 1-8, all concepts and skills.**

**Format:** Mixed (multiple choice, short answer, log analysis, scenarios)
**Time limit:** 120 minutes
**Passing score:** 70/100 (70%)
**Total questions:** 40

---

## Instructions

Answer all questions. For log analysis and scenario questions, show your reasoning.

---

## SECTION A — FUNDAMENTALS (1 point each)

**1.** What is the primary job of a SOC Tier 1 analyst?
A) Writing detection rules in SIEM
B) Triaging alerts and determining TP/FP
C) Running threat hunts across the environment
D) Managing the entire incident response process

**2.** A Windows Event ID 4624 with Logon Type 10 indicates:
A) A scheduled task ran
B) An RDP connection
C) A network file share access
D) A failed authentication

**3.** Which OSI layer handles IP addresses and routing?
A) Layer 2
B) Layer 3
C) Layer 4
D) Layer 5

**4.** What does DLP stand for?
A) Dynamic Load Processing
B) Domain Level Protection
C) Data Loss Prevention
D) Detection and Logging Protocol

**5.** Port 445 is associated with which protocol?
A) HTTP
B) SSH
C) SMB
D) DNS

**6.** What is a false negative in security?
A) Blocking legitimate traffic
B) A real threat that is missed by detection systems
C) An alert that turns out to be benign
D) A misconfigured detection rule

**7.** Kerberoasting targets which accounts?
A) Domain user accounts
B) Service accounts with weak passwords
C) System accounts
D) Guest accounts

**8.** What does DMARC enforce?
A) SPF authentication
B) DKIM signature verification
C) Alignment between SPF/DKIM and the From header
D) Email encryption

**9.** A process tree showing word.exe → powershell.exe is suspicious because:
A) PowerShell should never be used
B) Word should not normally spawn PowerShell (likely malicious macro)
C) Excel should be used instead of Word
D) This is always a legitimate operation

**10.** EDR stands for:
A) Endpoint Detection and Response
B) Event Detection and Reporting
C) Enterprise Data Retrieval
D) Email Data Repository

---

## SECTION B — LOG ANALYSIS (2 points each)

**11.** Analyze this log:
```
2024-03-15T03:00:01Z  EventID 4624
User: administrator
Source IP: 185.220.101.47
Logon Type: 10 (RDP)
Time: 3:00 AM
Device: Unmanaged, unrecognized
```
Is this suspicious? Why or why not? What are your next steps?

**12.** Read these DNS logs:
```
03:00:01  192.168.3.44 → xjkqrp19ns.com → NXDOMAIN
03:00:02  192.168.3.44 → qzxkjmn47.net → NXDOMAIN
03:00:03  192.168.3.44 → wbmrpx83.org → NXDOMAIN
[400 more attempts]
03:06:44  192.168.3.44 → plqmrx72.com → 185.220.101.47
```
What is this? What should you do?

**13.** A proxy log shows:
```
User: david.lee@company.com
Time: 3:15 AM
URL: http://185.220.101.47/gate.php?id=LAPTOP-DLEE&status=idle
User-Agent: Mozilla/4.0 (MSIE 6.0 Windows NT 5.1)
Response: 200
Bytes: 12
```
What does this indicate? Explain every suspicious element.

**14.** Azure AD log shows:
```
Time: 14:22:00 UTC — Login success from New York
Time: 14:23:00 UTC — Login success from Lagos, Nigeria
Same user: sarah.jones@company.com
Same device? No (different browsers, different OSes)
MFA passed both times
```
Is this suspicious? What is it called? What could explain it?

---

## SECTION C — INCIDENT INVESTIGATION (3 points each)

**15.** You receive an alert: "Scheduled task created on Domain Controller at 3 AM." The task is named "\Microsoft\Windows\Defender\Update" and runs "C:\Temp\svc.exe". Is this normal? What does this likely mean?

**16.** A user's mailbox shows:
```
New-InboxRule: "Auto Archive"
Action: Forward all emails to external@gmail.com
Delete original: True
```
Explain what this rule does and what threat this indicates.

**17.** EDR shows:
```
Parent: svchost.exe
Child: cmd.exe
Command: cmd.exe /c vssadmin.exe delete shadows /all /quiet
User: SYSTEM
Time: 3:47 AM
```
What is the attacker preparing for? Why delete shadow copies?

---

## SECTION D — ATTACK CHAIN RECONSTRUCTION (4 points)

**18.** Put these events in chronological order and explain the complete attack:

A) Event ID 4624: user.account logged in via RDP from external IP
B) Firewall: external IP → port 445 (SMB) — BLOCKED
C) Event ID 4625: 3,000 failed logins to multiple accounts
D) Event ID 4788: DLL loaded from C:\Windows\Temp\
E) Email: phishing from fake domain

**Most likely sequence:** __ → __ → __ → __ → __

**Explanation:** [Write 3-4 sentences describing the attack chain]

---

## SECTION E — SCENARIO ANALYSIS (5 points)

**19.** You are a Tier 1 analyst. At 9:15 AM, you receive this alert:

```
SIEM Alert: "Possible Ransomware Activity"
Severity: CRITICAL
13 alerts fired simultaneously across different systems
Alert: vssadmin.exe executed on 13 computers
Alert: bcdedit.exe executed on 13 computers
Alert: 47,000 files modified with extension ".crypted" in 4 minutes
Source: Group Policy object deployed at 4:00 AM
```

Your supervisor says: "We're getting alerts non-stop. What do you do in the next 5 minutes?"

Write your immediate response plan (step-by-step, prioritized).

---

## SECTION F — SIEM DETECTION LOGIC (2 points each)

**20.** Write a detection rule (in simple English) for Kerberoasting:
"Alert when [CONDITION] in [TIME WINDOW]"

**21.** Write a detection rule for impossible travel:
"Alert when [CONDITION]"

---

## SECTION G — FORENSICS AND EVIDENCE (2 points each)

**22.** You discovered that Windows Security event logs were cleared (EventID 1102). Why is this event itself valuable evidence? What does it tell you?

**23.** You need to present findings to management about a HIPAA breach (patient data stolen). What three key metrics/numbers do you provide?

---

## SECTION H — PROTOCOL & NETWORK KNOWLEDGE (1 point each)

**24.** What does NTLM stand for?

**25.** What is a TGT in Kerberos?

**26.** What does SPF check?

**27.** Which of these IPs is private? 10.0.0.1, 8.8.8.8, 192.168.5.50, 185.220.101.47

**28.** What does SIEM stand for?

---

## SECTION I — THREAT MODELING (3 points)

**29.** An attacker has just obtained a user's password. List 5 techniques they might use AFTER gaining initial access (from the Kill Chain or MITRE ATT&CK).

**30.** You are designing security for a hospital. Name the top 3 security risks specific to healthcare organizations and how you would mitigate each.

---

## SECTION J — COMPLETE INVESTIGATION (10 points)

**31.** You receive multiple alerts over a weekend. Reconstruct the full attack and provide a complete incident report:

```
FRIDAY 22:00 — Email Security: Phishing email delivered to mark.davis@company.com
  From: "IT Support" <support@company-helpdesk.net> (not company.com)
  Subject: "Action Required: Update Your Password"
  Link: https://company-helpdesk.net/reset

FRIDAY 22:15 — Proxy: User visited the phishing URL, submitted a form (POST)

FRIDAY 22:15 — Azure AD: Successful login for mark.davis from 185.220.101.47 (Romania)
  MFA: Not triggered (trusted location misconfiguration)

FRIDAY 22:17 — M365 Audit: New-InboxRule created: "Archive" → Delete emails with "security" or "alert"

SATURDAY 02:00 — M365 Audit: 47 files downloaded from /sites/ConfidentialData/ (8.2 GB)

SATURDAY 03:14 — Windows Event: EventID 4662 (DCSync) from mark.davis account

SUNDAY 04:00 — EDR: Ransomware deployed on 7 systems, file encryption began
```

**Your complete report should include:**
1. Attack timeline (chronological order)
2. Each attack technique (name and MITRE ATT&CK ID)
3. Impact assessment (what data/systems compromised)
4. Root causes (why the defenses failed)
5. Immediate response actions (first 24 hours)
6. Remediation (short, medium, long term)
7. Recommendations to prevent recurrence

---

## ANSWER KEY

**SECTION A:**
1. B | 2. B | 3. B | 4. C | 5. C | 6. B | 7. B | 8. C | 9. B | 10. A

**SECTION B:**
11. (2 pts) YES, very suspicious. Administrator login from external IP at 3 AM on unmanaged device with no MFA. Next steps: Check if this succeeded; if so, disable the account and begin incident response. Check what happened after this login. Investigate the external IP in threat intel.

12. (2 pts) Domain Generation Algorithm (DGA) malware. The device is trying random domain names, most fail (NXDOMAIN), then one resolves. Immediate action: Isolate the device, run EDR scan, identify the malware family, block the resolved domain and IP.

13. (2 pts) C2 beaconing. Suspicious elements: 3 AM (no work happening), gate.php (classic C2 endpoint), no user logged in, computer ID in URL (malware reporting in), old fake user agent (MSIE 6.0 from 2001), response is tiny (12 bytes = command). This is malware communicating with its attacker.

14. (2 pts) YES, very suspicious. Called "impossible travel" — same user cannot be in New York and Nigeria in 1 minute. Possible explanations: account compromise (most likely), VPN/proxy misconfiguration (less likely), or the user is on a plane with WiFi (very unlikely given the same time stamps). Investigate immediately.

**SECTION C:**
15. (3 pts) NOT normal. Legitimate Windows update tasks run from \Microsoft\Windows\Defender\ and execute from C:\Program Files\. This task runs from C:\Temp\ (suspicious) at 3 AM (suspicious). This is almost certainly a persistence mechanism — a backdoor disguised as a Windows update.

16. (3 pts) This rule forwards ALL incoming emails to an external Gmail account and deletes the originals. The mailbox owner will never see the emails. This indicates: either the account is compromised and is being silently monitored by an attacker, OR the account owner is doing insider espionage. Either way, this is a threat.

17. (3 pts) The attacker is preparing for ransomware deployment. Shadow copies are the local backups that allow Windows to restore previous file versions. By deleting them, the attacker ensures the victim cannot use Windows' built-in recovery to undo the encryption. After deleting shadows, ransomware is deployed.

**SECTION D:**
18. (4 pts) Sequence: **E → C → A → B → D**

Explanation: The attack began with a phishing email (E), likely containing credentials. The attacker used the stolen credentials to attempt RDP login (A), which was blocked by the firewall on port 445 (B) — so they tried brute force instead. After 3,000 failed attempts (C), one succeeded. The attacker then loaded malware from a temporary directory (D) to establish persistence.

**SECTION E:**
19. (5 pts) Immediate response (next 5 minutes):
1. Declare critical incident — notify management, security team, IT operations
2. Use EDR to remotely isolate all 13 affected systems from the network
3. Block the Group Policy object that deployed the ransomware
4. Preserve forensic evidence before anyone takes additional actions
5. Begin damage assessment: how many total systems at risk? How many encrypted?

**SECTION F:**
20. (2 pts) "Alert when EventID 4769 (Kerberos service ticket requests) appears more than 30 times from the same user within 5 minutes, AND the requests are all for different service accounts AND encryption type is RC4."

21. (2 pts) "Alert when the same user logs in successfully from two geographically distant locations within 15 minutes AND the distance is impossible to travel in that time."

**SECTION G:**
22. (2 pts) EventID 1102 (log cleared) is itself a logged event. It proves that logs were intentionally cleared and tells you the account that cleared them. This gives you evidence of cover-up activity. However, if ALL logs are cleared, you lose the history — which is why off-system logging (SIEM collection) is critical.

23. (2 pts) Three key metrics: (1) Number of affected patients (required for HIPAA breach notification threshold of 500+), (2) Type of data stolen (PHI, financial, etc.), (3) Date range of affected data (what period of patient records were compromised).

**SECTION H:**
24. NT LAN Manager
25. Ticket Granting Ticket (issued by the KDC, used to get service tickets)
26. Which mail servers are authorized to send email for a domain
27. 10.0.0.1 and 192.168.5.50 are private; 8.8.8.8 and 185.220.101.47 are public
28. Security Information and Event Management

**SECTION I:**
29. (3 pts) Five post-access techniques:
- Privilege escalation (attempt to gain admin/root)
- Lateral movement (access other systems via file shares, RDP, SMB)
- Persistence (create backdoors, scheduled tasks, new accounts)
- Data exfiltration (copy sensitive files to external server)
- Defense evasion (disable antivirus, delete logs, cover tracks)

30. (3 pts) Top 3 healthcare risks and mitigations:
- Patient data breach (PHI): Implement DLP, encrypt databases, limit access to only necessary staff, audit access logs
- Ransomware (threatens patient care): Immutable off-site backups, EDR, network segmentation, staff training
- Insider threats (staff with access): Principle of least privilege, activity monitoring, regular audits, separation of duties

**SECTION J:**
31. (10 pts) Complete incident report:

**Attack Timeline:**
Friday 22:00 → Phishing email delivered
Friday 22:15 → User clicked phishing link and submitted credentials
Friday 22:15 → Attacker logged into compromised account from Romania
Friday 22:17 → Email forwarding rule created to hide alerts
Saturday 02:00 → 8.2 GB of confidential data downloaded and exfiltrated
Saturday 03:14 → DCSync attack: all AD password hashes stolen
Sunday 04:00 → Ransomware deployed on 7 systems

**Attack Techniques:**
- T1566.002: Phishing: Spearphishing Link
- T1078: Valid Accounts
- T1137.003: Office Application Startup (inbox rule persistence)
- T1003.006: OS Credential Dumping (DCSync)
- T1567: Exfiltration Over Web Service
- T1486: Data Encrypted for Impact

**Impact:**
- Confidential data (8.2 GB) exfiltrated
- All AD password hashes compromised
- 7 systems encrypted (ransomware)
- Potential access to hundreds more systems via compromised AD hashes

**Root Causes:**
- DMARC p=none allowed phishing email delivery
- MFA trusted location misconfiguration
- No alerting on new inbox rules
- No DLP on sensitive file downloads
- No DCSync detection

**Immediate Response (24 hours):**
1. Isolate all 7 encrypted systems
2. Disable mark.davis account
3. Block Romanian IP at firewall
4. Delete malicious inbox rule
5. Preserve forensic evidence
6. Begin mandatory password reset for all domain accounts
7. Rotate KRBTGT twice
8. Notify legal/compliance (potential data breach)

**Remediation:**
- Short: Rebuild encrypted systems, reset all passwords, re-enroll MFA
- Medium: Fix DMARC (p=reject), remove MFA trusted location exceptions, implement email sandboxing
- Long: Deploy immutable backups, implement AD tiering, require MFA on all accounts, implement DLP

**Recommendations:**
1. DMARC p=reject (prevents phishing email delivery)
2. No MFA exceptions for any user
3. Conditional access: block login from high-risk countries
4. Alert on inbox rule creation (immediate notification)
5. DLP: alert on large downloads of sensitive data
6. EDR: alert on shadow copy deletion (pre-ransomware indicator)
7. Network segmentation: isolate critical systems
8. Immutable backups: prevent ransom leverage
9. Kerberos ticket requests (RC4, high volume) should alert
10. Privilege auditing: DCSync should only be run by DCs

---

## GRADING SCALE

90-100: Expert SOC Analyst ready for day 1
80-89: Proficient analyst — strong fundamentals
70-79: Passing — ready to work with supervision
Below 70: Needs review — recommend additional study

---

## WHAT'S NEXT?

If you pass this exam (70+):
- You are ready to work as a SOC Tier 1 analyst
- You can triage alerts, identify true positives, and escalate confidently
- You understand protocols, logs, and attack techniques
- Continue learning: Tier 2 skills, threat hunting, OSINT, malware analysis

**Congratulations on completing the SOC Analyst Training Program.**
