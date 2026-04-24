# Scenario Labs — Level 4: Full SOC Simulation

**Purpose:** Experience a real SOC investigation from first alert to full incident report.
**Difficulty:** Expert
**Skills:** Complete investigation, timeline building, multi-source correlation, incident classification, response recommendations.

---

## SITUATION BRIEF

**Time:** Monday, 2024-03-18, 09:00 AM
**You are:** Tier 1 SOC Analyst, starting your day shift
**Organization:** MedTech Solutions (healthcare technology, HIPAA-regulated, 800 employees)

Your shift lead says: "We got some alerts over the weekend. Several things fired at different times and nobody investigated them yet. See what you can piece together."

You have access to: SIEM (Microsoft Sentinel), EDR (Defender for Endpoint), Firewall logs, Proxy logs, DNS logs, Azure AD logs, M365 audit logs.

**Work through each alert in chronological order and build the complete picture.**

---

## ALERT 1 — Friday 2024-03-15T14:22:00Z

**SIEM Alert: "Phishing Email Detected — Low Confidence"**

```
Email Security:
  From: helpdesk@medtech-it-support.com  
  To: amy.zhang@medtech.com
  Subject: IT Security Update - Password Reset Required
  URL: https://medtech-it-support.com/reset
  SPF: Pass (for medtech-it-support.com)
  DKIM: Pass (for medtech-it-support.com)
  DMARC: Fail (medtech-it-support.com ≠ medtech.com)
  URL Category: Newly registered domain (3 days old)
  AV: Clean
  Action: Delivered (DMARC policy = none)
```

**WHOIS for medtech-it-support.com:**
```
Registered: 2024-03-12 (3 days before this email)
Registrant: Privacy Protected
Name Server: ns1.namecheap.com
```

**Your Task — Alert 1:**
- Is this a true positive or false positive?
- What is the risk?
- What do you do?

---

## ALERT 2 — Friday 2024-03-15T14:45:00Z

*23 minutes after Alert 1*

**SIEM Alert: "User Visited Suspicious URL"**

```
Proxy Log:
  Time: 2024-03-15T14:45:12Z
  User: amy.zhang@medtech.com
  Source: 192.168.5.44 (LAPTOP-AZHANG)
  Method: GET
  URL: https://medtech-it-support.com/reset
  Response: 200
  Bytes: 38,492
  
  Time: 2024-03-15T14:45:30Z
  User: amy.zhang@medtech.com
  Source: 192.168.5.44
  Method: POST
  URL: https://medtech-it-support.com/reset
  Response: 302 (Redirect)
  Bytes Sent: 284 (form submission)
```

**Azure AD Log (same time):**
```
2024-03-15T14:45:35Z
  Sign-in type: UserLogin
  User: amy.zhang@medtech.com
  Result: Success
  IP: 185.220.101.47  ← Different IP than Amy's normal source!
  Device: Unknown
  Location: Romania
  Risk: High
  MFA: Not prompted (Trusted location exception — misconfigured)
```

**Your Task — Alert 2:**
- Connect this to Alert 1. What just happened?
- Is Amy's account compromised?
- Why was MFA not prompted?
- What are your immediate actions?

---

## ALERT 3 — Friday 2024-03-15T14:47:00Z

*2 minutes after Alert 2*

**SIEM Alert: "Suspicious Inbox Rule Created"**

```
M365 Audit Log:
  Time: 2024-03-15T14:47:03Z
  Operation: New-InboxRule
  User: amy.zhang@medtech.com
  IPAddress: 185.220.101.47
  RuleName: "Archive - IT"
  Conditions: Subject contains "security" OR "password" OR "compromise" OR "alert" OR "suspicious"
  Actions: Delete immediately
```

**Your Task — Alert 3:**
- What is this inbox rule designed to do?
- How does this connect to Alerts 1 and 2?
- What is the attacker trying to achieve with this rule?

---

## ALERT 4 — Saturday 2024-03-16T02:00:00Z

*11 hours after initial compromise*

**SIEM Alert: "Unusual SharePoint Access — High Volume"**

```
M365 Audit Log (02:00-02:15 AM):
  User: amy.zhang@medtech.com
  IP: 185.220.101.47
  
  FileDownloaded: /sites/MedTech/PatientRecords/BatchData-Q1-2024.csv (2.1 GB)
  FileDownloaded: /sites/MedTech/PatientRecords/PatientDB-Export-2024.csv (4.8 GB)  
  FileDownloaded: /sites/MedTech/Finance/Insurance-Billing-Q1.xlsx (842 MB)
  FileDownloaded: /sites/MedTech/HR/Employee-PHI-Records.xlsx (124 MB)
  FileDownloaded: /sites/MedTech/Legal/Contracts-Active-2024.zip (2.4 GB)
  
  Total: 5 files, 10.3 GB in 15 minutes
```

**Firewall Log:**
```
2024-03-16T02:16:00Z to 02:58:00Z
  Source: 185.220.101.47
  Destination: 185.220.101.47 (same — attacker's server)  
  Actually: Source 192.168.5.44 → Destination 185.220.101.47:443
  Bytes: 10,824,134,656 (10.3 GB)
  Duration: 42 minutes
```

**Your Task — Alert 4:**
- What happened?
- Why is this particularly serious for a healthcare organization?
- What regulations are implicated?

---

## ALERT 5 — Saturday 2024-03-16T03:14:00Z

*1 hour after Alert 4*

**SIEM Alert: "Credential Harvesting — DCSync Indicators"**

```
Windows Security Log (DC01):
  2024-03-16T03:14:22Z  EventID 4662
  Subject: amy.zhang@medtech.com
  Computer: LAPTOP-AZHANG (via remote connection)
  Object Type: Directory Service
  Access: Control Access
  Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} DS-Replication-Get-Changes-All
  Source IP: 192.168.5.44
```

**Your Task — Alert 5:**
- What is DCSync?
- What does the attacker have now?
- How does amy.zhang (a regular user) have permission to run DCSync? What does this tell you?

---

## ALERT 6 — Sunday 2024-03-17T04:00:00Z

*25 hours after Alert 5*

**EDR Alert: "Ransomware Behavior Detected" (CRITICAL)**

```
EDR Alerts across 14 systems simultaneously:
  Process: C:\Windows\Temp\windefend32.exe
  Parent: taskeng.exe (Task Scheduler)
  Actions:
    vssadmin.exe delete shadows /all /quiet
    bcdedit.exe /set {default} recoveryenabled no
    wbadmin delete backup -keepVersions:0 -quiet
    [mass file modification: .docx → .docx.medtech, .pdf → .pdf.medtech, etc.]
    [ransom note creation: DECRYPT_INSTRUCTIONS.html on all desktops]
```

**Windows Events:**
```
2024-03-17T03:59:50Z  EventID 4698  (on DC01)
  Actor: amy.zhang (compromised account)
  Task Name: \Microsoft\Windows\WindowsUpdate\WinUpdateSvc
  Action: C:\Windows\Temp\windefend32.exe
  Trigger: At 04:00:00, run on all computers (via domain-wide scheduled task)
```

**Your Task — Alert 6:**
- What is happening?
- How did the ransomware deploy on all systems simultaneously?
- The ransomware only appears on 14 of 800 computers. Why might this be?

---

## YOUR FINAL INVESTIGATION REPORT

Write a complete incident report including:

**Section 1: Incident Summary** (2-3 sentences)
**Section 2: Timeline of Events** (chronological)
**Section 3: Attack Techniques Used** (MITRE ATT&CK)
**Section 4: Impact Assessment**
**Section 5: Immediate Response Actions**
**Section 6: Remediation Steps**
**Section 7: Recommendations to Prevent Recurrence**

---

## COMPLETE ANSWER KEY

**Alert 1 Analysis:**
TRUE POSITIVE (Phishing). Red flags: medtech-it-support.com ≠ medtech.com; 3-day-old domain; DMARC fail; privacy-protected registration; asks for password reset. Actions: Remove email from all inboxes. Block the domain. Call Amy directly to warn her. Check if she clicked the link.

**Alert 2 Analysis:**
Amy was phished. She clicked the link (GET request) and submitted her credentials (POST request with 284 bytes — username and password). The attacker immediately used the stolen credentials to log in from Romania (success at 14:45:35). MFA was not prompted because of a misconfigured "trusted location" exception. Amy's account is fully compromised. Immediate actions: Disable Amy's account. Invalidate all sessions. Remove the trusted location exception. Block 185.220.101.47. Contact Amy via phone.

**Alert 3 Analysis:**
The attacker created an inbox rule to delete all security-related emails. Purpose: hide the compromise notification emails (password change confirmations, security alerts, unusual login notifications) from Amy so she does not realize her account was hacked. This buys the attacker time to operate undetected.

**Alert 4 Analysis:**
The attacker (using Amy's account) downloaded 10.3 GB of highly sensitive data including patient records (PHI — Protected Health Information), financial data, HR records, and legal contracts. For a HIPAA-regulated healthcare organization, this is a DATA BREACH. HIPAA requires:
- Notification to affected patients within 60 days
- Notification to HHS (Department of Health and Human Services)
- If 500+ patients affected: notification to media
- Potential fines: $100-$50,000 per violation, up to $1.9M per violation category
This is now a HIPAA breach incident with regulatory reporting requirements.

**Alert 5 Analysis:**
DCSync attack — Amy's account (now used by the attacker) is requesting directory replication rights to pull all password hashes from Active Directory. Regular users cannot run DCSync — this requires special permissions (DS-Replication-Get-Changes-All). This tells you: either (1) Amy was improperly given domain replication rights, or more likely (2) the attacker has already escalated privileges before this event (perhaps through a technique not captured in our logs). The attacker now has all password hashes for all 800 employees, all service accounts, and the KRBTGT hash — complete domain compromise.

**Alert 6 Analysis:**
Ransomware deployment. The attacker (using the compromised Amy.zhang domain admin credentials they escalated to) created a domain-wide scheduled task 5 minutes before the ransomware fired. The task ran on all computers via Group Policy / domain join. The ransomware only appeared on 14 systems because: either (1) EDR blocked it on the other 786 computers, or (2) the ransomware was deployed in a test batch first, or (3) only 14 computers were online at 4 AM Sunday. EDR detected and (partially) stopped it on other systems.

**Complete Investigation Report:**

Section 1 — Incident Summary:
MedTech Solutions experienced a complete ransomware attack that began with a credential phishing attack targeting employee amy.zhang@medtech.com on Friday March 15 at 2:22 PM. The attacker escalated from a compromised user account to domain administrator access over 36 hours, exfiltrated 10.3 GB of protected health information and sensitive business data, and deployed ransomware across the domain Sunday morning at 4:00 AM. This constitutes a HIPAA breach requiring regulatory notification.

Section 2 — Timeline:
```
15-Mar 14:22 — Phishing email delivered from medtech-it-support.com (fake domain, 3 days old)
15-Mar 14:45 — amy.zhang clicked link and submitted credentials to phishing site
15-Mar 14:45 — Attacker logged into Amy's account from Romania (185.220.101.47)
15-Mar 14:47 — Attacker created inbox rule to delete security alert emails
15-Mar-15 to 16-Mar-03 — [Escalation period — requires further investigation]
16-Mar 02:00 — Attacker downloaded 10.3 GB: patient records, financial, HR, legal data
16-Mar 02:16 — Exfiltration of 10.3 GB to attacker's server (42 minutes)
16-Mar 03:14 — DCSync attack: all Active Directory password hashes extracted
17-Mar 03:59 — Domain-wide scheduled task created to deploy ransomware at 4:00 AM
17-Mar 04:00 — Ransomware deployed on 14 systems, file encryption began
```

Section 3 — MITRE ATT&CK:
T1566.002 — Phishing: Spearphishing Link
T1078 — Valid Accounts
T1137.003 — Office Application Startup: Outlook Rules (inbox rule for persistence)
T1567 — Exfiltration Over Web Service
T1003.006 — OS Credential Dumping: DCSync
T1053.005 — Scheduled Task/Job: Scheduled Task
T1486 — Data Encrypted for Impact (Ransomware)
T1490 — Inhibit System Recovery (shadow copy deletion)

Section 4 — Impact:
Patient PHI (Protected Health Information): Minimum 2 CSV exports of patient records. Quantity of affected patients: UNKNOWN — must be determined urgently for HIPAA notification.
Financial data: Q1 billing data (potential PCI-DSS implications for payment data)
Business data: Legal contracts, HR records
Systems encrypted: 14 confirmed, 800 potentially at risk
HIPAA breach: Confirmed — reporting required within 60 days to HHS and patients

Section 5 — Immediate Response:
1. Isolate all 14 encrypted systems from network via EDR
2. Disable amy.zhang's account and all accounts whose passwords were potentially stolen (DCSync = ALL accounts)
3. Block 185.220.101.47 at firewall
4. Delete the malicious domain-wide scheduled task from DC01
5. Rotate KRBTGT password TWICE (invalidates Golden Tickets)
6. Begin emergency password reset for ALL domain accounts
7. Preserve forensic evidence before remediation
8. Engage incident response firm for HIPAA breach response
9. Notify legal and compliance teams immediately
10. Do NOT pay ransom without legal/executive approval

Section 6 — Remediation:
Short term: Rebuild the 14 infected systems. Restore from last known good backup. Change all passwords. Re-enroll all MFA. Review and revoke excessive privileges.
Medium term: Remove trusted location exception for MFA. Implement DMARC enforcement (p=reject). Deploy email sandboxing for attachments/links.
Long term: Full AD tiering (admin accounts separate from user accounts). Privileged Access Workstations for domain admin tasks. Immutable off-site backups. Purple team exercise to test detection capabilities.

Section 7 — Recommendations:
1. DMARC enforcement (p=reject) — would have stopped the initial phishing email
2. MFA without exceptions — no trusted location bypasses for regular users
3. Conditional access: block authentication from high-risk countries
4. Alerting on new inbox rules — immediate alert when any user creates an inbox forwarding rule
5. Data loss prevention: alert on downloads >1 GB from SharePoint
6. Alert on DCSync (Event ID 4662 with replication GUID) — this should fire Critical immediately
7. Principle of least privilege — regular users should not be able to access all SharePoint sites
8. Immutable backups — the ransom demand would be moot with reliable backups
9. Security awareness training — focused on credential phishing
10. HIPAA training — all employees must know PHI handling requirements
