# Phase 4 Quiz — Protocols Deep Dive (Mid-Course Test)

**Time limit:** 45 minutes
**Total questions:** 25
**Passing score:** 20/25

This quiz covers all protocols from Phase 4. It also serves as the MID-COURSE TEST.

---

## Section A — Multiple Choice (1 point each)

**Question 1:**
Which DNS record type is used to identify mail servers for a domain?

A) A record
B) CNAME record
C) MX record
D) TXT record

---

**Question 2:**
A computer generates 500 DNS queries per minute, all returning NXDOMAIN, to domains like "xjkqrp19.com", "qzxkjmn47.net". What is most likely occurring?

A) DNS cache poisoning
B) DGA malware looking for its C2 server
C) DNS tunneling exfiltrating data
D) A legitimate DNS health check

---

**Question 3:**
Which HTTP status code indicates successful authentication has occurred after previous 401 responses?

A) 200 OK
B) 302 Found
C) 403 Forbidden
D) 204 No Content

---

**Question 4:**
In an HTTP proxy log, you see: User-Agent: "python-requests/2.28.0" making POST requests every 3 minutes. What does this user-agent indicate?

A) Google Chrome on Windows
B) An automated script or tool, not a web browser
C) Microsoft Internet Explorer
D) A mobile browser on iOS

---

**Question 5:**
SMBv1 is dangerous primarily because:

A) It is slower than SMBv2
B) It uses UDP instead of TCP
C) It is unauthenticated by default
D) It has critical vulnerabilities including EternalBlue that allow remote code execution without credentials

---

**Question 6:**
In Kerberoasting, what does the attacker request?

A) TGTs for all domain users
B) Service tickets (TGS) for service accounts to crack their hashes offline
C) The KRBTGT hash from the Domain Controller
D) NTLM hashes from LSASS memory

---

**Question 7:**
What makes a Golden Ticket attack uniquely dangerous?

A) It targets the web application layer
B) It uses the KRBTGT hash to forge TGTs for any user with any privileges, valid for any duration
C) It allows complete network packet interception
D) It only works against unpatched systems

---

**Question 8:**
SPF (Sender Policy Framework) checks:

A) The digital signature of the email body
B) Whether the email was modified in transit
C) Whether the sending server IP is authorized to send email for the MAIL FROM domain
D) Whether the From: header domain matches the Reply-To: domain

---

**Question 9:**
A DMARC policy of "p=reject" means:

A) Log and monitor emails that fail checks
B) Send failing emails to the junk/spam folder
C) Reject emails that fail both SPF and DKIM alignment checks
D) Accept all emails regardless of SPF/DKIM results

---

**Question 10:**
SSH public key authentication is more secure than password authentication because:

A) It encrypts the password before sending
B) The private key never leaves the client — authentication is proved cryptographically without sending secrets
C) It requires a 2048-character minimum password
D) It uses NTLM instead of plaintext authentication

---

## Section B — True or False (1 point each)

**Question 11:**
In Pass-the-Hash, the attacker must crack the password hash to authenticate.

True / False

---

**Question 12:**
HTTPS traffic encrypts the URL path, meaning a SOC analyst with no SSL inspection cannot see which specific pages were visited — only the destination IP or SNI hostname.

True / False

---

**Question 13:**
A DKIM signature validates that the From: header domain matches the sending server's IP address.

True / False

---

**Question 14:**
FTP sends usernames and passwords in plaintext over the network.

True / False

---

**Question 15:**
In Kerberos, the TGT is encrypted with the KRBTGT account's hash. This is why stealing the KRBTGT hash enables a Golden Ticket attack.

True / False

---

## Section C — Log Analysis (2 points each)

**Question 16:**
Analyze this email header excerpt:
```
Received: from unknown-host (185.220.101.47 [185.220.101.47])
From: "CEO - John Smith" <john.smith@company.com>
Authentication-Results:
    spf=fail smtp.mailfrom=company.com
    dkim=fail header.d=company.com  
    dmarc=fail action=reject header.from=company.com
Subject: URGENT: Wire Transfer Required Today
```
What is happening? Is this email legitimate? What are all the indicators of compromise?

---

**Question 17:**
Review these Windows Event ID 4769 entries:
```
14:22:01  User: john.smith  Service: MSSQLSvc/sql01.company.com   EncType: 0x17 (RC4)
14:22:02  User: john.smith  Service: HTTP/webserver.company.com   EncType: 0x17 (RC4)
14:22:03  User: john.smith  Service: CIFS/fileserver.company.com  EncType: 0x17 (RC4)
14:22:04  User: john.smith  Service: HOST/dc01.company.com         EncType: 0x17 (RC4)
[43 more requests from john.smith in 60 seconds]
```
What attack is occurring? What is john.smith doing? What should you investigate?

---

**Question 18:**
Proxy log entry:
```
Time: 03:15:00  Source: 192.168.2.77  
GET http://185.220.101.47/gate.php?id=WORKSTATION-KWILSON&status=idle
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)
Response: 200  Bytes: 8

[Repeated every 5 minutes for 72 hours]
```
Identify everything suspicious. What is the computer doing?

---

**Question 19:**
```
Mar 15 03:22:14 webserver ftpd: USER root: Login OK
Mar 15 03:22:15 webserver ftpd: STOR /var/www/html/images/shell.php: 4096 bytes
Mar 15 03:22:22 webserver access.log: 185.220.101.47 GET /images/shell.php?cmd=id 200 18
Mar 15 03:22:25 webserver access.log: 185.220.101.47 GET /images/shell.php?cmd=cat+/etc/shadow 200 4096
```
What happened in sequence? What was the ultimate goal? How serious is this?

---

**Question 20:**
```
EventID: 4662
Time: 2024-03-15 02:44:22
Object: Domain NC
Access: Control Access
Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} DS-Replication-Get-Changes-All
Subject Account Name: john.smith  (NOT a Domain Controller)
Source IP: 192.168.1.77
```
What attack does this indicate? What does john.smith have access to? What is the immediate risk?

---

## Section D — Short Answer (1 point each)

**Question 21:**
What is the difference between MAIL FROM and the From: header in an email, and why does it matter for phishing detection?

---

**Question 22:**
Why should RDP (port 3389) and SMB (port 445) never be exposed directly to the internet?

---

**Question 23:**
What is DNS tunneling and name two characteristics you would look for in DNS logs to detect it?

---

**Question 24:**
Explain the Kerberos TGT and service ticket flow in simple terms. Why is this design more secure than NTLM?

---

**Question 25:**
An organization's DMARC policy is set to "p=none". What does this mean? Is the organization protected against email spoofing? What should they do?

---

## Answer Key

**Section A:**
1. C — MX record
2. B — DGA malware
3. A — 200 OK after 401 = successful authentication
4. B — Automated script/tool
5. D — EternalBlue RCE vulnerability
6. B — Service tickets for offline cracking
7. B — Forged TGTs using KRBTGT hash
8. C — Authorized sending server for MAIL FROM domain
9. C — Reject emails failing SPF/DKIM alignment
10. B — Private key never leaves the client

**Section B:**
11. False — PtH uses the hash directly, no cracking needed
12. True — Without SSL inspection, only the IP/SNI is visible
13. False — DKIM validates via the d= domain in the DKIM header, not the IP
14. True — FTP is plaintext
15. True — KRBTGT hash signs all TGTs

**Section C:**

16. (2 points) The email is NOT legitimate — it is a phishing/BEC attempt. All three authentication checks (SPF, DKIM, DMARC) failed. The actual sending IP (185.220.101.47) is not authorized to send email for company.com. The From: header displays a legitimate-looking name but the underlying authentication all failed. The subject "URGENT: Wire Transfer" is a classic BEC tactic. The email should be blocked by DMARC (action=reject), but if it reached the user's inbox (e.g., DMARC is p=none), it must be reported and removed. Check if any users responded or transferred funds.

17. (2 points) This is a Kerberoasting attack. John.smith is requesting Kerberos service tickets (TGS, Event ID 4769) for 47+ service accounts in 60 seconds, all using RC4 encryption (0x17). RC4 tickets are weaker and crackable faster than AES tickets. The attacker has the credentials/access of john.smith and is requesting tickets for every service account to crack their passwords offline. Investigation: Is john.smith's account compromised? What service accounts were requested? Do any have privileged access (Domain Admin)? Reset service account passwords for all requested accounts. Investigate how john.smith's account was compromised.

18. (2 points) The computer WORKSTATION-KWILSON is infected with malware performing C2 beaconing. Signs: 3:15 AM start time with no user logged in; URL contains "gate.php" with machine ID and status — classic C2 beacon format; old/fake user-agent (MSIE 9.0 on Windows XP — very suspicious in 2024); response is only 8 bytes (server sending command/ack); perfectly regular 5-minute interval; running for 72 hours. This is an established C2 connection. KWILSON has been infected for at least 72 hours. Immediate isolation required.

19. (2 points) The sequence: (1) Attacker logged into FTP server as root from an external IP. (2) Uploaded "shell.php" to the web-accessible images directory. (3) Immediately accessed the shell via HTTP to run "id" command (verified code execution). (4) Read /etc/shadow — stealing all password hashes. Ultimate goal: privileged access and credential theft. This is a complete webshell installation and exploitation. Extremely serious — attacker has full web server access, all system passwords may be compromised. Immediate response: take the server offline, begin forensics, reset all passwords, identify how attacker got FTP root access.

20. (2 points) This is a DCSync attack. Event ID 4662 with the property GUID for "DS-Replication-Get-Changes-All" indicates that john.smith's account (at 192.168.1.77) is requesting directory replication rights — impersonating a Domain Controller. john.smith now has access to all password hashes in Active Directory. Immediate risk: every domain account's password hash has potentially been exfiltrated. The attacker can perform offline cracking or Pass-the-Hash attacks against any account, including Domain Admins. Required response: change ALL domain account passwords, rotate KRBTGT twice, investigate how john.smith was compromised.

**Section D:**

21. (1 point) MAIL FROM is the actual technical sender (used in the SMTP conversation) and is what SPF checks. The From: header is the display name that users see. These can be different — attackers use a legitimate MAIL FROM (which passes SPF) while displaying a fake From: header that appears to come from a trusted sender. DMARC enforces alignment between these two, closing the gap that SPF alone cannot address.

22. (1 point) Both protocols have critical vulnerabilities (EternalBlue for SMB/WannaCry, BlueKeep for RDP) that allow unauthenticated remote code execution. Both are constantly brute-forced by attackers worldwide. Exposing them directly gives attackers direct network access to internal systems without any gateway or VPN protection.

23. (1 point) DNS tunneling hides data inside DNS queries to bypass firewalls. Detection: unusually long subdomain names (base64 encoded data), high frequency of queries to the same parent domain, unusually large DNS query/response sizes, queries that consistently return NXDOMAIN but keep repeating.

24. (1 point) User logs in → gets a TGT (day pass) from the KDC. When accessing a service, presents TGT to get a service ticket (ride ticket). Presents service ticket to the actual service. This is more secure than NTLM because the password hash is never sent to individual services — only to the DC (KDC) once. Individual services only see a service ticket, not any credential material. NTLM sends a cryptographic function of the hash to every server, increasing the attack surface.

25. (1 point) p=none means DMARC is in monitoring mode — failing emails are delivered normally, only reports are generated. The organization is NOT protected against email spoofing — attackers can successfully spoof the domain and emails will be delivered. They should: first review DMARC reports to understand email sending patterns, ensure SPF and DKIM are properly configured for all legitimate senders, then move to p=quarantine, then p=reject.
