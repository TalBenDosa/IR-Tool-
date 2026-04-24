# Lesson 4.4 — Kerberos and NTLM — Deep Dive

**Phase:** 4 — Protocols
**Prerequisite:** Lesson 4.3
**Time to complete:** 50 minutes

---

## Why Authentication Protocols Matter

Kerberos and NTLM are the two authentication protocols used in Windows environments. They answer the fundamental question: "How does one computer prove to another that it is who it claims to be?"

These protocols are at the heart of almost every advanced Active Directory attack. Kerberoasting, Pass-the-Hash, Pass-the-Ticket, Golden Ticket, Silver Ticket, DCSync — all of these attacks target either Kerberos or NTLM.

Understanding these protocols deeply is what separates a competent SOC analyst from a beginner.

---

# PART A: NTLM — NT LAN Manager

## What Is NTLM? (Simple)

NTLM is an older Windows authentication protocol. It is a challenge-response protocol — meaning it proves identity through a series of cryptographic challenges rather than sending the actual password.

NTLM is a fallback when Kerberos cannot be used:
- Authenticating with IP addresses (not hostnames)
- Authenticating to systems not joined to a domain
- When Kerberos infrastructure is unavailable

---

## How NTLM Works (Step by Step)

1. Client sends a Negotiate message: "I want to authenticate. Here's what I support."

2. Server sends a Challenge: "Prove who you are. Here's a random 64-bit challenge value."

3. Client calculates a response:
   - Takes the user's NTLM hash (MD4 hash of the password)
   - Encrypts the challenge with this hash
   - Sends the result to the server (the "response")

4. Server forwards to Domain Controller (if domain-joined):
   The server sends the username, challenge, and response to the DC.
   
5. Domain Controller verifies:
   DC looks up the stored NTLM hash for this user.
   DC encrypts the same challenge with the stored hash.
   If the result matches the client's response → authentication success.

6. Server receives confirmation from DC → grants access.

### The Critical Weakness: The Hash IS the Password

In NTLM, the hash of the password is what proves your identity. This means:
If an attacker steals your password hash, they can authenticate as you — without ever knowing your actual password.

This is the basis of Pass-the-Hash attacks.

---

## NTLM Hashes — What They Look Like

The NTLM hash is the MD4 hash of the Unicode password.

Password: "Password123"
NTLM hash: 8846F7EAEE8FB117AD06BDD830B7586C

Password: "Winter2024!"
NTLM hash: B7E9C22FCDB00D0C3B9AB07B9BEE6B9E

Where NTLM hashes are stored:
- SAM database (C:\Windows\System32\config\SAM) — local accounts on each machine
- NTDS.dit file on Domain Controllers — ALL domain account hashes
- LSASS.exe process memory — hashes of recently logged-in accounts (in memory!)

Mimikatz:
The tool most commonly used to extract hashes from LSASS memory.
```
mimikatz # sekurlsa::logonpasswords
[output shows usernames, domains, NTLM hashes for all logged-in users]
```
This is one of the most dangerous capabilities an attacker can use — once they have admin access, they dump all hashes and can authenticate as anyone.

---

## NTLM Relay Attacks

NTLM Relay does not need to crack the hash — it relays it in real-time.

Attack flow:
1. Attacker sets up a rogue server that accepts NTLM authentication.
2. Victim's computer is tricked into authenticating to the attacker's rogue server (via phishing, UNC path injection, etc.).
3. Attacker receives the NTLM challenge-response from the victim.
4. Attacker simultaneously relays this to the real target server.
5. Target server authenticates the attacker as the victim.

Result: Attacker has access to the target server with the victim's credentials — without knowing the password or even the hash.

Tools: Responder, ntlmrelayx (from Impacket)

Detection:
- NTLM authentication from unexpected source IPs
- Authentication to unusual resources
- Event ID 4624 with unusual authentication package "NTLM" where Kerberos would be expected
- Multiple failed NTLM authentications followed by a success

---

## NTLM in Logs

Windows Security Event ID 4776 — NTLM Authentication:
```
EventID: 4776
Time: 2024-03-15 03:22:14
Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0
Logon Account: john.smith
Source Workstation: LAPTOP-JSMITH
Error Code: 0x0 (Success)
```

When Error Code is NOT 0x0:
0xC000006A — Wrong password (bad password)
0xC0000064 — User name does not exist
0xC000006D — General authentication failure
0xC0000234 — Account is locked out

Multiple 4776 events with error codes = NTLM brute force.

---

# PART B: Kerberos — The Modern Windows Authentication Protocol

## What Is Kerberos? (Simple)

Kerberos is the primary authentication protocol in Active Directory domains. It is named after the three-headed dog guarding the underworld in Greek mythology — because it involves three parties: the client, the server, and a trusted third party (the Key Distribution Center).

Think of Kerberos like a theme park ticketing system:
1. You arrive at the park entrance (KDC) and show your ID. You get a day pass (TGT).
2. Your day pass lets you get ride tickets (service tickets) from a ticket booth without showing ID again.
3. You show your ride ticket to enter each attraction (service).
The benefit: You only prove your identity once. After that, tickets handle everything.

---

## How Kerberos Works (Complete Flow)

### The Three Parties

KDC (Key Distribution Center):
The trusted authority — runs on the Domain Controller.
Has two components:
- AS (Authentication Service) — issues Ticket Granting Tickets (TGTs)
- TGS (Ticket Granting Service) — issues service tickets

Client: The user's computer.
Service: The resource being accessed (file server, email, application).

### Step-by-Step Flow

Step 1 — AS-REQ (Authentication Request):
User logs in. Client sends username to the KDC's AS.
```
Client → KDC/AS: "Hello, I'm john.smith. I need a TGT."
```

Step 2 — AS-REP (Authentication Response):
KDC verifies the user exists.
KDC sends back:
- A TGT (Ticket Granting Ticket) — encrypted with the KDC's secret key (only KDC can read it)
- A session key — encrypted with the user's password hash
```
KDC/AS → Client: Here is your TGT [encrypted] and session key [encrypted with your password hash]
```
The client can only decrypt the session key (they know their password). They cannot read the TGT — it is opaque to them.

Step 3 — TGS-REQ (Ticket Granting Service Request):
Client needs to access a service (e.g., \\fileserver01\shared).
Client presents the TGT to the KDC's TGS.
```
Client → KDC/TGS: "I have my TGT. Please give me a ticket for \\fileserver01\shared."
```

Step 4 — TGS-REP (Ticket Granting Service Response):
KDC decrypts the TGT (only it can), verifies it is valid.
KDC issues a service ticket encrypted with the service account's password hash.
```
KDC/TGS → Client: Here is your service ticket for fileserver01 [encrypted with fileserver01's service account key]
```

Step 5 — AP-REQ (Application Request):
Client presents the service ticket to the service.
```
Client → Service: "I have a ticket from the KDC for you."
```

Step 6 — Service Validates:
Service decrypts the ticket with its own secret key.
If valid, access is granted.

The genius of Kerberos: The user's password is never sent over the network. Only a timestamp encrypted with the password hash is sent in AS-REQ.

---

## Kerberos Tickets

TGT (Ticket Granting Ticket):
- Issued by the AS after successful login
- Valid for typically 10 hours (configurable)
- Encrypted with the KDC's master key (krbtgt account hash)
- Opaque to the client — they cannot read its contents
- Presented to get service tickets

Service Ticket (ST) / TGS:
- Issued by the TGS for a specific service
- Encrypted with the service account's hash
- Contains: user identity, authorization data, timestamp, session key
- Valid for typically 10 hours

PAC (Privilege Attribute Certificate):
- Embedded inside tickets
- Contains user's group memberships, privileges
- Services check PAC to know what access to grant
- PAC validation is crucial — forged PACs enable privilege escalation

---

## Kerberos Attacks — The Most Important AD Attacks

### 1. Kerberoasting

Concept:
Any domain user can request a service ticket for any service account.
Service tickets are encrypted with the service account's password hash.
If the service account has a weak password, the hash can be cracked offline.

Attack flow:
1. Attacker requests service tickets for all service accounts with SPNs (Service Principal Names).
2. Attacker receives service tickets encrypted with each service account's hash.
3. Attacker takes the tickets offline and runs cracking tools (Hashcat, John the Ripper).
4. If the service account has a weak password, attacker recovers the plaintext password.
5. Attacker uses the service account credentials directly.

Why this is dangerous:
Service accounts often have high privileges. They are used for running critical services. Organizations often give them Domain Admin rights "just to be safe." If cracked, the attacker gains domain admin.

Windows Event ID 4769 — Kerberos service ticket requested:
```
EventID: 4769
Time: 2024-03-15 14:22:14
Account Name: john.smith@COMPANY.COM
Service Name: MSSQLSVC/sqlserver01.company.com
Service ID: COMPANY\sql-service-account
Ticket Encryption Type: 0x17 (RC4-HMAC)  ← This is the vulnerable type
Client Address: 192.168.1.55
```
A large number of 4769 events requesting tickets with RC4-HMAC encryption from one user in a short time = Kerberoasting.

Normal: A user requests 2-3 service tickets per day.
Kerberoasting: A user requests 50 service tickets in 2 minutes.

### 2. AS-REP Roasting

Similar to Kerberoasting but targets accounts that have "Do not require Kerberos preauthentication" enabled.

Normally, the AS-REQ includes a timestamp encrypted with the user's hash — this proves the user knows their password before the KDC issues a TGT.

For accounts with preauthentication disabled, the KDC sends the TGT and session key without verifying identity. The session key is encrypted with the user's hash. The attacker can try to crack this hash offline.

Event ID 4768 — Kerberos TGT requested:
```
EventID: 4768
Preauth Type: 0  ← 0 means preauthentication was NOT required
Account Name: svc-backup
```

### 3. Pass-the-Ticket (PtT)

Similar to Pass-the-Hash but for Kerberos tickets.

The attacker steals a Kerberos ticket from memory (using Mimikatz) and uses it to authenticate.

```
mimikatz # sekurlsa::tickets /export
```
Exports all Kerberos tickets from LSASS memory.

```
mimikatz # kerberos::ptt [ticket]
```
Injects a stolen ticket into the current session.

Result: Attacker uses the victim's valid ticket to access resources they are authorized for.

### 4. Golden Ticket Attack

The most powerful Kerberos attack. If an attacker has the NTLM hash of the KRBTGT account (the special Kerberos account that signs all TGTs), they can forge TGTs for ANY user with ANY privileges.

What they need: KRBTGT hash (from DCSync or direct DC compromise)
What they can do: Create a TGT claiming to be ANY user (including Domain Admin), valid for any duration, with any group memberships.

This is called "Golden Ticket" because:
- It is as valuable as gold
- A forged TGT can grant access to everything
- It can be valid for years
- Even after a password reset of the actual user, the ticket works until KRBTGT hash is rotated

Detection:
- Service tickets created without a corresponding TGT request (the forged TGT was never logged)
- Event ID 4769 with tickets having unusual lifetimes or encryption types
- Event ID 4672 (Special Privileges Assigned) for unexpected accounts
- Tickets with attributes inconsistent with what AD would generate

Response: Rotate KRBTGT password TWICE (to invalidate all existing tickets).

### 5. Silver Ticket Attack

Attacker has the hash of a SERVICE account (not KRBTGT).
They forge a service ticket for that specific service.
No communication with the DC is needed — the forged ticket is presented directly to the service.
Less powerful than Golden Ticket (only works for one service) but harder to detect (no DC communication).

Detection: PAC validation enabled on services catches forged tickets. Monitor for service tickets with unusual attributes.

### 6. DCSync Attack

Attacker mimics the behavior of a Domain Controller replication.
DCs replicate their data (including password hashes) using DRSUAPI.
An attacker with Domain Admin rights (or replication rights) can pretend to be a DC and request all password hashes.

```
mimikatz # lsadump::dcsync /domain:company.com /all /csv
```
This dumps all password hashes from Active Directory — every account in the domain.

Detection:
Event ID 4662 — Operation was performed on an object:
```
EventID: 4662
Object Type: %{19195a5b-6da0-11d0-afd3-00c04fd930c9}  ← Directory Service Access
Access: Control Access
Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  ← DS-Replication-Get-Changes-All
Subject: john.smith  ← Should be a DC, not a regular user!
```
If a non-DC account triggers replication rights events → DCSync attack.

---

## Kerberos in Logs — Summary of Key Event IDs

4768 — TGT was requested (AS-REQ → AS-REP)
4769 — Service ticket was requested (TGS-REQ → TGS-REP)
4770 — Service ticket was renewed
4771 — Kerberos pre-authentication failed (wrong password or bad ticket)
4772 — Kerberos authentication ticket request failed
4776 — NTLM authentication (fallback from Kerberos)

Alert-worthy patterns:
- 4769 with RC4-HMAC encryption in large quantities = Kerberoasting
- 4768 with preauth type 0 = AS-REP Roasting target
- 4769 for service tickets without corresponding 4768 = possible Golden Ticket
- 4662 with replication rights from non-DC = DCSync

---

## Summary

NTLM: Challenge-response authentication. Hash IS the password. Vulnerable to Pass-the-Hash, NTLM Relay, hash cracking.
Kerberos: Ticket-based authentication. Three parties: Client, KDC, Service. Uses TGTs and service tickets.
Kerberoasting: Request service tickets, crack the hash offline. Target: service accounts with weak passwords.
Pass-the-Ticket: Steal and use Kerberos tickets from memory.
Golden Ticket: Forge TGTs using KRBTGT hash — total domain compromise.
DCSync: Steal all password hashes by pretending to be a Domain Controller.

---

## Practice Questions

**Easy:**
1. What is the difference between NTLM and Kerberos?
2. What is a TGT and how is it used?
3. What is Pass-the-Hash?

**Medium:**
4. You see 47 Event ID 4769 events from user john.smith in 90 seconds, all with encryption type 0x17 (RC4-HMAC). What attack is this? What is the attacker trying to do?
5. What is DCSync and why is it so dangerous? What event ID would you look for to detect it?

**Thinking Questions:**
6. An attacker has compromised a workstation and extracted the NTLM hash of a service account called "svc-sql". The service account is a member of "Domain Admins". The attacker cannot crack the hash. How can they still use this to gain domain admin access?
7. A Golden Ticket attack is performed against your organization. The attacker generated a ticket valid for 10 years. Your incident response team resets the compromised user's password. Is the organization now safe? What must be done and why?
