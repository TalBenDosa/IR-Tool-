# Lesson 4.3 — SMB, SSH, RDP, and FTP — Deep Dive

**Phase:** 4 — Protocols
**Prerequisite:** Lesson 4.2
**Time to complete:** 50 minutes

---

# PART A: SMB — Server Message Block

## What Is SMB? (Simple)

SMB is the protocol Windows uses to share files, printers, and other resources over a network.

When you see a "network drive" in Windows (like H:\ mapped to a server), SMB is making that work. When your computer can print to a shared office printer, SMB is involved. When Windows computers communicate in a Windows domain, SMB is often part of it.

SMB runs on port 445 (and historically 137-139 for NetBIOS).

---

## When Is SMB Used?

File sharing — accessing files on another computer or server
Printer sharing — printing to network printers
Inter-process communication — Windows programs talking to each other
Remote administration — tools like PsExec use SMB to run commands on remote computers
Active Directory replication — domain controllers share data via SMB

---

## How SMB Works Behind the Scenes

### SMB Versions

SMBv1 — Obsolete, extremely dangerous. Responsible for the WannaCry ransomware outbreak. NEVER should be enabled. If you see it in use, that is a critical finding.
SMBv2 — Much improved security over v1. Introduced in Windows Vista/Server 2008.
SMBv3 — Current version. Supports encryption. Used in Windows 8/Server 2012 and newer.

### SMB Connection Flow

1. Client connects to server on TCP port 445.
2. SMB Negotiate: Client and server agree on SMB version and capabilities.
3. Session Setup: Authentication occurs.
   - Kerberos (if on a domain) — preferred, uses tickets
   - NTLM — fallback authentication
4. Tree Connect: Client "connects" to a specific share.
   Example: \\server01\files$ or \\192.168.1.10\C$
5. File operations: Create, read, write, delete, list directory.
6. Tree Disconnect, Session Logoff.

### SMB Administrative Shares

Windows automatically creates hidden admin shares (ending with $):
C$ — The C: drive (accessible by administrators)
ADMIN$ — The Windows directory
IPC$ — Inter-process communication (used for remote administration)

Attackers use admin shares to:
- Access files on the target system
- Copy malware to the target
- Execute malware remotely (via PsExec-like tools)

---

## SOC Perspective — SMB Attacks

### EternalBlue (CVE-2017-0144) — Historic but Still Relevant

EternalBlue is an exploit for SMBv1 that allows unauthenticated remote code execution.

This vulnerability was used in:
- WannaCry ransomware (May 2017 — infected 200,000+ systems worldwide)
- NotPetya destructive malware (June 2017)

How it works:
1. Attacker sends a malformed SMBv1 packet to port 445.
2. A buffer overflow vulnerability allows arbitrary code execution.
3. Attacker gains SYSTEM level access — without credentials.

Detection:
- SMBv1 traffic in logs
- Malformed SMB packets (IDS alert)
- Unusual processes spawned immediately after SMB connection

### Pass-the-Hash (PtH)

An attacker can authenticate to SMB using a stolen password hash — without knowing the actual password.

In Windows authentication, the hash of the password is what is actually used during NTLM authentication. If an attacker steals the hash (from memory, from the SAM database), they can use it directly.

Tools: Mimikatz, PsExec with stolen hash, Impacket's psexec.py

Detection:
- Event ID 4624 with Logon Type 3 (network logon) at unusual times
- Authentication from unusual source IPs
- Access to admin shares (C$, ADMIN$) from unexpected accounts

### SMB Lateral Movement

Once inside the network, attackers use SMB to move laterally:

1. Attacker is on Computer A.
2. They use stolen credentials or hashes to authenticate to Computer B via SMB.
3. They access the C$ share or ADMIN$ share.
4. They copy malware to Computer B.
5. They use PsExec (or similar) via SMB to execute the malware on Computer B.
6. Now they are on Computer B. Repeat.

Detection in logs:
```
Source: LAPTOP-JSMITH (192.168.1.55)
Destination: SERVER01 (192.168.10.5)
Port: 445
Share accessed: \\SERVER01\C$
Files created: C:\Windows\Temp\payload.exe
New process: payload.exe
```
Workstation accessing C$ share of a server = suspicious. File dropped into Temp = very suspicious.

### SMB Log Example

Windows Security Event ID 5140 — Network share was accessed:
```
EventID: 5140
Time: 2024-03-15 03:22:14
Subject:
    Account Name: john.smith
    Account Domain: COMPANY
    Logon ID: 0x1C4A29

Share Information:
    Share Name: \\*\C$
    Share Path: C:\
    
Network Information:
    Object Type: File
    Source Address: 192.168.1.55
    Source Port: 54322
```
This shows john.smith accessed the C$ share from 192.168.1.55 at 3:22 AM. Accessing C$ (the entire C drive) is a high-privilege action that warrants investigation.

---

# PART B: SSH — Secure Shell

## What Is SSH? (Simple)

SSH is a protocol for securely accessing a remote computer's command line.

When a system administrator needs to configure a Linux server, they use SSH — they type commands on their own computer that execute on the remote server, as if they were sitting at that server's keyboard.

SSH replaced Telnet, which did the same thing but sent everything in plaintext. SSH encrypts everything.

Port: 22

---

## How SSH Works Behind the Scenes

### SSH Authentication Methods

Password Authentication:
Client sends username and password.
Server verifies against /etc/shadow (Linux) or local accounts.
Weakness: Vulnerable to brute force.

Public Key Authentication:
Client generates a key pair: public key + private key.
Public key is placed on the server in ~/.ssh/authorized_keys.
When connecting, client proves it has the private key without sending it.
The server encrypts a challenge with the public key — only the holder of the private key can decrypt it.
Strength: Cannot be brute-forced. If the private key is secure, the account is secure.

Multi-Factor Authentication (MFA):
Requires both a key and a code (Google Authenticator, etc.).
Best security.

### SSH Host Key Verification

The first time you connect to a server, SSH shows its fingerprint:
```
The authenticity of host '192.168.1.10' can't be established.
RSA key fingerprint is SHA256:xMxOLGVBB3RFpaDMd7VUPRY3LMqlNtBTfBm9+7oJ3KY.
Are you sure you want to continue connecting (yes/no)?
```
If you accept, this fingerprint is stored in ~/.ssh/known_hosts.
Next time, SSH verifies the server presents the same key.

If the key changes: SSH warns you — "REMOTE HOST IDENTIFICATION HAS CHANGED."
This warning means either: the server was rebuilt, OR someone is performing a man-in-the-middle attack on your SSH connection.

---

## SOC Perspective — SSH Attacks

### SSH Brute Force

Attackers try thousands of username/password combinations hoping to find valid credentials.

Log evidence (/var/log/auth.log):
```
Mar 15 03:00:01 server sshd[1234]: Failed password for root from 185.220.101.47 port 49812 ssh2
Mar 15 03:00:02 server sshd[1234]: Failed password for admin from 185.220.101.47 port 49813 ssh2
Mar 15 03:00:03 server sshd[1234]: Failed password for user from 185.220.101.47 port 49814 ssh2
[thousands more...]
Mar 15 03:22:41 server sshd[1234]: Accepted password for root from 185.220.101.47 port 50001 ssh2
```

Detection:
- High rate of failed authentication from one IP
- Attempts against multiple usernames (root, admin, ubuntu, oracle, postgres...)
- Success after many failures

Response:
- Block the source IP
- Check if the successful login performed any actions (commands run, files accessed, new users created)
- Determine how the attacker will maintain access (look for new SSH keys added)

### SSH Key Theft and Unauthorized Key Installation

Attacker steals a private SSH key (from a compromised computer, from a config repository, from backup files).

Or:
Attacker who has gained access adds their public key to ~/.ssh/authorized_keys for persistent access.

Detection:
- Modification of .ssh/authorized_keys file
- New SSH connection from unexpected IP using key authentication
- Audit log showing who modified .ssh/authorized_keys

### SSH Tunneling

SSH can forward network ports — creating an encrypted tunnel for other traffic.

Local port forwarding:
```
ssh -L 3306:database-server:3306 user@jump-host
```
This tunnels connections to local port 3306 through the SSH connection to the jump host, then to the database server.
Legitimate use: accessing internal services through a jump server.
Malicious use: tunneling C2 traffic or exfiltrating data through SSH.

Dynamic port forwarding (SOCKS proxy):
```
ssh -D 1080 user@server
```
Creates a SOCKS proxy — all traffic configured to use it goes through the SSH server.
Malicious use: Using a compromised server as a proxy for attacking other systems.

---

# PART C: RDP — Remote Desktop Protocol

## What Is RDP? (Simple)

RDP is Windows' built-in remote access protocol. It lets you see and control a Windows computer remotely as if you were sitting in front of it — full graphical interface, mouse, keyboard, everything.

Port: 3389

Used by:
- IT administrators managing servers
- Remote workers accessing their office computers
- Help desk staff assisting users

---

## How RDP Works Behind the Scenes

1. Client connects to server's TCP port 3389.
2. RDP Negotiation: Client and server agree on security level.
   Network Level Authentication (NLA) — authentication before remote desktop is shown (more secure)
   Without NLA — desktop is shown before authentication (allows screen-based brute force)
3. Authentication: Username and password (or SSO with Kerberos).
4. Graphical session: Screen content is compressed, encrypted, and sent to the client. Mouse/keyboard input is sent to the server.
5. Session ends on logoff or disconnection.

### RDP Security Levels

NLA (Network Level Authentication) — Preferred. Authentication happens at the TCP/credential level before a full RDP session is established. Limits the attack surface.

Classic RDP Security — Older, weaker. The full desktop login screen is exposed.

RDP over TLS/SSL — Encrypts the session. Without this, RDP traffic can be intercepted.

---

## SOC Perspective — RDP Attacks

### RDP Brute Force / Credential Stuffing

Internet-exposed RDP is the most targeted service on the internet.
Attackers scan for port 3389 globally and attempt to log in with default/stolen credentials.

Windows Security Log for RDP failures:
```
EventID: 4625
Time: 2024-03-15 03:00:01
Logon Type: 3 (Network)
Account Name: Administrator
Failure Reason: Unknown user name or bad password
Source Network Address: 185.220.101.47
Source Port: 49812

EventID: 4625
Time: 2024-03-15 03:00:02
Account Name: admin
Source Network Address: 185.220.101.47
```
Rapid sequential failures = brute force.

### RDP Lateral Movement

After initial compromise, attackers use RDP to move between systems:
1. Attacker is on Computer A with stolen credentials.
2. They open an RDP session to Computer B.
3. Now they have a full graphical session on Computer B.
4. They can interact just like a legitimate user.

This is dangerous because:
- RDP sessions look like normal user activity
- Attackers use legitimate Windows tools (no malware to detect)
- The activity is "Living off the Land" — no suspicious files dropped

Detection:
- Event ID 4624 Logon Type 10 (RemoteInteractive) = RDP login
- RDP connections between workstations (workstations do not RDP each other normally)
- RDP connections from unusual source IPs
- RDP connections at unusual times (3 AM)
- Multiple RDP connections from the same account in short time (credential sharing or account compromise)

### BlueKeep (CVE-2019-0708)

A critical vulnerability in RDP that allows unauthenticated remote code execution.
Similar to EternalBlue but for RDP.
Affected: Windows 7, Windows Server 2008.
Patched in May 2019 — but many unpatched systems still exist.

Detection: Unusual traffic to port 3389, malformed RDP packets, unexpected processes after RDP connection.

### RDP Log Example:

```
EventID: 4624
Time: 2024-03-15 03:14:22
Logon Type: 10 (RemoteInteractive = RDP)
Subject:
    Account Name: john.smith
    Account Domain: COMPANY
Network Information:
    Source Network Address: 45.142.212.100  ← External IP — very suspicious
    Source Port: 51234
Logon Information:
    Authentication Package: NTLM
```
RDP login via NTLM from an external IP at 3 AM is highly suspicious. Legitimate remote workers should use VPN + RDP, not direct internet RDP.

---

# PART D: FTP — File Transfer Protocol

## What Is FTP? (Simple)

FTP is a protocol for transferring files between computers.

It has been used since the early internet days. Today it is mostly obsolete (replaced by SFTP and HTTPS file transfers), but it still exists in many environments.

Ports: 21 (control), 20 (data)
FTPS: FTP over SSL (encrypted), port 990
SFTP: SSH File Transfer Protocol (not FTP over SSH, but a different protocol), port 22

---

## Why FTP Is a Security Problem

FTP sends everything in plaintext — including username, password, and all file contents.

Anyone on the network (or an attacker performing a man-in-the-middle attack) can capture FTP traffic and read the credentials and files.

If you see FTP in use in your organization, this is a finding that should be reported.

---

## How Attackers Abuse FTP

Credential interception:
Sniff FTP credentials from the network.
Use Wireshark, Ettercap, or similar tools.
Then use the credentials to access the FTP server directly.

Anonymous FTP abuse:
Some FTP servers allow anonymous login (no credentials).
Attackers find misconfigured FTP servers and access files freely.
Attackers also use open FTP servers to host malware.

FTP C2:
Some malware uses FTP for command and control or data exfiltration.
Unusual FTP traffic from internal computers = suspicious.

FTP Log Example:
```
Mar 15 03:22:14 ftpserver vsftpd[12345]: CONNECT: Client "185.220.101.47"
Mar 15 03:22:14 ftpserver vsftpd[12345]: [root] OK LOGIN: Client "185.220.101.47"
Mar 15 03:22:16 ftpserver vsftpd[12345]: [root] OK UPLOAD: Client "185.220.101.47", "/var/www/html/webshell.php", 4096 bytes
```
An external IP logged in as root and uploaded a PHP file to the web root. This is a webshell installation — critical incident.

---

## Summary

SMB (port 445): Windows file/resource sharing. Abused for lateral movement, EternalBlue, Pass-the-Hash. Never expose to internet.
SSH (port 22): Secure remote shell. Brute forced if internet-exposed. Used for tunneling and persistent access.
RDP (port 3389): Windows remote desktop. Most attacked service on internet. Used for lateral movement. Never expose directly to internet.
FTP (ports 20/21): Legacy file transfer. Sends everything in plaintext. Should be replaced with SFTP or FTPS.

---

## Practice Questions

**Easy:**
1. What port does SMB use and why should it never be exposed to the internet?
2. What is SSH public key authentication and why is it more secure than passwords?
3. What is NLA in the context of RDP?

**Medium:**
4. A Windows security log shows Event ID 4624 Logon Type 3 with source IP 192.168.5.44 accessing \\SERVER01\C$ at 2 AM. No user is scheduled to work at that time. What does this tell you?
5. An FTP server log shows root logging in from an external IP and uploading a .php file to the web server directory. What happened and how serious is it?

**Thinking Questions:**
6. An attacker has obtained the password hash for the domain admin account "DA-backup". They have not cracked the actual password. How can they still use this hash to move laterally? What technique is this? What logs would show this activity?
7. A security audit reveals that RDP (port 3389) is open on your company's firewall from the internet (0.0.0.0/0). Current logs show 47,000 failed login attempts in the last 24 hours from 300 different external IPs. One attempt succeeded: user "backup-admin" from IP 45.142.212.100 at 3:14 AM. Walk through the incident from start to finish.
