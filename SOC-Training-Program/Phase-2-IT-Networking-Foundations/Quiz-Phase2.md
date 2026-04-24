# Phase 2 Quiz — IT & Networking Foundations

**Time limit:** 35 minutes
**Total questions:** 20
**Passing score:** 16/20

---

## Section A — Multiple Choice (1 point each)

**Question 1:**
Which Windows Event ID represents a failed logon attempt?

A) 4624
B) 4625
C) 4688
D) 4720

---

**Question 2:**
A process is running from C:\Windows\System32\svchost.exe. Its parent process is explorer.exe. The real svchost.exe is always started by services.exe. Is this suspicious?

A) No — svchost.exe is a legitimate Windows process
B) No — parent process does not matter
C) Yes — the file path is wrong
D) Yes — the parent process is wrong; svchost.exe should be started by services.exe, not explorer.exe

---

**Question 3:**
Which of the following Linux directories is most commonly used by malware to drop files?

A) /etc/
B) /usr/bin/
C) /tmp/
D) /home/

---

**Question 4:**
What does the DHCP protocol do?

A) Translates domain names to IP addresses
B) Automatically assigns IP addresses and network configuration to devices
C) Routes packets between networks
D) Encrypts network traffic

---

**Question 5:**
You want to identify which computer was using IP address 10.0.5.33 at 3 PM yesterday. Which log do you check?

A) DNS logs
B) Firewall logs
C) DHCP logs
D) Active Directory logs

---

**Question 6:**
Port 445 is associated with which protocol?

A) RDP
B) SSH
C) SMB
D) HTTPS

---

**Question 7:**
What is a TCP three-way handshake?

A) SYN, ACK, FIN
B) SYN, SYN-ACK, ACK
C) CONNECT, READY, SEND
D) REQUEST, ACKNOWLEDGE, TRANSFER

---

**Question 8:**
Which of the following PowerShell command characteristics is most suspicious?

A) Running as a domain user
B) Using the -enc flag (encoded command)
C) Running from C:\Windows\System32\
D) Being spawned by cmd.exe

---

**Question 9:**
What is DNS tunneling?

A) Encrypting DNS traffic with TLS
B) Hiding data inside DNS queries to bypass firewall restrictions
C) Redirecting DNS traffic through a VPN
D) Using DNS to perform a denial of service attack

---

**Question 10:**
Which of the following should NEVER be exposed directly to the internet without a VPN?

A) Port 443 (HTTPS)
B) Port 80 (HTTP)
C) Port 3389 (RDP)
D) Port 53 (DNS)

---

## Section B — True or False (1 point each)

**Question 11:**
The /etc/passwd file on Linux contains the actual password hashes.

True / False

---

**Question 12:**
If an attacker adds their public SSH key to /root/.ssh/authorized_keys, they can log in as root without a password.

True / False

---

**Question 13:**
A Windows Active Directory Domain Controller is the most critical server in an enterprise environment.

True / False

---

**Question 14:**
UDP guarantees that packets arrive in order and without loss.

True / False

---

**Question 15:**
Port 4444 is a well-known legitimate enterprise application port that you should never flag as suspicious.

True / False

---

## Section C — Log Analysis (2 points each)

Read each log entry and answer the questions.

---

**Question 16:**
```
EventID: 4688
Time: 2024-03-15 02:14:33
Computer: WORKSTATION-KLEE
Creator Process: winword.exe
New Process: cmd.exe
Command Line: cmd.exe /c powershell.exe -exec bypass -w hidden -enc JABjAGwA...
User: kim.lee@company.com
```
What happened here? Is it suspicious? Why? What would you investigate next?

---

**Question 17:**
```
Time: 2024-03-15 03:00:00 DHCPACK on 192.168.1.77 to LAPTOP-TBROWN
Time: 2024-03-15 03:01:14 Failed password for root from 192.168.1.77 port 52001 ssh2
Time: 2024-03-15 03:01:15 Failed password for root from 192.168.1.77 port 52002 ssh2
[1,247 more failures]
Time: 2024-03-15 03:22:41 Accepted password for root from 192.168.1.77 port 53250 ssh2
```
What happened? Who is involved? What is the significance of the DHCP entry?

---

**Question 18:**
```
DNS Query Log:
2024-03-15 04:00:01 LAPTOP-MWANG queries: xjkqrp19ns.com → NXDOMAIN
2024-03-15 04:00:02 LAPTOP-MWANG queries: qzxkjmn47.net → NXDOMAIN
2024-03-15 04:00:03 LAPTOP-MWANG queries: wbmrpx83.org → NXDOMAIN
2024-03-15 04:00:04 LAPTOP-MWANG queries: rkqvtn91.com → NXDOMAIN
[continues for 400+ queries]
```
What is this behavior? What does it indicate? What action would you take?

---

**Question 19:**
```
Firewall Log:
2024-03-15 14:20:00 ALLOW TCP 192.168.1.44:53211 → 8.8.8.8:53
2024-03-15 14:20:01 ALLOW UDP 192.168.1.44:63422 → 8.8.8.8:53
2024-03-15 14:20:02 ALLOW TCP 192.168.1.44:53213 → 443.something.com:443
2024-03-15 14:22:00 ALLOW TCP 192.168.1.44:53220 → 185.220.101.47:4444
2024-03-15 14:22:01 ALLOW TCP 192.168.1.44:53221 → 185.220.101.47:4444
```
Which entry is suspicious and why? What does port 4444 suggest?

---

**Question 20:**
```
Linux /etc/passwd (excerpt):
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sysadmin:x:1001:1001::/home/sysadmin:/bin/bash
maintenance:x:0:0::/root:/bin/bash
```
What is suspicious in this file? What does it mean?

---

## Answer Key

**Section A:**
1. B — 4625 is failed logon
2. D — The parent process (explorer.exe) is wrong
3. C — /tmp is world-writable, commonly used by malware
4. B — DHCP assigns IP addresses automatically
5. C — DHCP logs map IPs to devices at specific times
6. C — SMB uses port 445
7. B — SYN, SYN-ACK, ACK
8. B — -enc means encoded (hidden) command
9. B — DNS tunneling hides data in DNS queries
10. C — RDP (3389) should never be internet-facing

**Section B:**
11. False — /etc/passwd contains usernames and basic info. /etc/shadow contains password hashes.
12. True — SSH keys allow passwordless authentication.
13. True — The DC controls all authentication and is the highest-value target.
14. False — UDP is unreliable and does not guarantee delivery or order.
15. False — Port 4444 is a common Metasploit/malware default and should always be investigated.

**Section C:**

16. (2 points) Microsoft Word spawned cmd.exe, which then ran PowerShell with bypass execution policy, hidden window, and an encoded command. This is classic malware delivery via a malicious Word macro. Extremely suspicious. Next steps: Isolate the workstation, decode the PowerShell command, check what files were created or downloaded, check outbound network connections from this machine, check for persistence mechanisms. (2 points for identifying macro attack + next steps)

17. (2 points) LAPTOP-TBROWN (assigned IP 192.168.1.77 at 3:00 AM) performed an SSH brute force attack against a Linux server, making 1,247+ failed attempts before successfully authenticating as root at 3:22 AM. The DHCP entry is critical because it identifies the attacking machine as LAPTOP-TBROWN. Investigation: Who uses this laptop? Was the laptop itself compromised and used as a pivot point? (2 points for identifying brute force success + DHCP significance)

18. (2 points) This is a Domain Generation Algorithm (DGA) infection. LAPTOP-MWANG is infected with malware that generates random domain names trying to find the attacker's C2 server. All return NXDOMAIN (not found), meaning the active C2 domains have not been generated yet. Action: Immediately isolate LAPTOP-MWANG, run EDR scan, identify the malware family, check for persistence. (2 points)

19. (2 points) The connections to 185.220.101.47 on port 4444 are suspicious. Port 4444 is the default Metasploit listener port and is commonly used by RATs and malware for C2 communication. The other entries (DNS on port 53, HTTPS on port 443) are normal. Action: Investigate the workstation at 192.168.1.44, check DHCP logs to identify the computer, run EDR scan. (2 points)

20. (2 points) The "maintenance" account has UID 0 (same as root), giving it full root privileges. This is suspicious because there should never be two root-level accounts unless explicitly configured. The account likely does not belong in this file — it is probably a backdoor created by an attacker. The home directory is /root and shell is /bin/bash, confirming full root access. Immediate response: Remove the account, investigate how it was created, check auth logs for logins using this account. (2 points)
