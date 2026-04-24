# Lesson 2.5 — Ports and Protocols (Introduction)

**Phase:** 2 — IT & Networking Foundations
**Prerequisite:** Lessons 2.3 and 2.4
**Time to complete:** 30 minutes

---

## Simple Explanation

An IP address tells you which computer to contact. A port tells you which service on that computer to contact.

Think of an IP address as a building's street address. A port is the specific apartment number or office room within that building.

When you send a letter to "42 Main Street, Apartment 5B," the address gets you to the building, and the apartment number gets you to the right door. Similarly, an IP address gets a packet to the right computer, and the port number gets it to the right application.

---

## Real-World Analogy

Imagine a large airport. The airport has one address (the IP address). But inside, there are different terminals for different airlines (ports). If you are flying Delta, you go to Terminal A. American Airlines is Terminal B. International flights are Terminal C.

Each terminal (port) handles specific traffic and knows what to do with it. You would not go to the international terminal for a domestic flight — the wrong port means the wrong service.

---

## What Are Ports?

A port is a number from 0 to 65535 that identifies a specific application or service on a computer.

Port ranges:
- 0–1023: Well-known ports (reserved for standard services, require admin to open)
- 1024–49151: Registered ports (assigned to specific applications by IANA)
- 49152–65535: Dynamic/ephemeral ports (temporary, used by clients for their side of a connection)

When your browser connects to a website:
- Your browser picks a random high-numbered port (e.g., 54321) for itself
- It connects to the server's port 443 (HTTPS)
- The server responds back to your browser's port 54321

---

## Critical Ports Every SOC Analyst Must Know

Memorize these. You will see them in logs every day.

PORT 20/21 — FTP (File Transfer Protocol)
Used for transferring files.
Port 21 = control channel (commands)
Port 20 = data channel (file transfer)
Security concern: Unencrypted. Credentials sent in plaintext.

PORT 22 — SSH (Secure Shell)
Used for secure remote command-line access.
Encrypted. Replaces old Telnet (port 23).
Security concern: If SSH is exposed to the internet, attackers brute-force it.
Suspicious: SSH from unusual sources, at unusual times, or by unusual accounts.

PORT 23 — Telnet
Unencrypted remote access (obsolete, but still found on old devices).
Never use Telnet in 2024. Any Telnet traffic is suspicious.

PORT 25 — SMTP (Simple Mail Transfer Protocol)
Used for sending email between mail servers.
Internal to internal = server-to-server email relay. Normal.
Internal to external = your mail server sending emails. Normal.
User workstation to external port 25 = suspicious (possible spam/malware sending email).

PORT 53 — DNS (Domain Name System)
Used for domain name resolution.
UDP for queries (small requests).
TCP for large responses or zone transfers.
Security concern: DNS tunneling, DGA malware, DNS hijacking.

PORT 80 — HTTP (HyperText Transfer Protocol)
Unencrypted web traffic.
Less common now (most sites use HTTPS).
Security concern: Credentials and data sent in plaintext. C2 traffic often uses HTTP.

PORT 110 — POP3 (Post Office Protocol 3)
Used to download email from a server.
Older protocol. Being replaced by IMAP.

PORT 143 — IMAP (Internet Message Access Protocol)
Used to access email on a server (without downloading).
Port 993 = IMAP over SSL (encrypted).

PORT 443 — HTTPS (HTTP Secure)
Encrypted web traffic. The standard for all modern websites.
Security concern: Attackers use HTTPS for C2 traffic because it is encrypted and widely allowed.

PORT 445 — SMB (Server Message Block)
Used for Windows file sharing, printer sharing, and other Windows network services.
Critical port — many famous attacks used SMB (WannaCry, NotPetya, EternalBlue).
Should NEVER be exposed to the internet. If you see port 445 open on a public IP, that is critical.

PORT 3389 — RDP (Remote Desktop Protocol)
Used for graphical remote desktop access to Windows machines.
Attackers love RDP for lateral movement and initial access.
Should never be exposed directly to the internet without a VPN.
Massive brute-force attacks happen continuously against exposed RDP.

PORT 1433 — MSSQL
Microsoft SQL Server database.
Database ports should never be accessible from the internet.

PORT 3306 — MySQL
MySQL database.
Same rule as MSSQL.

PORT 8080 / 8443 — Alternative HTTP/HTTPS
Often used for web applications, developer environments, management consoles.
Also used by malware as alternative channels.

PORT 4444, 5555, 6666, 7777 — Metasploit/Common Malware Ports
These are default ports for penetration testing tools and malware.
Any traffic on these ports from corporate devices warrants immediate investigation.

PORT 9001, 9050 — Tor
Used by the Tor anonymization network.
Legitimate use is rare in corporate environments.
Any internal computer connecting to Tor is highly suspicious.

---

## Protocols — What They Are

A protocol is a set of rules that defines how communication happens.

Just as human languages have grammar rules (how to form sentences, when to pause, how to ask a question), network protocols define how computers communicate — how data is formatted, how connections are established, how errors are handled.

The key protocol families:

TCP — Transmission Control Protocol:
Reliable, connection-oriented communication.
Before data is sent, a connection is established (the "three-way handshake").
Data is guaranteed to arrive and in the correct order.
Used for: HTTP, HTTPS, SSH, RDP, SMB, SMTP, FTP (anything where accuracy matters)
Trade-off: Slower than UDP because of the reliability overhead.

UDP — User Datagram Protocol:
Unreliable, connectionless communication.
Data is sent without first establishing a connection.
No guarantee that data arrives or arrives in order.
Used for: DNS, DHCP, video streaming, VoIP (anything where speed matters more than accuracy)
Reason: Losing one video frame is acceptable. Resending it would cause the video to lag.

ICMP — Internet Control Message Protocol:
Used for network diagnostics and error messages.
ping uses ICMP.
Not used for application data — used for network management.
Security concern: ICMP can be used for reconnaissance (ping sweeps to find live hosts).

---

## TCP Three-Way Handshake

Before two computers communicate via TCP, they establish a connection using a three-way handshake.

Step 1 — SYN (Synchronize):
Client: "I want to connect. Let's synchronize."
Client sends a SYN packet to the server.

Step 2 — SYN-ACK (Synchronize-Acknowledge):
Server: "I received your request. I'm ready."
Server sends SYN-ACK back.

Step 3 — ACK (Acknowledge):
Client: "Confirmed. Connection established."
Client sends ACK.

Now they can exchange data.

Why this matters for SOC:
SYN flood attack: An attacker sends thousands of SYN packets but never completes the handshake. The server reserves resources for each incomplete connection until it runs out of resources and cannot accept new legitimate connections. This is a common Denial of Service (DoS) attack.
In logs: Thousands of SYN packets from one IP to many ports = port scan. Thousands of SYN packets from many IPs to one port = DDoS SYN flood.

---

## Reading Port Information in Logs

Firewall log format typically shows:
```
[timestamp] [action] [protocol] [source_ip]:[source_port] -> [destination_ip]:[destination_port]
```

Example:
```
2024-03-15 14:22:31 ALLOW TCP 192.168.1.55:54321 -> 172.217.14.100:443
```
Internal computer (192.168.1.55) connecting to an external server (172.217.14.100) via HTTPS (port 443). Normal browsing.

```
2024-03-15 14:22:33 ALLOW TCP 192.168.1.55:54322 -> 185.220.101.47:4444
```
Internal computer connecting to an external IP on port 4444. Port 4444 is a common Metasploit/C2 port. Very suspicious.

```
2024-03-15 03:15:00 DENY TCP 185.220.101.47:49212 -> 203.0.113.50:445
```
External IP trying to reach your company's public IP on port 445 (SMB). Blocked. If this were not blocked, it would be extremely dangerous.

---

## Common Attack Signatures by Port

Port 22 (SSH):
Attacker pattern: Many rapid connection attempts from one external IP = brute force
Attacker pattern: Successful connection from unusual geolocation = compromised credentials

Port 3389 (RDP):
Attacker pattern: Many connection attempts from external IPs = internet-exposed RDP under attack
Attacker pattern: Lateral movement: Internal IP connecting to other internal IPs via RDP at night

Port 445 (SMB):
Attacker pattern: Rapid connections to many internal IPs on port 445 = network worm or lateral movement scanner
Historical: WannaCry ransomware spread via SMB port 445 using the EternalBlue exploit

Port 53 (DNS):
Attacker pattern: Many queries with very long subdomains = DNS tunneling
Attacker pattern: NXDOMAIN flood = DGA malware

Port 443 (HTTPS):
Attacker pattern: Large outbound data volume to unknown IP at night = data exfiltration
Attacker pattern: Repeated beaconing (connections every X minutes/seconds) = C2 communication

---

## Summary

A port identifies a specific service on a computer. IP address = building, port = office number.
Ports 0–1023 are well-known, reserved for standard services.
Critical ports: 22 (SSH), 53 (DNS), 80 (HTTP), 443 (HTTPS), 445 (SMB), 3389 (RDP).
TCP is reliable and connection-oriented. UDP is fast and connectionless.
The TCP three-way handshake (SYN, SYN-ACK, ACK) establishes connections.
Knowing which ports are normal and which are suspicious is a core SOC skill.

---

## Practice Questions

**Easy:**
1. What is the port number for HTTPS?
2. What is the difference between TCP and UDP?
3. What is the TCP three-way handshake?

**Medium:**
4. You see traffic from an internal workstation to an external IP on port 4444. Why is this suspicious?
5. An external IP is sending SYN packets to your company's public IP on ports 22, 80, 443, 3389, 3306, 1433, 8080 in rapid succession. What is this activity?

**Thinking Questions:**
6. A firewall log shows that every 60 seconds, an internal computer makes a TCP connection to external IP 185.220.101.47 on port 443, transfers exactly 512 bytes, and disconnects. This has been happening for 3 days. What does this look like, and what would you investigate?
7. SMB (port 445) traffic is seen between workstations (not servers) on your internal network at 4 AM. No users are logged in. What are the possible explanations, and which is most likely in a security context?
