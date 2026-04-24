# Lesson 3.4 — NAT, Routing, and Common Ports Reference

**Phase:** 3 — Networking Deep Dive
**Prerequisite:** Lessons 3.2 and 3.3
**Time to complete:** 25 minutes

---

## NAT — Network Address Translation

### What Is NAT?

NAT is the technology that allows an entire organization to share one (or a few) public IP addresses while internally using private IP addresses.

Without NAT: Every device would need its own public IP address. Since IPv4 has ~4.3 billion addresses and the world has tens of billions of devices, this would be impossible.

With NAT: 500 employees share one public IP (like one postal address for the entire office building). The router keeps track of which internal IP/port maps to which external connection.

### How NAT Works

The NAT table:
```
Internal IP:Port       →  External IP:Port
192.168.1.55:54321    →  203.0.113.50:12001 (mapping to company public IP)
192.168.1.22:54444    →  203.0.113.50:12002
192.168.1.88:55100    →  203.0.113.50:12003
```

When 192.168.1.55:54321 sends traffic out:
1. The router changes the source from 192.168.1.55:54321 to 203.0.113.50:12001.
2. The destination server (Google, etc.) sees the traffic coming from 203.0.113.50.
3. Google sends the response to 203.0.113.50:12001.
4. The router looks up the NAT table: 203.0.113.50:12001 = 192.168.1.55:54321.
5. The router translates it back and forwards to 192.168.1.55:54321.

### NAT Types

SNAT (Source NAT) — changes the source IP (most common — what we described above)
DNAT (Destination NAT) — changes the destination IP (used for port forwarding, load balancing)
PAT (Port Address Translation) — uses different port numbers to track multiple connections (technically what most "NAT" is)

### Port Forwarding (Inbound NAT)

Port forwarding allows external traffic to reach a specific internal server.

Example:
Company's public IP: 203.0.113.50
Web server internal IP: 192.168.10.5
Port forward rule: External port 443 → 192.168.10.5:443

When the internet sends traffic to 203.0.113.50:443, the router/firewall forwards it to 192.168.10.5:443.

SOC relevance:
Port forwarding creates intentional "holes" in the NAT barrier.
Every port forward is a potential attack surface.
Monitor these rules — if an attacker can add a port forward rule, they can expose internal services.

### NAT in SOC Investigations

The challenge: When you see a firewall alert for traffic "from 203.0.113.50," you know the company's public IP, but which of 500 internal computers sent it?

Solve it with:
1. Firewall NAT logs — which internal IP was mapped to which external port at the time
2. DHCP logs — which computer had that internal IP at the time

This correlation is a core investigative technique.

---

## Routing — Deeper Understanding

### Static vs Dynamic Routing

Static routing: A network administrator manually enters every route.
Pros: Simple, predictable, no overhead.
Cons: Does not adapt to network changes. Must be manually updated.
Used for: Small networks, specific forced paths.

Dynamic routing: Routers share route information and automatically learn the best paths.
Protocols: OSPF (Open Shortest Path First), EIGRP, BGP.
Pros: Adapts automatically to network changes.
Cons: More complex, additional attack surface.

### Default Route

Every device has a default route — what to do when it does not know where to send a packet.
The default route points to the "next hop" — usually your ISP's router.

Configuration: 0.0.0.0/0 via [gateway IP]

In a corporate setting:
Workstations default route → internal router → firewall → internet
If an attacker can change a device's default gateway (via DHCP poisoning or rogue router), they can route all traffic through themselves.

---

## Complete Common Ports Reference

This is your practical reference for SOC work. Know these cold.

```
PORT    PROTOCOL   DESCRIPTION                          ATTACK RELEVANCE
─────────────────────────────────────────────────────────────────────────
20      FTP-DATA   File transfer data channel           Unencrypted file transfers
21      FTP        File transfer control                Brute force, unencrypted creds
22      SSH        Secure remote shell                  Brute force, lateral movement
23      TELNET     Insecure remote shell (obsolete)     Any usage = suspicious
25      SMTP       Email sending (server-to-server)     Spam, email spoofing
53      DNS        Domain name resolution               DNS tunneling, DGA, hijacking
67/68   DHCP       IP address assignment                Rogue DHCP, starvation
80      HTTP       Unencrypted web                      C2, phishing, data exfiltration
88      Kerberos   Windows authentication               Kerberoasting, pass-the-ticket
110     POP3       Email retrieval                      Credential theft
123     NTP        Network time synchronization         Amplification DDoS
135     MS-RPC     Microsoft RPC (remote procedure)     Lateral movement, exploitation
137-139 NetBIOS    Windows name resolution              Enumeration, relay attacks
143     IMAP       Email access                         Credential theft
161/162 SNMP       Network device management            Enumeration, amplification DDoS
389     LDAP       Directory services (Active Directory) Enumeration, pass-the-hash
443     HTTPS      Encrypted web                        C2, exfiltration (hard to inspect)
445     SMB        Windows file/print sharing           EternalBlue, WannaCry, lateral movement
465/587 SMTPS      Encrypted email sending              Phishing campaigns
514     Syslog     Log forwarding                       Log manipulation
636     LDAPS      Encrypted LDAP                       Directory enumeration
993     IMAPS      Encrypted email access               Credential theft
995     POP3S      Encrypted email retrieval            Credential theft
1433    MSSQL      Microsoft SQL Server                 SQL injection, data theft
1434    MSSQL-UDP  MSSQL discovery                     Enumeration
3306    MySQL      MySQL database                       SQL injection, data theft
3389    RDP        Windows remote desktop               Brute force, lateral movement
4444    Metasploit Default Metasploit handler           Metasploit C2 — always alert
5985    WinRM-HTTP Windows Remote Management (HTTP)     Lateral movement (PowerShell remoting)
5986    WinRM-HTTPS Windows Remote Management (HTTPS)   Lateral movement (PowerShell remoting)
6379    Redis      Redis database                       Unauthenticated access, RCE
8080    HTTP-ALT   Alternate HTTP                       C2, web applications
8443    HTTPS-ALT  Alternate HTTPS                      C2, admin portals
9001    Tor        Tor relay port                       Anonymization, C2
9050    Tor-Proxy  Tor SOCKS proxy                     Anonymization, C2
27017   MongoDB    MongoDB database                     Unauthenticated access, data theft
```

### Pattern Recognition — Suspicious Port Combinations

These port patterns should trigger investigation:

1. Internal to external on unusual ports:
   - Port 4444, 5555, 6666, 7777, 8888 — common RAT/Metasploit default ports
   - Port 9001, 9050 — Tor
   - Port 4899 — Radmin (remote admin tool)
   - Port 6667 — IRC (rarely legitimate, classic botnet C2)

2. External to internal on dangerous ports:
   - Port 445 from internet — SMB must never be internet-facing
   - Port 3389 from internet — RDP should be behind VPN
   - Port 1433/3306 from internet — databases should never be internet-facing
   - Port 23 from internet — Telnet is always suspicious

3. Internal to internal unusual:
   - Port 445 between workstations at night — lateral movement
   - Port 3389 from one workstation to another — attacker using RDP to move laterally
   - Port 135 widespread scanning — attacker using RPC for lateral movement

4. Beaconing patterns (regular intervals):
   - Any port: connection every X seconds/minutes for extended period
   - Even on allowed ports (443): regular small connections indicate C2

---

## Quiz-Ready Scenario Practice

Scenario 1:
Firewall log shows: internal IP 192.168.5.33 → external IP 185.220.101.47:4444
What does this mean and what is your immediate action?

Answer: Port 4444 is the default Metasploit listener. This strongly suggests the internal computer is compromised with a Metasploit reverse shell, connecting back to the attacker's C2 server. Immediate actions: Block the external IP at the firewall, isolate 192.168.5.33 from the network, begin incident response on that machine.

Scenario 2:
You see multiple internal workstations connecting to each other on port 445 at 3 AM.
What does this mean?

Answer: Port 445 is SMB (file sharing). Workstations do not normally communicate with each other via SMB. At 3 AM with no users logged in, this pattern strongly suggests a network worm (like WannaCry) or an attacker using SMB for lateral movement. Isolate affected segments and investigate immediately.

Scenario 3:
External IP 203.0.113.100 is sending traffic to your company's public IP on port 22 — 2,000 attempts per minute.
What is this?

Answer: This is an SSH brute force attack. The attacker is trying to guess SSH credentials. Check: Is SSH actually exposed on your public IP? If yes, consider blocking the source IP, enabling rate limiting, or moving SSH behind VPN. Check if any connection succeeded (look for successful authentication logs).

---

## Summary

NAT allows many devices to share one public IP. NAT logs + DHCP logs identify the internal device behind each external connection.
Routing tables determine packet paths. Default routes are a target for attackers.
Every SOC analyst must know the critical ports and what attacks are associated with each.
Pattern recognition — unusual port usage, beaconing, cross-segment communication — is a core skill.

---

## Practice Questions

**Easy:**
1. What is NAT and why is it needed?
2. What port does RDP use and why should it not be exposed to the internet?
3. Name three ports that should NEVER be accessible from the internet.

**Medium:**
4. You have a firewall log entry: external IP 45.142.212.100 → company public IP 203.0.113.50:445. The firewall is configured to block this. Is this a problem? What does it tell you?
5. An internal computer is making connections to port 88 (Kerberos) on the Domain Controller every 5 seconds. What might this indicate?

**Thinking Question:**
6. You see traffic from 192.168.1.77 to multiple external IPs on ports 6666, 7777, 8888 over the course of 30 minutes. No single connection lasts more than 5 seconds. The computer is trying different ports in sequence. What technique is this? What is the attacker's goal?
