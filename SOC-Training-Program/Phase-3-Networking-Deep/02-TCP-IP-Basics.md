# Lesson 3.2 — TCP/IP Basics

**Phase:** 3 — Networking Deep Dive
**Prerequisite:** Lesson 3.1
**Time to complete:** 35 minutes

---

## Simple Explanation

TCP/IP is the foundation protocol of the internet and all modern networks.

It is actually two protocols working together:
- IP (Internet Protocol) — handles addressing and routing (getting packets to the right place)
- TCP (Transmission Control Protocol) — handles reliability (making sure data arrives correctly)

When you visit a website, send an email, or connect to a server, you are using TCP/IP at the fundamental level.

---

## The TCP/IP Model vs OSI Model

The OSI model has 7 layers. The TCP/IP model has 4 layers. TCP/IP is what is actually used in practice. OSI is the conceptual framework used for discussion.

```
OSI Model          TCP/IP Model         Protocols
─────────────────────────────────────────────────────────
7. Application  ┐
6. Presentation ├─→ Application    HTTP, HTTPS, DNS, SMTP,
5. Session      ┘                  FTP, SSH, RDP

4. Transport    ──→ Transport      TCP, UDP

3. Network      ──→ Internet       IP, ICMP, ARP

2. Data Link    ┐
1. Physical     ┴─→ Network Access Ethernet, Wi-Fi
```

---

## IP — Internet Protocol (Deep Dive)

### IP Packet Structure

Every IP packet has a header containing:

Version — IPv4 or IPv6
Source IP Address — where the packet came from
Destination IP Address — where the packet is going
TTL (Time To Live) — how many routers the packet can pass through before being discarded
Protocol — what is inside (TCP, UDP, ICMP, etc.)
Checksum — error checking

The TTL field is important for SOC work:
- Every router the packet passes through decrements TTL by 1
- When TTL reaches 0, the packet is dropped and an ICMP "Time Exceeded" message is sent back
- Default TTL values: Windows = 128, Linux = 64, Cisco devices = 255

Why TTL matters:
You can sometimes identify the OS of a device based on TTL values.
If you see a packet with TTL of 124 arriving at your router, it started at 128 (Windows default) and passed through 4 routers.
Attackers sometimes manipulate TTL to evade IDS systems.

### IPv4 Addressing

IPv4 uses 32-bit addresses, written as 4 octets separated by dots.
Total possible addresses: ~4.3 billion.
Problem: The internet ran out of IPv4 addresses, which is why NAT was invented and IPv6 was created.

CIDR Notation:
192.168.1.0/24 means:
- The network is 192.168.1.0
- /24 means the first 24 bits are the network portion
- The remaining 8 bits are for host addresses
- This gives 256 addresses (254 usable for devices — .0 is network address, .255 is broadcast)

Subnet mask:
/24 = 255.255.255.0
/16 = 255.255.0.0
/8 = 255.0.0.0
/32 = 255.255.255.255 (single host)

### IPv6 Addressing

IPv6 uses 128-bit addresses, providing 340 undecillion addresses.
Written as 8 groups of 4 hex digits: 2001:0db8:85a3:0000:0000:8a2e:0370:7334

Why SOC analysts should know IPv6:
- Many organizations have IPv6 enabled but do not monitor it
- Attackers use IPv6 to bypass IPv4-based security controls
- Tunneling attacks hide IPv6 traffic inside IPv4 packets
- Always check if your security tools cover IPv6 traffic

---

## TCP — Transmission Control Protocol (Deep Dive)

### TCP Connection States

Understanding TCP connection states helps you identify network attacks.

LISTEN — Server waiting for incoming connections
SYN-SENT — Client sent SYN, waiting for SYN-ACK
SYN-RECEIVED — Server received SYN, sent SYN-ACK
ESTABLISHED — Connection fully established, data flowing
FIN-WAIT — Connection closing
TIME-WAIT — Waiting for late packets before fully closing
CLOSE-WAIT — Waiting for local application to close
CLOSED — Connection completely closed

In logs:
```
netstat output:
Proto  Local Address       Foreign Address     State
TCP    192.168.1.55:54321  172.217.14.100:443  ESTABLISHED
TCP    192.168.1.55:54322  185.220.101.47:4444 ESTABLISHED ← suspicious
TCP    0.0.0.0:3389        0.0.0.0:0           LISTENING   ← RDP open
```

### TCP Flags — Critical for Understanding Attacks

TCP packets carry flags that indicate the purpose of the packet:

SYN — Synchronize. Initiate a connection.
ACK — Acknowledge. Confirms received data.
FIN — Finish. Gracefully close the connection.
RST — Reset. Immediately terminate connection (often indicates error or rejection).
PSH — Push. Send data immediately.
URG — Urgent. High priority data.

Unusual flag combinations are attack signatures:

NULL scan: No flags set → used for stealth scanning
FIN scan: Only FIN set → used for stealth scanning
XMAS scan: SYN + FIN + URG → used for stealth scanning (packet is "lit up like a Christmas tree")
SYN flood: Only SYN sent, never completing the handshake → DoS attack

### TCP Sequence Numbers

TCP tracks every byte of data sent using sequence numbers.

This is how TCP guarantees data arrives in order and nothing is lost.

Sequence number attack — TCP Session Hijacking:
If an attacker can predict or capture the sequence number, they can inject data into an established TCP connection, essentially taking it over.

Why this matters: Older unencrypted protocols (Telnet) are vulnerable to session hijacking. This is why HTTPS is critical — even if someone intercepts the TCP stream, the data is encrypted and the sequence numbers mean nothing without the session key.

---

## UDP — User Datagram Protocol (Deep Dive)

### UDP Characteristics

No connection establishment (no handshake)
No acknowledgment — fire and forget
No ordering — packets may arrive out of order
No retransmission — if a packet is lost, it is lost
Very low overhead — headers are tiny (8 bytes vs TCP's 20+ bytes)

### When UDP is Used

DNS — Fast lookups are more important than guaranteed delivery
DHCP — Discovery and configuration
Video streaming — A lost frame is acceptable; retransmitting would cause buffering
VoIP (Voice over IP) — Latency is worse than a dropped packet
QUIC — Google's modern protocol that uses UDP but adds reliability at the application layer
Gaming — Speed matters, occasional packet loss is acceptable
NTP (Network Time Protocol) — Time synchronization

### UDP-Based Attacks

UDP Flood:
Attacker sends massive volumes of UDP packets to random ports.
Victim tries to process each packet, consuming CPU.
When no application is listening on the target port, victim sends ICMP "port unreachable" response — consuming more resources.
Result: Denial of service.

DNS Amplification:
Attacker spoofs victim's IP and sends small DNS queries to many open DNS resolvers.
DNS resolvers send large responses to the victim's IP.
Attacker uses small packets to generate large floods at the victim.
Amplification factor can be 50-100x.

UDP Port Scanning:
Attacker sends UDP packets to various ports.
If port is closed: ICMP "port unreachable" response.
If port is open: No response (or application response).
Slower and less reliable than TCP scanning.

---

## ICMP — Internet Control Message Protocol

ICMP is used for network diagnostics and error reporting, not for application data.

Common ICMP types:

Type 0 — Echo Reply (ping response)
Type 3 — Destination Unreachable (various codes: port unreachable, host unreachable, network unreachable)
Type 8 — Echo Request (ping)
Type 11 — Time Exceeded (TTL expired)

Security uses of ICMP:

Ping sweep (host discovery):
Attacker sends ICMP Echo Requests to a range of IPs.
Systems that respond with Echo Reply are alive.
```
Ping sweep to 192.168.1.0/24:
192.168.1.1 → Reply (router)
192.168.1.5 → No reply (down or firewalled)
192.168.1.10 → Reply (server)
...
```

ICMP tunneling:
Like DNS tunneling, attackers can hide data inside ICMP packets.
A ping response (ICMP Echo Reply) can carry 32-1472 bytes of data payload.
Malware can use ICMP for C2 communication because many firewalls allow ICMP.
Detection: ICMP packets with unusually large payloads or high frequency.

---

## ARP — Address Resolution Protocol

ARP operates at Layer 2 and bridges Layer 3 (IP) and Layer 2 (MAC addresses).

Problem: When computer A wants to send data to IP 192.168.1.10, it knows the IP but not the MAC address needed for the actual Ethernet frame.

ARP solution:
A broadcasts: "Who has IP 192.168.1.10? Tell 192.168.1.5."
All devices on the local network receive this.
The device with IP 192.168.1.10 responds: "I have that IP. My MAC is 00:50:56:AB:CD:EF."
Now A knows the MAC address and can send the Ethernet frame.

ARP table:
Each computer maintains an ARP table (cache) mapping IP addresses to MAC addresses.

```
arp -a output:
Interface: 192.168.1.5
  Internet Address    Physical Address      Type
  192.168.1.1         00-50-56-c0-00-01     dynamic
  192.168.1.10        00-50-56-ab-cd-ef     dynamic
```

### ARP Poisoning (Man-in-the-Middle)

ARP is inherently insecure — it trusts all ARP replies without authentication.

Attack:
Attacker: "I have IP 192.168.1.1 (the gateway). My MAC is AA:BB:CC:DD:EE:FF." (FAKE)
Victim's ARP table: 192.168.1.1 → AA:BB:CC:DD:EE:FF (attacker's MAC)

Now all of victim's traffic intended for the gateway goes to the attacker.
The attacker forwards it to the real gateway (so the connection still works).
But the attacker can read, modify, or drop the traffic.

Detection:
- Dynamic ARP inspection on switches
- ARP table changes logged by network monitoring
- Sudden change in MAC address for a known IP

---

## Real Examples

Example 1 — Reading netstat for investigation:
```
Active Connections on LAPTOP-JSMITH:

Proto  Local Address          Foreign Address        State
TCP    192.168.1.55:49812     52.113.194.132:443     ESTABLISHED  (Teams - Microsoft)
TCP    192.168.1.55:49813     216.58.204.100:443     ESTABLISHED  (Google - browser)
TCP    192.168.1.55:49820     185.220.101.47:8080    ESTABLISHED  ← suspicious
UDP    192.168.1.55:68        0.0.0.0:*              (DHCP client)
UDP    0.0.0.0:5353           0.0.0.0:*              (mDNS - normal)
```
The connection to 185.220.101.47:8080 stands out — unknown IP on an alternate HTTP port.

Example 2 — TCP flag analysis:
```
IDS Alert: SYN scan detected
Source: 45.142.212.100
Destination: 203.0.113.50
Packets: SYN to port 22, then SYN to port 80, then SYN to port 443...
         No ACK after any SYN-ACK responses
Pattern: Half-open scan (SYN only, never completing handshake)
```
Port scan using SYN flag only — stealth scanning. The attacker is mapping open ports without completing connections (which would be logged).

Example 3 — ICMP anomaly:
```
Source: 192.168.5.22
Destination: 93.184.216.34 (external)
Protocol: ICMP Echo Request (type 8)
Frequency: 1 per second
Payload size: 1,024 bytes (normal ping is 32-64 bytes)
Duration: 3 hours continuous
```
Normal pings are small and infrequent. Continuous, large ICMP packets to an external IP for 3 hours strongly suggests ICMP tunneling for C2 communication.

---

## Summary

TCP/IP is the foundation protocol of all networks.
IP handles addressing (source/destination IP) and routing.
TCP provides reliable, ordered delivery with connection states and flags.
UDP is fast and stateless — used for DNS, DHCP, streaming.
ICMP handles diagnostics — but can be abused for tunneling and reconnaissance.
ARP maps IPs to MAC addresses locally — and is vulnerable to poisoning.
Understanding TCP flags (SYN, ACK, FIN, RST) helps you identify scanning and attack patterns.

---

## Practice Questions

**Easy:**
1. What does TTL do in an IP packet?
2. What is the difference between TCP and UDP? Give a use case for each.
3. What does ARP do?

**Medium:**
4. You see a SYN packet from an external IP to your web server's port 443. You never see the corresponding ACK (completing the handshake). Then the same IP sends SYN to port 22, port 3389, port 3306. What is this?
5. A computer is sending ICMP echo requests every second to an external IP, with 1,000-byte payloads, for hours. Normal ping payloads are 32 bytes. What might this indicate?

**Thinking Questions:**
6. An attacker on your local network performs ARP poisoning targeting the CFO's computer. The attacker poisons the ARP table so the CFO's computer thinks the attacker's laptop is the default gateway. The CFO then logs into the company's banking portal over HTTPS. What can the attacker see? What protects the CFO?
7. A computer shows a TCP ESTABLISHED connection to an external IP on port 443. The connection has been active for 4 hours with data flowing in tiny amounts (a few bytes every minute). What does this pattern suggest, and why does using port 443 make it harder to detect?
