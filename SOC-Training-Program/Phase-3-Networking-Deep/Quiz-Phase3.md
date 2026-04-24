# Phase 3 Quiz — Networking Deep Dive

**Time limit:** 30 minutes
**Total questions:** 15
**Passing score:** 12/15

---

## Section A — Multiple Choice (1 point each)

**Question 1:**
At which OSI layer do IP addresses operate?

A) Layer 2
B) Layer 3
C) Layer 4
D) Layer 7

---

**Question 2:**
What does the TTL (Time To Live) field in an IP packet do?

A) Defines how long the packet can be stored in a buffer
B) Limits how many routers a packet can pass through before being discarded
C) Controls the session timeout
D) Sets the maximum payload size

---

**Question 3:**
A SYN flood attack works by:

A) Sending many complete TCP connections to overwhelm a server
B) Sending SYN packets without completing the three-way handshake, exhausting server resources
C) Flooding the network with ICMP packets
D) Sending malformed UDP packets

---

**Question 4:**
ARP (Address Resolution Protocol) is used to:

A) Translate domain names to IP addresses
B) Assign IP addresses to devices
C) Map IP addresses to MAC addresses on a local network
D) Route packets between networks

---

**Question 5:**
Which protocol is used for routing between major internet networks (Autonomous Systems)?

A) OSPF
B) EIGRP
C) BGP
D) RIP

---

**Question 6:**
A proxy server provides which of the following for SOC analysis?

A) Encryption of all web traffic
B) Full URL-level visibility and logging of web requests
C) IP address assignment
D) Domain name resolution

---

**Question 7:**
NetFlow data differs from full packet capture in that NetFlow:

A) Captures all packet contents
B) Only captures encrypted traffic
C) Records metadata summaries (who talked to whom, timing, volume) without the actual content
D) Is used only for internal network monitoring

---

## Section B — Scenario Analysis (2 points each)

**Question 8:**
Read this NetFlow record and answer: Is anything suspicious? If so, what?
```
Start          End            Src IP          Dst IP           Protocol  Bytes
03:00:00.000   03:00:00.001   185.220.101.47  192.168.10.5     TCP/22    342
03:00:01.000   03:00:01.001   185.220.101.47  192.168.10.5     TCP/22    428
[continues every second for 47 minutes]
03:47:00.000   03:47:35.122   185.220.101.47  192.168.10.5     TCP/22    2,847,022
```

---

**Question 9:**
A firewall log shows:
```
Source: 192.168.1.0/24 (all internal workstations)
Destination: 192.168.2.50 (Domain Controller)
Port: 88 (Kerberos)
Pattern: Each workstation sends a burst of 500 requests to port 88 within 10 seconds
Time: 14:30:00
```
What attack technique does this pattern suggest?

---

**Question 10:**
An IDS alert fires for "ARP spoofing detected":
```
Previous ARP entry: 192.168.1.1 → MAC 00:50:56:C0:00:01
New ARP entry:      192.168.1.1 → MAC 00:AA:BB:CC:DD:EE (new/unknown MAC)
Computer affected:  192.168.1.100 (LAPTOP-CJOHNSON)
```
What attack is occurring? What is the danger to LAPTOP-CJOHNSON?

---

**Question 11:**
A traceroute from an internal server to an external IP shows:
```
1   192.168.1.1     1ms   (internal gateway)
2   10.100.0.1      2ms   (internal routing)
3   192.168.5.88    1ms   ← UNEXPECTED (another internal IP)
4   203.0.113.1     8ms   (ISP)
5   ...
```
Why is hop 3 (192.168.5.88) suspicious? What might it indicate?

---

## Section C — Short Answer (2 points each)

**Question 12:**
Explain ICMP tunneling in your own words. How would you detect it in logs?

---

**Question 13:**
A security engineer says: "We have a firewall, so we are protected." Give two specific reasons why a firewall alone is insufficient protection.

---

**Question 14:**
Explain the OSI layer at which each of these attacks operates:
a) SQL injection
b) SYN flood
c) ARP poisoning
d) BGP hijacking

---

**Question 15:**
You see this in proxy logs:
```
Time: 03:15:22  Source: 192.168.3.44  User: -  
Method: GET  URL: http://185.220.101.47/beacon.php?id=LAPTOP-HWANG&data=
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Response: 200  Bytes: 12

Time: 03:16:22  Source: 192.168.3.44  User: -  
Method: GET  URL: http://185.220.101.47/beacon.php?id=LAPTOP-HWANG&data=
Response: 200  Bytes: 12
[Repeated exactly every 60 seconds for 3 hours]
```
Identify every suspicious element and explain what this tells you about what is happening on the computer at 192.168.3.44.

---

## Answer Key

**Section A:**
1. B — Layer 3 (Network layer)
2. B — Limits the number of router hops
3. B — Sends SYNs without completing handshakes
4. C — Maps IP to MAC on local network
5. C — BGP routes between Autonomous Systems
6. B — Full URL logging for web requests
7. C — Metadata without content

**Section B:**

8. (2 points) Suspicious — highly suspicious. The pattern shows an external IP (185.220.101.47) making SSH connections to an internal server (192.168.10.5) every second for 47 minutes. This is almost certainly a brute force SSH attack. After 47 minutes, there is suddenly a large data transfer (2.8 MB) — this likely indicates the brute force succeeded and the attacker is now downloading files or executing commands. Immediate response: check SSH auth logs for success, isolate the server, block the external IP.

9. (2 points) This pattern resembles Kerberoasting — an attack where an attacker requests Kerberos service tickets for multiple service accounts to crack their passwords offline. The burst of Kerberos requests from multiple workstations is suspicious. However, it could also be a legitimate Kerberos issue. Context matters: check if this correlates with any other suspicious activity, what accounts were requested, and whether ticket responses were captured.

10. (2 points) ARP poisoning / ARP spoofing attack. The attacker has sent fake ARP replies claiming their MAC address owns the default gateway IP (192.168.1.1). LAPTOP-CJOHNSON's ARP table has been poisoned. All of CJOHNSON's traffic intended for the gateway will now be sent to the attacker's machine (MAC 00:AA:BB:CC:DD:EE). The attacker can intercept, read, and potentially modify all of CJOHNSON's network traffic — a classic man-in-the-middle attack.

11. (2 points) Hop 3 is an internal IP (192.168.5.88) that appears in the path between the internal router (hop 2) and the ISP (hop 4). This should not be there — traffic going to the internet should not route back through an internal network segment. This could indicate: a misconfigured routing policy, a rogue routing device, or a man-in-the-middle device that has inserted itself into the traffic path. Investigate what device owns 192.168.5.88.

**Section C:**

12. (2 points) ICMP tunneling hides data inside ICMP echo request/reply packets (pings). Normally, pings carry a tiny payload (32-64 bytes) for testing connectivity. Malware can embed data in this payload to communicate with a C2 server, since firewalls typically allow ICMP. Detection: ICMP packets with unusually large payloads (more than 64 bytes), high frequency of ICMP traffic to external IPs, ICMP traffic to unknown/suspicious external destinations, ICMP traffic that continues for extended periods.

13. (2 points) Any two of: (1) Firewalls cannot inspect encrypted HTTPS traffic (without SSL inspection), allowing malware to communicate undetected; (2) Firewalls cannot protect against threats already inside the network (lateral movement happens on the internal network); (3) Firewalls only control traffic at the perimeter — if an attacker enters via a phishing email, they are already inside; (4) Firewalls do not detect application-layer attacks like SQL injection; (5) Firewalls do not detect credential theft or account compromise.

14. (2 points)
a) SQL injection — Layer 7 (Application) — attack is in the application data
b) SYN flood — Layer 4 (Transport) — attack abuses TCP connection mechanics
c) ARP poisoning — Layer 2 (Data Link) — attack manipulates MAC-to-IP mappings
d) BGP hijacking — Layer 3 (Network) — attack manipulates routing between networks

15. (2 points) Every suspicious element:
- Time 3:15 AM — unusual; no user logged in (User: -)
- User field is "-" — automated request, not from a browser with logged-in user
- URL contains "beacon.php" — literally named "beacon" (a term for malware C2 check-in)
- URL contains computer name in the query string (data exfiltration of system info)
- User-Agent: MSIE 6.0 / Windows NT 5.1 — extremely outdated (IE6, Windows XP) — attacker using fake/old user agent
- Response is only 12 bytes — server sending a tiny response (command? ack?)
- Exactly every 60 seconds for 3 hours — perfectly regular timing = automated malware beaconing
- Conclusion: LAPTOP-HWANG is infected with malware that is checking in with a C2 server every minute, receiving commands, and the whole thing started at 3:15 AM when no users were active.
