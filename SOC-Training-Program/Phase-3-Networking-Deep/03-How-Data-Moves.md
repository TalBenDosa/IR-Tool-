# Lesson 3.3 — How Data Moves in a Network

**Phase:** 3 — Networking Deep Dive
**Prerequisite:** Lessons 3.1 and 3.2
**Time to complete:** 30 minutes

---

## Complete Flow: From Browser to Server and Back

Understanding the complete path data takes is essential for understanding where attacks happen and where your tools provide visibility.

Let us trace a complete request from an employee's browser to an external website and back.

Scenario: User john.smith opens Chrome and types "https://company-sharepoint.com"

---

### Step 1 — DNS Resolution

Before any connection, the computer needs to find the IP address.

John's computer:
1. Checks local DNS cache — is "company-sharepoint.com" already known? No.
2. Checks the hosts file (C:\Windows\System32\drivers\etc\hosts) — is it there? No.
3. Asks the configured DNS server (e.g., 10.0.0.5 — company's internal DNS server).
4. Company DNS server checks if it knows — yes, it resolves to 104.215.148.63.
5. John's computer gets the IP: 104.215.148.63.

SOC visibility: DNS logs on the company's DNS server capture every query.
Attacker opportunity: Malware may modify the hosts file to redirect legitimate domains.

---

### Step 2 — TCP Connection (Three-Way Handshake)

Now John's browser initiates a TCP connection to 104.215.148.63 port 443.

1. Browser sends SYN packet:
   Source: 192.168.1.55:54321 → Destination: 104.215.148.63:443

2. Server responds with SYN-ACK:
   Source: 104.215.148.63:443 → Destination: 192.168.1.55:54321

3. Browser sends ACK:
   Source: 192.168.1.55:54321 → Destination: 104.215.148.63:443
   Connection established.

SOC visibility: Firewall logs show this connection. IDS may capture the packets.

---

### Step 3 — TLS Handshake (HTTPS)

Because this is HTTPS, the browser and server negotiate encryption before any application data is sent.

1. Client Hello: Browser announces supported encryption methods and its random value.
2. Server Hello: Server selects encryption method, provides its SSL certificate.
3. Certificate validation: Browser verifies the certificate is valid and issued by a trusted CA.
4. Key exchange: Both sides generate a shared encryption key without sending it over the network.
5. Finished: Both sides confirm encryption is working. All subsequent data is encrypted.

SOC visibility: Without SSL inspection, the SOC can see that a connection happened but NOT what data was exchanged. This is the core challenge with encrypted traffic.

With SSL inspection (TLS interception): The company's firewall decrypts, inspects, and re-encrypts traffic. The firewall can see the actual URLs visited and data transferred.

---

### Step 4 — HTTP Request

The browser sends an encrypted HTTP request:
```
GET / HTTP/2
Host: company-sharepoint.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml
Accept-Language: en-US,en;q=0.9
Cookie: AuthToken=eyJhbGciOiJIUzI1...
Authorization: Bearer eyJhbGciOiJSUzI1...
```

Key fields that matter for SOC:
- Host — the actual domain being accessed (visible in proxy logs)
- User-Agent — what browser/software is making the request (attackers may use unusual user agents)
- Cookie / Authorization — session tokens (if stolen, attacker can use these)

---

### Step 5 — Data Travels Through the Network

The encrypted HTTP request leaves John's computer and travels:

John's computer (192.168.1.55)
↓ (via Ethernet/Wi-Fi to local switch)
Switch (Layer 2 — forwards based on MAC address)
↓
Default Gateway / Router (192.168.1.1)
↓ (Company firewall checks the connection)
Firewall / Proxy
↓ (If proxy is configured, traffic goes to proxy first)
Proxy server (inspects URL, logs the request, forwards if allowed)
↓ (Travels across the internet through multiple routers)
Multiple internet routers (each router has a routing table — decides the best path)
↓
SharePoint server (104.215.148.63)

SOC tools at each hop:
- Switch: Layer 2 logs (MAC addresses, VLAN information)
- Firewall: Logs the IP/port/action (allow/block)
- Proxy: Logs the full URL, user agent, response code, bytes transferred
- IDS/IPS: Scans for attack signatures in the packet stream

---

### Step 6 — Server Response

The server sends back an HTTP response:
```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 42381
Date: Fri, 15 Mar 2024 10:22:31 GMT
[HTML content of the page]
```

The response travels back through the same path.

---

## How Routing Works

When a packet travels across the internet, it passes through many routers.

Each router makes an independent decision: "Based on the destination IP, which direction should I forward this packet?"

Routing tables:
Every router has a routing table — a map of IP ranges and which interface to send them out.

Example routing table entry:
```
Destination    Gateway         Interface
0.0.0.0/0      203.0.113.1     eth0    (default route — send unknown traffic here)
192.168.1.0/24 0.0.0.0         eth1    (local network — direct delivery)
10.0.0.0/8     10.255.0.1      eth2    (internal company network)
```

The default route (0.0.0.0/0) is used when no specific route matches — it sends the packet to the next router in the direction of the internet.

Traceroute:
A diagnostic tool that shows the path a packet takes.
```
traceroute google.com
1  192.168.1.1      0.5 ms   (your router)
2  10.0.0.1         2 ms     (ISP first hop)
3  72.14.236.1      8 ms     (Google peering point)
4  142.250.80.4     10 ms    (Google's server)
```

Attackers use traceroute to map network paths.
Defenders use it to understand network topology and diagnose routing issues.

---

## BGP — Border Gateway Protocol

BGP is the routing protocol used between major internet networks (called Autonomous Systems or AS).

Each major internet network (Google, Comcast, AT&T, AWS) has an AS number and advertises which IP ranges it owns.

BGP hijacking:
An attacker or misconfigured router advertises ownership of an IP range it does not own.
Other routers believe the false advertisement and start routing traffic to the attacker.
This has happened in real incidents — traffic for major services temporarily routed through other countries.

This is advanced but knowing it exists is important for understanding why geolocation of traffic is not 100% reliable.

---

## Proxy Servers — Your Network's Eyes

A proxy server sits between internal users and the internet.

When properly configured, ALL outbound web traffic goes through the proxy.

Benefits:
- Visibility: Every URL, every file downloaded, every request logged
- Filtering: Block malicious or inappropriate websites by category
- Caching: Store frequently visited pages to save bandwidth
- SSL Inspection: Decrypt HTTPS to inspect content

Proxy log example:
```
2024-03-15 10:22:31 192.168.1.55 john.smith GET https://company-sharepoint.com/ 200 42381 "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" 0.234s
2024-03-15 10:23:45 192.168.1.55 john.smith GET https://evildomain.com/payload.ps1 200 15240 "PowerShell/5.1" 0.089s
```

The second line is alarming:
- The user agent is PowerShell (not a browser — automated request)
- The URL ends in .ps1 (PowerShell script)
- The destination is an unknown domain

This is malware downloading a PowerShell script — and the proxy caught it.

---

## NetFlow — Seeing Traffic Without Seeing Content

NetFlow (and similar protocols: sFlow, IPFIX) records summaries of network conversations without capturing the actual content.

Think of it as the phone bill — it shows who called whom, when, for how long, and how much was transferred — but not what was said.

NetFlow record example:
```
Start Time   End Time     Src IP         Dst IP           Src Port  Dst Port  Proto  Packets  Bytes
10:22:31.000 10:22:31.234 192.168.1.55   104.215.148.63   54321     443       TCP    45       12,440
03:14:22.000 03:14:52.122 192.168.1.88   185.220.101.47   38291     443       TCP    2,841    4,718,012
```

The second record is suspicious:
- 4.7 MB transferred at 3:14 AM
- To an unknown external IP
- 30 seconds of activity at 3 AM

NetFlow is invaluable for detecting:
- Large data transfers (exfiltration)
- C2 beaconing (regular small connections)
- Port scanning (many short connections to different ports)
- Lateral movement (unusual internal-to-internal traffic)

---

## Summary

Data travels through multiple hops: switch → router/firewall → proxy → internet routers → destination.
DNS resolution happens before any TCP connection.
TLS/HTTPS encryption hides content but not metadata (destination IP, timing, volume).
Routing tables determine the path through the internet.
Proxies provide full URL visibility for web traffic.
NetFlow captures traffic summaries — who talked to whom, when, how much.
Each hop is a point of visibility for your security tools.

---

## Practice Questions

**Easy:**
1. What happens before a browser can connect to a website?
2. What is a routing table?
3. What does a proxy server log?

**Medium:**
4. HTTPS encrypts web traffic. What information can a SOC analyst still see even without decrypting the traffic?
5. NetFlow data shows 4.7 GB transferred from an internal server to an external IP between 2:00 AM and 2:15 AM. No firewall rule blocked it. What does this indicate and what should you do?

**Thinking Questions:**
6. An attacker compromises a computer inside your network. They want to exfiltrate 10 GB of stolen data. They decide to use HTTPS to do it over port 443 in small chunks spread over 2 weeks. Why did they choose this approach? What would you need to detect it?
7. A proxy log shows: source IP 192.168.1.77, user-agent "curl/7.64.0", requesting http://185.220.101.47/update.exe, response code 200, 2.4 MB downloaded, at 4:33 AM. Explain every suspicious element and what this suggests.
