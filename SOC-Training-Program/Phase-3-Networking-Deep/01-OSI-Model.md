# Lesson 3.1 — The OSI Model

**Phase:** 3 — Networking Deep Dive
**Prerequisite:** All Phase 2 lessons
**Time to complete:** 40 minutes

---

## Why the OSI Model Matters

The OSI model is a framework that describes how network communication happens in seven layers.

You will hear the OSI model referenced constantly in security conversations:
"This attack works at Layer 3." "The IDS inspects at Layer 7." "That firewall is a Layer 4 device."

Understanding the OSI model helps you understand where in the communication stack an attack happens, what tools detect it, and how to respond.

---

## Simple Explanation

Think of the OSI model as a seven-floor building.

When you send a message from one computer to another, the message travels down all seven floors on the sender's side, across the network, and then up all seven floors on the receiver's side.

Each floor (layer) has a specific job. Each layer only cares about its own job and communicates with the layers directly above and below it.

---

## The Seven Layers (Top to Bottom)

### Layer 7 — Application Layer

This is what you interact with directly.

Examples: Web browser (HTTP/HTTPS), email client (SMTP, IMAP), file transfer (FTP), DNS.

This is where your data is — the actual content of your request.

When you type a URL and press Enter, Layer 7 creates an HTTP request.

Security relevance: Application-layer attacks target the application directly — SQL injection, cross-site scripting, phishing, malware delivered as documents.

### Layer 6 — Presentation Layer

Handles data formatting, encryption, and compression.

Translates data between the application format and the network format.

Examples: SSL/TLS encryption (HTTPS), JPEG compression, ASCII/Unicode encoding.

When your browser connects to an HTTPS website, Layer 6 handles the encryption and decryption.

Security relevance: SSL/TLS inspection happens here. When a firewall decrypts HTTPS traffic to inspect it (SSL inspection), it operates at Layer 6.

### Layer 5 — Session Layer

Manages sessions — the ongoing conversation between two computers.

It establishes, maintains, and terminates connections.

Examples: NetBIOS sessions, RPC sessions, authentication sessions.

Security relevance: Session hijacking attacks target this layer. If an attacker steals your session token (the key that proves you are already logged in), they can take over your session without knowing your password.

### Layer 4 — Transport Layer

Handles end-to-end communication and reliability.

This is where TCP and UDP live.
TCP: reliable, connection-oriented, includes error checking.
UDP: fast, connectionless, no guarantee.

Adds port numbers to identify which application the data is for.

Security relevance: Port scanning, SYN flood attacks, and firewall rules (which typically filter by IP and port = Layer 3 + Layer 4) operate here. "Stateful firewall" means the firewall tracks the state of TCP connections at Layer 4.

### Layer 3 — Network Layer

Handles logical addressing and routing — getting packets from one network to another.

This is where IP addresses live.

Routers operate at Layer 3.

Security relevance: IP spoofing (faking source IP), IP-based blocking, ICMP (ping), traceroute, and routing attacks happen at this layer.

### Layer 2 — Data Link Layer

Handles communication within the same local network (LAN).

Uses MAC addresses (hardware addresses burned into network cards).

Switches operate at Layer 2.

ARP (Address Resolution Protocol) lives here — maps IP addresses to MAC addresses.

Security relevance: ARP poisoning/spoofing attacks target Layer 2. An attacker on the local network can send fake ARP replies to redirect traffic through their machine (man-in-the-middle). MAC flooding attacks overload switches.

### Layer 1 — Physical Layer

The actual physical medium: cables, wireless signals, electrical signals.

Ethernet cables, fiber optics, Wi-Fi radio signals.

Security relevance: Physical access attacks (tapping cables, rogue access points, evil twin Wi-Fi attacks). Physical security is part of the security posture.

---

## Memory Aid

The most common mnemonic (top to bottom):
"All People Seem To Need Data Processing"
Application, Presentation, Session, Transport, Network, Data Link, Physical

Bottom to top:
"Please Do Not Throw Sausage Pizza Away"
Physical, Data Link, Network, Transport, Session, Presentation, Application

---

## How Data Moves Through the Layers

When you send data (top-down on the sending side):

Layer 7 — Your browser creates an HTTP request:
"GET /index.html HTTP/1.1"

Layer 6 — The data is encrypted (if HTTPS):
The HTTP data becomes encrypted TLS data.

Layer 5 — A session is established:
The session between your browser and the server is tracked.

Layer 4 — TCP adds port numbers:
Source port: 54321 (random)
Destination port: 443 (HTTPS)
Data becomes a TCP segment.

Layer 3 — IP adds IP addresses:
Source IP: 192.168.1.55
Destination IP: 142.250.80.4
TCP segment becomes an IP packet.

Layer 2 — Ethernet adds MAC addresses:
Source MAC: your computer's MAC
Destination MAC: your router's MAC
IP packet becomes an Ethernet frame.

Layer 1 — Electrical/optical signals:
The frame is converted to bits and transmitted physically.

On the receiving end, the process reverses — each layer strips its header and passes the data up to the next layer.

---

## Encapsulation — The Key Concept

At each layer, a header is added to the data. This is called encapsulation.

Think of it like nested envelopes:
- Your message is in a small envelope (Layer 7 data)
- That envelope goes inside a TCP envelope (Layer 4 — adds port numbers)
- That goes inside an IP envelope (Layer 3 — adds IP addresses)
- That goes inside an Ethernet envelope (Layer 2 — adds MAC addresses)

When the receiving computer gets the message, it opens each envelope from outside to inside.

---

## Practical SOC Use — Which Layer Each Tool Operates At

Physical (L1): Physical security cameras, cable inspections
Data Link (L2): Switch logs, ARP tables, VLAN configuration
Network (L3): Firewall IP-based rules, router logs, IP reputation tools
Transport (L4): Firewall port-based rules, IDS/IPS signatures for port-based attacks
Session (L5): Web application firewalls (WAF) for session management
Presentation (L6): SSL inspection / TLS decryption appliances
Application (L7): WAF (application attacks), proxy logs, email security, IDS/IPS deep packet inspection

SIEM — Collects logs from all layers and correlates them.
EDR — Operates on the endpoint (all layers from that device's perspective).
Network IDS — Typically Layers 3–7.
Next-Generation Firewall — Layers 3–7 (can inspect application traffic).

---

## Real Examples — Attacks by Layer

Layer 7 — SQL Injection:
```
HTTP Request:
GET /user?id=1' OR '1'='1 HTTP/1.1
Host: company.com
```
The attack is in the application data itself. Only an application-aware tool can detect it.

Layer 4 — SYN Flood:
```
Firewall shows:
10,000 SYN packets per second from 50,000 different source IPs
Destination: 203.0.113.50:443
No SYN-ACK responses completing
```
DDoS attack at the transport layer. The attacker is flooding TCP connections.

Layer 3 — Port Scan:
```
Source: 185.220.101.47
Destinations: 203.0.113.50:22, 203.0.113.50:80, 203.0.113.50:443, 203.0.113.50:3389...
```
Attacker scanning ports at Layer 3/4 to discover what services are running.

Layer 2 — ARP Poisoning:
```
ARP Table on switch:
IP: 192.168.1.1 → MAC: 00:50:56:AA:BB:CC (legitimate router)
→ Changed to →
IP: 192.168.1.1 → MAC: 00:AA:BB:CC:DD:EE (attacker's machine)
```
All traffic destined for the router now goes to the attacker first (man-in-the-middle).

---

## Common Mistakes Beginners Make

Mistake 1: Trying to memorize the model without understanding what each layer does.
Reality: Focus on the concept — each layer has a job. The specific layer numbers are reference points, not the goal.

Mistake 2: Thinking all security tools work at all layers.
Reality: A basic firewall (Layer 3/4) cannot detect an SQL injection (Layer 7). Understanding which tool works where helps you know what you can and cannot see.

Mistake 3: Confusing the OSI model with the TCP/IP model.
Reality: The TCP/IP model (next lesson) is a simplified 4-layer model used in practice. The OSI 7-layer model is the theoretical framework used for discussion. Both are useful.

---

## Summary

The OSI model describes network communication in 7 layers.
Each layer adds its own header (encapsulation) going down, and strips it going up.
Key layers for SOC: Layer 3 (IP/routing), Layer 4 (TCP/UDP/ports), Layer 7 (application).
Different attacks and tools operate at different layers.
Understanding layers helps you choose the right tool and understand where in the communication stack a threat exists.

---

## Practice Questions

**Easy:**
1. What is Layer 3 of the OSI model and what does it use for addressing?
2. What is Layer 4 and what protocols live there?
3. What is encapsulation?

**Medium:**
4. A Next-Generation Firewall (NGFW) can inspect application traffic. What layer does this involve? Why can a traditional firewall not do this?
5. An attacker performs ARP poisoning on your local network. At which OSI layer does this attack occur? What is the effect?

**Thinking Questions:**
6. An intrusion detection system alerts on "suspicious HTTP traffic" to your web server. At which OSI layer is this traffic? What does the word "suspicious" mean at Layer 7 versus Layer 4?
7. You are told "the firewall blocked a port scan." Walk through what this means at the OSI layer level — what did the attacker send, what did the firewall see, and at which layers?
