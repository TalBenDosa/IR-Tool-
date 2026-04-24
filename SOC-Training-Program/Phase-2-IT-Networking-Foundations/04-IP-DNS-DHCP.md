# Lesson 2.4 — IP Addresses, DNS, and DHCP Together

**Phase:** 2 — IT & Networking Foundations
**Prerequisite:** Lessons 1.5, 1.6, and 2.3
**Time to complete:** 35 minutes

---

## Overview — The Three Systems That Make Networks Work

Every time a device connects to a network and accesses the internet, three fundamental systems work together:

DHCP — Gives the device an IP address (its identity on the network)
DNS — Translates names to addresses (its navigation system)
IP — Carries data to the right destination (its postal system)

Understanding how these interact — and how attackers abuse each — is fundamental SOC knowledge.

---

## DHCP — Dynamic Host Configuration Protocol

### What It Does

When a device connects to a network (like when you plug in your laptop or connect to Wi-Fi), it does not have an IP address yet. DHCP automatically provides one.

Without DHCP, a network administrator would have to manually assign an IP address to every device. In an organization with 1,000 employees and multiple devices each, this would be chaos.

DHCP does more than assign an IP. It gives the device a complete network configuration:
- IP Address — the device's address on this network
- Subnet Mask — defines which part of the IP is the network and which is the device
- Default Gateway — the router address (where to send traffic going outside this network)
- DNS Server addresses — where to look up domain names

### How DHCP Works (Step by Step)

Step 1 — DHCP Discover:
The device broadcasts: "Is there a DHCP server? I need an IP address!"
Source IP: 0.0.0.0 (no IP yet)
Destination: 255.255.255.255 (broadcast to everyone on the network)

Step 2 — DHCP Offer:
The DHCP server responds: "Here, take IP address 192.168.1.105. I'm reserving it for you."

Step 3 — DHCP Request:
The device replies: "Yes, I'll take 192.168.1.105, thank you."

Step 4 — DHCP Acknowledge:
The DHCP server confirms: "It's yours. Lease time: 8 hours."

The acronym is DORA: Discover, Offer, Request, Acknowledge.

### DHCP Leases

The DHCP assignment is not permanent — it is a lease with an expiration time (typically 8 hours, 24 hours, or 7 days depending on configuration).

When the lease expires:
- The device requests a renewal
- The DHCP server may give the same IP or a new one
- If the device disconnects and reconnects, it may get a different IP

DHCP Lease Log Example:
```
2024-03-15 08:00:00 DHCPACK on 192.168.1.105 to 00:50:56:ab:cd:ef (LAPTOP-JSMITH) via eth0
2024-03-15 16:00:00 DHCPACK on 192.168.1.105 to 00:50:56:ab:cd:ef (LAPTOP-JSMITH) via eth0 (renewal)
```

### Why DHCP Matters for SOC

When investigating an alert involving an IP address, you need to know:
"Which computer was using this IP at the time of the incident?"

DHCP logs tell you exactly which MAC address and hostname was assigned each IP at every point in time.

Key DHCP investigation workflow:
```
Alert: Suspicious activity from 192.168.5.33 at 2024-03-15 14:22:00

DHCP Log query: Who had 192.168.5.33 on 2024-03-15 at 14:22?
Result: LAPTOP-SBROWN, MAC: 00:50:56:cd:ef:12

Active Directory query: Who uses LAPTOP-SBROWN?
Result: sarah.brown@company.com
```
Now you know the alert involves Sarah Brown's laptop.

### DHCP Attacks

DHCP Starvation:
An attacker sends thousands of DHCP requests with fake MAC addresses, exhausting the pool of available IP addresses. Legitimate devices cannot get an IP and cannot connect to the network.

Rogue DHCP Server:
An attacker sets up their own DHCP server on the network.
When devices request an IP, the rogue server responds first.
The rogue server assigns a legitimate IP but points to:
- A malicious DNS server (that redirects users to fake websites)
- A malicious default gateway (that intercepts all traffic — man-in-the-middle attack)

---

## DNS — Domain Name System (Deep Dive)

### DNS Record Types

DNS is not just about translating domain names to IPs. It stores different types of records:

A Record — Maps a hostname to an IPv4 address.
Example: www.company.com → 203.0.113.50

AAAA Record — Maps a hostname to an IPv6 address.
Example: www.company.com → 2001:db8::1

CNAME Record — Alias; maps one hostname to another.
Example: mail.company.com → exchange.company.com

MX Record — Mail exchanger; where email for this domain should be delivered.
Example: company.com → mail.company.com (priority 10)
Used for validating email sources in security investigations.

TXT Record — Text information; used for SPF, DKIM, DMARC (email security — Phase 4).
Example: "v=spf1 include:office365.com ~all"

PTR Record — Reverse DNS; maps an IP address back to a hostname.
Example: 203.0.113.50 → www.company.com
Used for verifying that an IP actually belongs to who it claims.

NS Record — Name servers; which servers are authoritative for this domain.

SOA Record — Start of Authority; administrative information about the domain.

### DNS in SOC — Threat Intelligence

DNS logs are gold. Every connection starts with a DNS query.

If you can see DNS traffic, you can see every domain that every device tried to contact — even if the actual connection was encrypted.

DNS-based indicators:
- High volume of DNS queries to one domain (may indicate DGA or beacon)
- DNS queries to newly registered domains
- DNS queries returning unusual IPs (may indicate DNS hijacking)
- DNS queries to known-malicious domains (match against threat intel feeds)
- Very long subdomains (DNS tunneling — data hidden in DNS queries)
- Non-existent domain responses (NXDOMAIN) in high volumes (DGA)

DNS Tunneling:
Attackers encode data inside DNS queries to bypass firewalls.
Firewalls usually allow DNS traffic. If blocked from using HTTP/HTTPS, an attacker can send and receive data hidden inside DNS requests.

Normal DNS query:
```
Query: mail.google.com → A record → 142.250.80.100
```

DNS tunneling:
```
Query: dGhpcyBpcyBzdG9sZW4gZGF0YQ==.evil.com → NXDOMAIN
```
The long random-looking subdomain is actually base64-encoded data being exfiltrated.

Signs of DNS tunneling:
- Very long subdomain names (normal domains have short subdomains)
- High frequency of queries to the same parent domain
- Base64 or hex-encoded strings in subdomains
- Unusually large DNS query/response sizes

### DNS Hijacking

DNS hijacking is when an attacker modifies DNS responses to redirect users to malicious sites.

Types:
1. Local DNS hijacking — malware on the device changes its DNS server settings
2. Router DNS hijacking — malware changes the router's DNS settings, affecting all devices on the network
3. DNS server compromise — attacker compromises the DNS server directly
4. BGP hijacking — advanced attack that redirects DNS traffic at the internet routing level

How to detect: A user reports that banking website looks different. DNS query shows unusual IP for the domain. PTR record does not match the claimed organization.

---

## IP — Working with IP Addresses in Investigations

### IP Reputation

Every IP address has a reputation based on its history. Tools that check IP reputation:

VirusTotal — check if IP is associated with malware or phishing
AbuseIPDB — database of IPs reported for abuse
Shodan — search engine for internet-connected devices (shows what services an IP exposes)
IPinfo.io — geolocation, ISP, organization information
MaxMind — geolocation database
Threat Intelligence Platforms (e.g., MISP, ThreatConnect)

### Geolocation

Every public IP address is registered to a specific organization and associated with a geographic region.

Geolocation is not perfectly accurate but gives you the country and often the city.

Why geolocation matters:
- If your company is US-based and a login comes from Russia at 3 AM, that is suspicious
- If an IP claims to be from Microsoft but geolocation shows a VPS in Vietnam, that is suspicious
- Impossible travel: User logs in from New York at 10 AM, then from Lagos at 10:15 AM — physically impossible

### WHOIS Information

WHOIS is a public database of domain and IP registration information.

For a domain: Who registered it? When? What contact information?
For an IP: Which organization owns this IP block? What country? What ISP?

WHOIS lookup for a suspicious domain:
```
Domain: company-billing-2024.com
Registrar: Namecheap, Inc.
Registered On: 2024-03-13 (2 days ago)
Expires On: 2025-03-13
Registrant: REDACTED FOR PRIVACY
Name Servers: ns1.hostinger.com
```
Newly registered, privacy-protected (common for attackers), generic name server. High suspicion.

---

## Putting It Together — A Complete Investigation Example

Alert: User john.smith@company.com clicked a link in an email and their browser connected to an unknown external domain.

Step 1 — Identify the destination:
DNS log shows: john.smith's workstation queried "company-documents-2024.com"
DNS response: 185.220.101.47

Step 2 — Investigate the domain:
WHOIS: Registered 3 days ago. Privacy protected.
VirusTotal: 7/90 vendors flag it as malicious.
Threat Intel: Associated with phishing campaigns.

Step 3 — Investigate the IP:
IP 185.220.101.47: Geolocation = Netherlands. Registered to a hosting provider known for bulletproof hosting.
AbuseIPDB: 47 reports of abuse in past 30 days.

Step 4 — Identify the computer:
DHCP logs: IP 192.168.1.88 at 14:22:00 → LAPTOP-JSMITH

Step 5 — Assess impact:
Proxy logs: 192.168.1.88 made one GET request to company-documents-2024.com/login.html
User submitted form data (indicated by POST request).
The user likely entered credentials on a phishing page.

Step 6 — Response:
Reset john.smith's password immediately.
Check his email for other suspicious emails.
Check other employees who may have received the same email.
Block the domain and IP at the firewall.

---

## Summary

DHCP assigns IP addresses to devices automatically. DHCP logs tell you which device had which IP at what time.
DNS translates domain names to IP addresses. DNS logs reveal every domain device on your network tried to contact.
IP addresses are core evidence. Reputation, geolocation, and WHOIS provide context.
Together, these three systems let you trace an attack from the alert all the way back to the specific user and device.

---

## Practice Questions

**Easy:**
1. What does DHCP stand for and what does it do?
2. What is an MX record?
3. What is a DHCP lease?

**Medium:**
4. An alert shows suspicious activity from IP 192.168.10.77. You check DHCP logs and find this IP was used by two different computers on the day of the incident (it was reassigned mid-day). How does this complicate your investigation?
5. What is DNS tunneling and how would you recognize it in DNS logs?

**Thinking Questions:**
6. An attacker sets up a rogue DHCP server on your network. They configure it to assign the same IP addresses but point to a different DNS server. What attack can they now perform? Walk through the full chain of events.
7. You see a computer making DNS queries to the domain "invoice.microsoft.com.attacker.net". Is this microsoft.com? Explain how you read this domain correctly and what the actual parent domain is.
