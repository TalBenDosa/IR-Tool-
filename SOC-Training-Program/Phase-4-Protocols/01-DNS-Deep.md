# Lesson 4.1 — DNS (Domain Name System) — Deep Dive

**Phase:** 4 — Protocols
**Prerequisite:** All Phase 3 lessons
**Time to complete:** 45 minutes

---

## What Is DNS? (Simple)

DNS is the internet's phone book.

When you type "google.com", your computer does not know where Google's servers are. DNS tells it. DNS translates human-readable names (google.com) into machine-usable IP addresses (142.250.80.4).

Without DNS, you would need to memorize IP addresses for every website — like memorizing phone numbers for thousands of people without a contact list.

---

## When Is DNS Used?

Every single time a network connection is made to a named destination.

Every website visit. Every email sent. Every application that connects to a server. Even internal systems connecting to each other by hostname. DNS is happening constantly in the background.

On an average corporate network, tens of thousands of DNS queries occur every hour.

---

## How DNS Works Behind the Scenes (Complete Flow)

### The DNS Hierarchy

DNS is organized as a hierarchy:

Root Level (.)
The invisible dot at the top of every domain name.
13 root server clusters worldwide, operated by different organizations.
They know where to find the TLD name servers.

Top-Level Domain (TLD)
.com, .org, .net, .gov, .uk, .de, etc.
Each TLD has its own name servers.
.com name servers know where to find registrations for all .com domains.

Second-Level Domain
google, microsoft, company, etc.
This is what organizations register and own.

Subdomain
www, mail, api, vpn, etc.
Created by the domain owner to point to specific servers.

### Complete Resolution Process

1. User types: www.google.com

2. Browser checks its local cache:
   Has it looked up www.google.com recently? If yes, use cached IP.
   Cache TTL (Time To Live) determines how long this entry is valid.

3. OS checks hosts file:
   C:\Windows\System32\drivers\etc\hosts (Windows)
   /etc/hosts (Linux)
   If an entry exists here, use it and skip all DNS servers.
   (Attackers modify this file to redirect users to malicious sites.)

4. OS asks the configured DNS resolver:
   Usually the company's internal DNS server or ISP's DNS.
   This is the "recursive resolver" — it does the work of finding the answer.

5. Resolver checks its own cache:
   Has it looked up www.google.com recently? If yes, return cached answer.

6. If not cached, resolver starts from the top:
   Asks a root server: "Who handles .com?"
   Root server replies: "a.gtld-servers.net"

7. Resolver asks the .com TLD server:
   "Who handles google.com?"
   .com server replies: "ns1.google.com, ns2.google.com" (Google's name servers)

8. Resolver asks Google's name servers:
   "What is the IP for www.google.com?"
   Google replies: "142.250.80.4, TTL=300"

9. Resolver caches the answer (for 300 seconds = 5 minutes) and returns to the user.

10. Browser connects to 142.250.80.4.

### DNS Record Types (Complete Reference)

A Record — Hostname to IPv4 address
```
www.google.com.    300   IN  A   142.250.80.4
```

AAAA Record — Hostname to IPv6 address
```
www.google.com.    300   IN  AAAA   2607:f8b0:4004:808::2004
```

CNAME Record — Alias (points to another hostname)
```
mail.company.com.  300   IN  CNAME  exchange.company.com.
```
(mail.company.com is just another name for exchange.company.com)

MX Record — Mail exchanger (where to deliver email)
```
company.com.       300   IN  MX  10  mail.company.com.
```
Priority 10 — lower number = higher priority.

TXT Record — Arbitrary text (used for SPF, DKIM, DMARC, domain verification)
```
company.com.       300   IN  TXT  "v=spf1 include:spf.protection.outlook.com -all"
```

PTR Record — Reverse DNS (IP to hostname)
```
4.80.250.142.in-addr.arpa.   300   IN  PTR   www.google.com.
```

NS Record — Authoritative name servers for a domain
```
company.com.       300   IN  NS   ns1.company.com.
company.com.       300   IN  NS   ns2.company.com.
```

SOA Record — Start of authority (administrative info)
```
company.com.       3600  IN  SOA  ns1.company.com. admin.company.com. (
    2024031501  ; serial number
    3600        ; refresh
    900         ; retry
    604800      ; expire
    300 )       ; minimum TTL
```

### DNS Response Codes

NOERROR — Query succeeded, answer found
NXDOMAIN — Domain does not exist (No such domain)
SERVFAIL — Server failed to process the query
REFUSED — Server refused to answer
FORMERR — Malformed query

NXDOMAIN is especially important — a high volume of NXDOMAIN responses is a key DGA malware indicator.

---

## SOC Perspective — Why DNS Matters

DNS is one of the most powerful visibility tools you have because:
1. It happens before every connection
2. Even encrypted connections (HTTPS) generate plaintext DNS queries
3. Every device on your network queries your internal DNS servers
4. DNS logs give you a view of every domain any device tried to contact

If you can see DNS, you can see intent — even if you cannot see the actual traffic.

---

## How Attackers Abuse DNS

### 1. DNS Tunneling

Concept: Encode data in DNS queries and responses to bypass firewalls.

Most firewalls allow DNS traffic (port 53) because DNS is required for all network communication. If an attacker can encode data in DNS queries, they can exfiltrate data or receive commands from a C2 server through a channel that is typically trusted.

Normal DNS query: `mail.google.com → 142.250.2.17`

DNS tunneling query:
```
dGhpcyBpcyBleGZpbHRyYXRlZCBkYXRh.evil-c2.com → NXDOMAIN (or any response)
```
The subdomain contains base64-encoded exfiltrated data.

The C2 server receives the DNS query (with the encoded data in the subdomain) and responds.
The malware sends the next chunk in the next query.

Tools used: iodine, dns2tcp, dnscat2

Detection signs:
- Subdomains are very long (base64 is 4/3 the size of the original data)
- High frequency of queries to the same parent domain
- Queries return NXDOMAIN consistently but keep repeating
- Unusually large DNS query/response sizes (DNS is normally tiny)
- Entropy analysis: base64 encoded strings have higher entropy than real words

Log Example — Normal vs Tunneling:
```
Normal:
14:22:31 LAPTOP-JSMITH → teams.microsoft.com A? → 52.113.194.132

DNS Tunneling:
14:22:31 LAPTOP-JSMITH → dGhpcyBpcyBzdG9sZW4gZGF0YQ==.evil-c2.com A? → NXDOMAIN
14:22:32 LAPTOP-JSMITH → aGVyZSBpcyBtb3JlIGRhdGE=.evil-c2.com A? → NXDOMAIN
14:22:33 LAPTOP-JSMITH → YW5kIG1vcmUgYW5kIG1vcmU=.evil-c2.com A? → NXDOMAIN
```

### 2. Domain Generation Algorithm (DGA)

Malware generates domain names using an algorithm. The algorithm produces hundreds or thousands of different domains. Most do not exist (NXDOMAIN), but the attacker registers one or a few of them as the actual C2.

Why DGA?
If defenders block the C2 domain, the malware just tries the next generated domain.
Defenders cannot block domains in advance because the list is effectively infinite.

Example DGA output (different families have different patterns):
Mushtari: rdsrnrgsnzifkqjd.com, hfdksafhdslkfhds.net
Suppobox: emsejfdfstnjvdmv.com, kbsxmfmdlxifkqhm.com
Shiotob: vpnhznupqsejjslg.com, qcpgkehbkpxqktmv.com

Detection:
- High volume of NXDOMAIN responses from one device
- Random-looking domain names with no dictionary words
- Domains registered very recently (if any resolve)
- Query frequency (DGA malware queries rapidly)

### 3. DNS Hijacking

Attacker modifies DNS responses so users are redirected to malicious servers.

Types:
Local: Malware modifies DNS settings on the infected device
Router: Malware/attacker compromises the router's DNS settings
DNS server: Attacker compromises the DNS server
DNS spoofing: Attacker poisons the DNS cache of a resolver with fake entries

Example:
Real: bank.com → 203.0.113.50 (legitimate bank server)
After hijacking: bank.com → 185.220.101.47 (attacker's phishing server)

User types bank.com, lands on a perfect-looking fake bank site.
User enters credentials → stolen.

Detection:
- PTR (reverse DNS) record does not match the claimed organization
- IP geolocation does not match expected location for the organization
- Users report that familiar websites look different
- SSL certificate does not match expected issuer

### 4. DNS Reconnaissance

Attackers use DNS to gather information about a target's infrastructure.

Techniques:
Zone transfer (AXFR): If a DNS server is misconfigured, an attacker can download the complete list of all hostnames and IPs in a domain.

Subdomain enumeration: Attackers guess common subdomains (mail, vpn, api, admin, dev, staging, etc.) to discover the organization's infrastructure.

Reverse DNS lookup: Look up what hostnames correspond to IP addresses to understand the target's address space.

---

## DNS in Logs — Real Examples

### Windows DNS Server Log:
```
3/15/2024 14:22:31 PM 0BC4 PACKET  00000001 UDP Rcv 192.168.1.55:51234 Q [0001 D NOERROR] A (4)mail(9)microsoft(3)com(0)
3/15/2024 14:22:31 PM 0BC4 PACKET  00000001 UDP Snd 192.168.1.55:51234 R Q [8081 DR NOERROR] A 52.113.194.132
```
Translation: Computer 192.168.1.55 asked for mail.microsoft.com and got 52.113.194.132.

### Sysmon DNS Event (Event ID 22):
```xml
<EventID>22</EventID>
<TimeCreated>2024-03-15T14:22:31.123Z</TimeCreated>
<Computer>LAPTOP-JSMITH</Computer>
<QueryName>teams.microsoft.com</QueryName>
<QueryStatus>SUCCESS</QueryStatus>
<QueryResults>type: 5 cname: teams.microsoft.com.akadns.net; ::ffff:52.113.194.132</QueryResults>
<User>john.smith@company.com</User>
<ProcessId>4521</ProcessId>
<Image>C:\Program Files\Google\Chrome\Application\chrome.exe</Image>
```
This is Sysmon's DNS log — it shows not just the query but also WHICH PROCESS made it. Chrome made this DNS query — normal.

### DGA Detection Example:
```
3/15/2024 03:00:01 AM  LAPTOP-JSMITH  Q → xjkqrp19ns.com         NXDOMAIN
3/15/2024 03:00:02 AM  LAPTOP-JSMITH  Q → qzxkjmn47rt.net         NXDOMAIN
3/15/2024 03:00:03 AM  LAPTOP-JSMITH  Q → wbmrpx83nt.org          NXDOMAIN
3/15/2024 03:00:04 AM  LAPTOP-JSMITH  Q → rkqvtn91ms.com          NXDOMAIN
[400 more NXDOMAIN responses]
3/15/2024 03:06:44 AM  LAPTOP-JSMITH  Q → plqmrx72kk.com          SUCCESS → 185.220.101.47
```
400 NXDOMAIN, then one success — the malware found its active C2 domain.

---

## Common Analyst Mistakes

Mistake 1: Trusting DNS responses without verifying.
Reality: DNS can be hijacked. Always verify that an IP actually belongs to the claimed organization.

Mistake 2: Not checking the parent domain in long URLs.
Reality: "microsoft.com.attacker.net" — the actual domain is attacker.net, not microsoft.com.

Mistake 3: Ignoring NXDOMAIN responses.
Reality: NXDOMAIN responses are critical — they reveal DGA behavior and tunneling attempts.

Mistake 4: Thinking DNS traffic is always innocuous.
Reality: DNS carries almost no content but can carry a lot of evidence. It is one of your best intelligence sources.

Mistake 5: Not checking TTL values.
Reality: A very low TTL (like 0 or 1 second) is often used by attackers for "fast flux" — rapidly changing IP addresses to evade blocking.

---

## Summary

DNS translates domain names to IPs. It is involved in every network connection.
DNS record types: A, AAAA, CNAME, MX, TXT, PTR, NS.
DNS is heavily abused: tunneling, DGA, hijacking, reconnaissance.
DNS logs reveal every domain any device tried to reach — even encrypted connections.
Key signals: NXDOMAIN floods (DGA), long subdomains (tunneling), new domains, low TTL (fast flux).
Always analyze the parent domain, not just the subdomain.

---

## Practice Questions

**Easy:**
1. What is an A record?
2. What does NXDOMAIN mean?
3. What is a DGA and why do attackers use it?

**Medium:**
4. You see DNS queries to "YWRtaW4gcGFzc3dvcmQ=.exfil.attacker.com" from an internal computer. What is this? Decode the subdomain hint: YWRtaW4gcGFzc3dvcmQ= is base64.
5. A low TTL on a domain (like 5 seconds) is suspicious. Why? What attack technique does this support?

**Thinking Questions:**
6. You need to detect DGA malware in your DNS logs. Write the criteria you would use to create an alert: What patterns would you look for? What would the alert look like?
7. An employee reports that their online banking website "looks different" today. Walk through how you would investigate whether they have been targeted by DNS hijacking.
