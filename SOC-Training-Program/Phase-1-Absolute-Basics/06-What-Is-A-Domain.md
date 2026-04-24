# Lesson 1.6 — What Is a Domain?

**Phase:** 1 — Absolute Basics
**Prerequisite:** Lesson 1.5
**Time to complete:** 25 minutes

---

## Simple Explanation

A domain is a human-friendly name for a computer or group of computers on the internet.

Instead of remembering that Google's server is at IP address 142.250.80.4, you type "google.com" and your computer figures out the rest.

A domain is registered by an organization. It becomes their identity on the internet and often inside their internal network too.

---

## Real-World Analogy

An IP address is like a GPS coordinate (40.7128° N, 74.0060° W).
A domain is like the name of the place (New York City).

Both refer to the same location. But humans remember names, not coordinates. The internet uses both — humans use names, computers use numbers.

When you type "amazon.com" into your browser, a DNS server acts like a GPS navigator — it translates the name into coordinates (an IP address) that computers can use.

---

## Structure of a Domain

A domain has multiple parts, read right to left:

Example: mail.company.com

.com = Top-Level Domain (TLD) — the highest level. Other TLDs: .org, .net, .gov, .edu, .io, country codes like .uk, .de, .ru
company = Second-Level Domain — this is the part the organization registered and owns
mail = Subdomain — a subdivision of company.com, often pointing to a specific server

Full domain: mail.company.com
This likely points to company's email server.

Other examples:
vpn.company.com → VPN server
login.company.com → Login portal
api.company.com → API server

---

## Domain Name System (DNS)

DNS is the system that translates domain names into IP addresses.

Think of DNS as the internet's phone book.
Before smartphones, you looked up a name in the phone book to get their number.
DNS does the same thing: you give it a name (google.com), it gives you the number (IP address).

How DNS works:
1. You type google.com in your browser.
2. Your computer checks its local cache (has it seen this before?). If yes, it uses the cached IP.
3. If not, your computer asks your DNS resolver (usually provided by your ISP or your company's DNS server).
4. The resolver checks its cache. If not found, it queries the root DNS servers.
5. Root servers point to the .com name servers.
6. .com name servers point to Google's name servers.
7. Google's name servers provide the IP address.
8. Your computer receives the IP and connects to Google.

This entire process takes milliseconds.

---

## Internal Domains (Active Directory)

Inside a corporate network, there is often an internal domain — a private DNS system that only works inside the company.

Example internal domain: company.local or company.internal or company.corp

All company computers are members of this domain. The domain is managed by Active Directory (a Microsoft service you will learn about in Phase 6).

When an employee logs in to their Windows computer, they log in to the domain:
Username: john.smith
Domain: COMPANY
Full login: COMPANY\john.smith or john.smith@company.com

This internal domain controls:
- Who can log in to which computers
- What files employees can access
- What software is installed
- Security policies

The internal domain is completely separate from the internet-facing domain, though they often share the same name (company.com).

---

## How Attackers Abuse Domains

Understanding domain abuse is critical for SOC analysts.

Technique 1 — Typosquatting:
Attacker registers a domain that looks like a real one but has a small typo.
Real: paypal.com
Fake: paypa1.com (number 1 instead of letter l)
Real: microsoft.com
Fake: micosoft.com

The fake site looks identical to the real one. Users accidentally type the wrong address or click a link without reading carefully, and they land on the attacker's site.

Technique 2 — Homograph Attack:
Attackers use characters from other alphabets that look like Latin letters.
The Cyrillic "а" looks identical to the Latin "a" but they are different characters.
The domain looks correct at a glance but is actually different.

Technique 3 — Newly Registered Domains:
Attackers register domains that are only a few days or hours old.
Legitimate websites are usually registered months or years before being used in attacks.
A newly registered domain sending you email or receiving data from your network is highly suspicious.

Technique 4 — Domain Generation Algorithm (DGA):
Sophisticated malware uses algorithms to generate hundreds of random domain names.
The malware tries each one until it finds the attacker's active command-and-control server.
This makes it hard to block because the domains change constantly.
Example DGA domains: xjkqrp.com, amzntv.net, updateservice93.com

Technique 5 — Subdomain Abuse:
Legitimate services allow users to create subdomains.
user-controlled.legitimate-service.com
If company data is being sent to a subdomain of a normally trusted service, it may be an exfiltration technique.

---

## SOC Perspective — Domain Indicators

When investigating an alert, domains are key indicators:

Questions to ask about a domain:
1. Is this domain known malicious? (Check threat intelligence feeds)
2. When was it registered? (Check WHOIS — newly registered = suspicious)
3. Who registered it? (Check WHOIS for registrant info)
4. Does it look like a typosquatted version of a legitimate domain?
5. What does it resolve to? (What IP does it point to?)
6. Have other employees or systems contacted this domain?
7. Is the domain categorized? (Web proxies categorize domains — uncategorized = suspicious)

Domain analysis tools you will use:
- WHOIS — finds registration information
- VirusTotal — checks domain against threat intelligence
- Any.run / URLScan — analyzes the domain/URL safely
- Threat intelligence platforms — checks if domain is known malicious

---

## Real Examples

Example 1 — Normal domain activity:
```
User: sarah.jones@company.com
Query: teams.microsoft.com
Resolved to: 52.113.194.132
Time: 10:15:23
```
Normal. User connecting to Microsoft Teams.

Example 2 — Typosquatted domain:
```
User: david.lee@company.com
Query: paypa1.com (number 1, not letter l)
Resolved to: 185.220.101.47
Time: 14:33:07
Action: DNS query allowed
```
Suspicious. "paypa1.com" is not the real PayPal. This could be a phishing site. The analyst should check: Was this from a phishing email? Did the user enter credentials? Was any data submitted?

Example 3 — DGA domain:
```
Source: 192.168.5.22 (LAPTOP-BWILLIAMS)
DNS Query: xjkqrp19ns.com
Result: NXDOMAIN (domain does not exist)
Repeated: 247 times in 10 minutes with different random domains
Time: 02:00:00
```
Very suspicious. A computer making hundreds of DNS queries to random-looking domains that don't exist is almost certainly infected with DGA malware. The malware is trying to find its command-and-control server.

Example 4 — Newly registered domain:
```
Sender: invoice@company-billing-2024.com
Email sent to: accounting@company.com
Domain registered: 3 days ago
Email content: "Please review attached invoice"
Attachment: invoice.pdf
```
High-risk phishing. "company-billing-2024.com" registered 3 days ago, with a PDF attachment, sent to the accounting department — classic business email compromise (BEC) attack.

---

## Common Mistakes Beginners Make

Mistake 1: Trusting a domain just because it has HTTPS.
Reality: Attackers can get SSL certificates for malicious domains. HTTPS means the connection is encrypted — not that the site is legitimate.

Mistake 2: Only looking at the main domain and ignoring subdomains.
Reality: Attackers use long subdomains to hide malicious content: invoice.legitimage.company-billing.com — the actual domain is company-billing.com (suspicious), not company.com.

Mistake 3: Not checking when a domain was registered.
Reality: Domain age is one of the fastest checks you can do. A domain registered yesterday being used in an enterprise email is almost always malicious.

Mistake 4: Assuming an uncategorized domain is fine.
Reality: Threat intelligence tools categorize known domains. If a domain has no category and no history, treat it with extra suspicion.

---

## Summary

A domain is a human-readable name for computers on a network.
DNS translates domain names to IP addresses.
Internal corporate domains (Active Directory) control company resources.
Attackers abuse domains through typosquatting, newly registered domains, and DGA.
Domain analysis is a core SOC skill — check age, reputation, registration, and category.
Never trust a domain based on appearance alone — verify with threat intelligence.

---

## Practice Questions

**Easy:**
1. What does DNS do?
2. What is a subdomain? Give an example.
3. What is a TLD?

**Medium:**
4. An employee receives an email from "support@micros0ft.com" (zero instead of o). What type of attack is this? What is the risk?
5. You see DNS queries to 47 different random-looking domains (like qzxpwr.net, mnjvkr.com) from the same computer in one minute. What does this suggest?

**Thinking Questions:**
6. How would you determine if a domain is legitimate or suspicious? List the checks you would perform and explain why each check matters.
7. An email arrives with an attachment claiming to be a shipping invoice. The sender domain was registered 2 days ago, has no reputation in threat intelligence, and the domain name is "fedex-shipping-update-2024.com". Walk through your analysis of this situation.
