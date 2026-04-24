# Lesson 5.1 — What Is a Cyber Attack?

**Phase:** 5 — Introduction to Cybersecurity
**Prerequisite:** All Phase 4 lessons
**Time to complete:** 30 minutes

---

## Simple Explanation

A cyber attack is when someone tries to access, damage, or steal from a computer system without permission.

Just as a physical break-in involves someone entering a building they are not supposed to be in, a cyber attack involves someone entering a computer system or network they are not authorized to access.

The key difference: physical break-ins are visible. Cyber attacks are often invisible. The attacker may be sitting in a different country, using a keyboard, and the "breaking in" happens silently in the middle of the night.

---

## Who Attacks? (Threat Actors)

Understanding who is attacking you helps you understand what they want and how they operate.

### Script Kiddies
Low-skill attackers who use tools created by others without fully understanding them.
Motivation: Fun, showing off, minor disruption.
Threat level: Low to medium.
They use public exploits, automated scanning tools, brute-force scripts.
What they go after: Any vulnerable system — opportunistic.

### Cybercriminals
Organized, financially motivated attackers.
Motivation: Money — ransomware, credit card theft, business fraud.
Threat level: Medium to very high.
Operate like businesses — teams, customer service for ransomware victims, negotiation.
What they go after: Companies with data to steal or money to extort.

### Nation-State Attackers (APT — Advanced Persistent Threat)
Government-sponsored or military groups conducting cyber espionage or sabotage.
Motivation: Intelligence gathering, political influence, economic advantage, critical infrastructure disruption.
Threat level: Very high.
Highly sophisticated, patient, well-funded, custom-built tools.
Well-known groups: APT28 (Russia), APT41 (China), Lazarus Group (North Korea).
What they go after: Government, defense, critical infrastructure, high-value corporations.

### Hacktivists
Attackers motivated by ideology or politics.
Motivation: Making a political statement, disrupting organizations they disagree with.
Threat level: Medium.
Common tactics: Website defacement, DDoS attacks, data leaks.
Examples: Anonymous, groups targeting specific governments or corporations.

### Insider Threats
Employees, contractors, or partners with legitimate access who misuse it.
Motivation: Financial gain (selling data), revenge (fired employee), espionage (recruited by competitor/nation-state).
Threat level: Very high — they already have access.
They know the systems, the processes, the weaknesses.
Harder to detect because their activities can look like legitimate business activity.

---

## The Anatomy of an Attack — The Kill Chain

The Cyber Kill Chain (developed by Lockheed Martin) describes the stages of a typical attack. Understanding these stages helps you recognize where in the attack you are and what to do.

### Stage 1 — Reconnaissance
The attacker gathers information about the target.

Passive reconnaissance: Gathering publicly available information.
- Company website (employee names, email formats, technologies used)
- LinkedIn (employee roles, departments, technologies)
- WHOIS (domain registration information)
- Google dorking (searching for sensitive files accidentally exposed online)
- Shodan (finding internet-exposed systems)

Active reconnaissance: Directly probing the target.
- Port scanning
- Subdomain enumeration
- Banner grabbing (identifying software versions)
- Social engineering calls

What SOC sees: Port scans from external IPs, unusual external queries to your DNS server, increased scanning activity.

### Stage 2 — Weaponization
The attacker prepares the attack tool.

Creating or customizing malware.
Setting up a phishing email with a malicious attachment.
Preparing an exploit for a specific vulnerability in the target's software.

What SOC sees: Nothing yet — this happens on the attacker's side.

### Stage 3 — Delivery
The attacker delivers the weapon to the target.

Methods:
- Phishing email with malicious attachment or link
- Drive-by download (visiting a compromised website)
- Physical device (USB drop)
- Exploitation of a public-facing service
- Supply chain attack

What SOC sees: Suspicious email, unusual downloads, exploit attempts against web servers.

### Stage 4 — Exploitation
The weapon exploits a vulnerability to execute code.

Examples:
- User opens the malicious document → macro runs
- Browser visits exploit page → browser vulnerability exploited
- Vulnerable web server receives malicious request → code executed

What SOC sees: EDR alerts, suspicious process creation, exploitation signatures in IDS.

### Stage 5 — Installation
Malware establishes persistence on the system.

Methods:
- Registry Run keys
- Scheduled tasks
- New services
- DLL hijacking
- Boot sector modification

What SOC sees: Registry changes, new scheduled tasks, new services, suspicious files written to disk.

### Stage 6 — Command and Control (C2)
The malware establishes communication with the attacker.

The attacker now has remote control of the infected system.
Methods: HTTP/HTTPS beaconing, DNS tunneling, C2 over legitimate cloud services (Dropbox, Pastebin, GitHub).

What SOC sees: Unusual outbound traffic, regular beaconing, connections to new/suspicious domains.

### Stage 7 — Actions on Objectives
The attacker achieves their goal.

Goals vary by attacker:
- Data exfiltration (stealing intellectual property, customer data, credentials)
- Ransomware deployment (encrypting files for ransom)
- Lateral movement (spreading to more systems)
- Persistence (establishing long-term access)
- Destruction (deleting data, causing damage)

What SOC sees: Large data transfers, mass file encryption, new accounts, deletion of backups, Active Directory changes.

---

## MITRE ATT&CK Framework

The MITRE ATT&CK framework is a comprehensive knowledge base of attacker tactics and techniques, based on real-world observations.

It organizes attacks into:
Tactics — the "why" (what the attacker is trying to achieve): Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.

Techniques — the "how" (specific methods): T1566 Phishing, T1059 Command and Scripting Interpreter, T1078 Valid Accounts, etc.

Why MITRE ATT&CK matters for SOC:
- Standardizes how we describe attack behaviors
- Helps identify gaps in detection coverage
- Aligns with many SIEM detection rules
- When you see an EDR or SIEM alert, it often references a MITRE technique ID

---

## Types of Attacks (Quick Overview)

You will learn these in depth in the next lessons. This is the overview:

Malware — Malicious software (viruses, trojans, ransomware, spyware, worms, rootkits)
Phishing — Deceptive emails tricking users into providing credentials or downloading malware
Ransomware — Malware that encrypts files and demands payment
Man-in-the-Middle (MitM) — Intercepting communications between two parties
SQL Injection — Injecting malicious SQL code into database queries
Cross-Site Scripting (XSS) — Injecting malicious scripts into web pages
DDoS — Overwhelming a service with traffic to make it unavailable
Social Engineering — Manipulating humans rather than hacking systems
Insider Threat — Misuse of legitimate access
Supply Chain Attack — Compromising software or hardware before it reaches the target

---

## Summary

A cyber attack is unauthorized access to or damage of computer systems.
Threat actors range from script kiddies to nation-states with different motivations and capabilities.
The Kill Chain describes attack stages: Recon → Weaponize → Deliver → Exploit → Install → C2 → Act.
MITRE ATT&CK provides a standardized framework for describing attacker tactics and techniques.
SOC analysts can detect attacks at each Kill Chain stage — earlier detection = less damage.

---

## Practice Questions

**Easy:**
1. What is the Kill Chain?
2. Name three types of threat actors.
3. What does APT stand for?

**Medium:**
4. At which stage of the Kill Chain does malware establish a backdoor for persistent access? What evidence would this leave?
5. Why are insider threats particularly difficult to detect?

**Thinking Questions:**
6. An attacker is performing reconnaissance against your company. They look at your company's LinkedIn page and learn the names and email addresses of IT staff. They look at your company website and learn that you use Cisco routers. They use Shodan and find that your VPN gateway runs an outdated firmware version. How does this reconnaissance help them plan the next stages of their attack?
7. MITRE ATT&CK Technique T1078 is "Valid Accounts" — using legitimate credentials to access systems. Why is this technique particularly dangerous for detection? What would a SOC analyst need to see to detect it?
