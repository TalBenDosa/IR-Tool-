# Lesson 7.1 — How SOC Analysts Think: The Complete Framework

**Phase:** 7 — Thinking Like a SOC Analyst
**Prerequisite:** All Phase 6 lessons
**Time to complete:** 45 minutes

---

## The Analyst Mindset

Being a SOC analyst is not just about knowing technical facts — it is about thinking in a structured, systematic way when under pressure.

Great analysts share these qualities:
- Skepticism: Question everything. Do not assume something is normal just because it looks normal.
- Curiosity: Want to understand what is happening. Ask "why" constantly.
- Patience: Investigations take time. Resist the urge to close quickly.
- Structure: Follow a methodology. Do not jump to conclusions.
- Context awareness: The same event can be normal or suspicious depending on context.
- Communication: Clearly articulate findings, even when uncertain.

---

## What Makes Something Suspicious?

### The Three Questions

For every event you analyze, ask three questions:

1. Is this expected?
   Does this activity match what I would normally see for this user, system, or time?

2. Is this authorized?
   Even if unusual, was someone supposed to do this? Is there a change request? Did IT plan maintenance tonight?

3. Does this make sense?
   Does the story add up? Does the context support a benign explanation?

If you cannot answer YES to all three, investigate further.

---

## Understanding Normal vs Anomaly

You cannot detect anomalies without knowing what is normal. Building a baseline is critical.

### Behavioral Baseline

Normal for a finance employee:
- Logs in Monday-Friday, 8 AM - 6 PM
- From IP addresses in New York
- Uses Excel, SAP, Outlook
- Accesses finance file shares
- Sends email to internal colleagues and known vendors
- VPN not used (works in the office)

What would be anomalous for the same employee:
- Login at 3 AM on Sunday
- Login from IP in Romania
- Running PowerShell
- Accessing the engineering file server
- Large file download from sensitive server
- VPN connected when no remote work is scheduled

### System Baseline

Normal for a web server:
- Listens on port 80 and 443
- Makes outbound connections to update servers
- Generates Apache/nginx logs
- No interactive user sessions
- Stable CPU and memory usage

What would be anomalous for the same server:
- Outbound connection to an unknown external IP
- Interactive SSH login from the internet at 3 AM
- PHP process spawning bash shells
- Sudden CPU spike to 100%
- New files created in web directory

### Network Baseline

Normal:
- Workstations connect to domain controllers, DNS servers, file servers
- Traffic goes out to the internet via the proxy
- Mail traffic goes through the mail gateway

Anomalous:
- Workstations connecting directly to each other (east-west) without going through a server
- Traffic bypassing the proxy
- Internal server sending mail directly to the internet (not through mail gateway)

---

## True Positive vs False Positive — The Core Decision

Every alert is one of four things:

TRUE POSITIVE (TP): The alert is correct. A real threat was detected.
True Positive — high severity: Immediate response required.
True Positive — informational: Document and monitor.

FALSE POSITIVE (FP): The alert fired, but it is not actually a threat. Normal activity that matched the rule.
Example: A security scan triggers an alert for "port scanning." The scan was scheduled and authorized.

TRUE NEGATIVE (TN): No alert, no threat. Everything is fine.

FALSE NEGATIVE (FN): There IS a threat, but no alert fired. The most dangerous category — you did not know you were being attacked.

### Why FP Rate Matters

If your SIEM generates 1,000 alerts per day and 990 are false positives, analysts waste time and become desensitized. Real threats (the 10 true positives) get missed because analysts are burned out chasing false alarms.

This is called "alert fatigue" — and it has contributed to many major breaches.

Goal: High detection rate (catch real threats) with low false positive rate (do not waste time on non-threats).

---

## The Investigation Framework — 7 Steps

Follow this framework for every alert.

### Step 1 — Read the Alert

Before doing anything:
- What is the alert name? What does it detect?
- What is the severity? (Critical, High, Medium, Low)
- What are the key indicators? (User, IP, hostname, domain, timestamp)
- What rule triggered this? (Understanding the rule helps you understand what to look for)

Example:
```
Alert Name: Possible Credential Brute Force
Severity: High
User: john.smith@company.com
Source IP: 185.220.101.47
Failed attempts: 47 in 5 minutes
Service: Microsoft 365 (Azure AD)
Triggered at: 03:14:22 UTC
```

### Step 2 — Validate the Data

Is the data accurate?
- Is the timestamp correct (check timezone)?
- Is the user account a real account in the directory?
- Is the IP address real? Internal or external?
- Does the source system actually exist?

Mistakes to avoid:
- Acting on an alert based on test/demo data
- Being fooled by clocks with incorrect timezone settings

### Step 3 — Gather Context

For every entity in the alert, gather background:

For the USER:
- Who is this? What department? What role?
- Where do they normally work from?
- What is their normal working schedule?
- Have they been in the news, involved in HR issues, or recently left the company?
- Do they have privileged access?

For the IP ADDRESS:
- Internal or external?
- If external: geolocation, ASN, threat intelligence reputation
- If internal: DHCP lookup to identify the device and user

For the HOSTNAME:
- What system is this? Server, workstation, printer?
- Who owns it?
- What is its normal role and behavior?

For the DOMAIN/URL:
- Is it known good (Microsoft, Google, Cisco)?
- Age (WHOIS)?
- Reputation (VirusTotal, threat intel)?
- Category (proxy categorization)?

### Step 4 — Expand the Investigation

Now look beyond the alert itself.

For a brute force alert:
- Did the brute force succeed? Is there a successful login after the failures?
- What did the account do after the (possibly) successful login?
- Are other accounts being targeted from the same IP?
- Is this IP associated with known attacks?

"Pivot" on indicators — every indicator leads to more information:
IP → What else connected from this IP?
User → What else did this user do today?
Domain → What other systems contacted this domain?
Process → What other processes did this parent start?

### Step 5 — Correlate Across Sources

Check multiple log sources for the same event:
- Does the SIEM alert match what the EDR shows?
- Does the Windows event log match the SIEM's interpretation?
- Are there related events in proxy logs, DNS logs, email logs?

Cross-source correlation often reveals the full picture that no single source shows.

Example:
SIEM alert: "High — Malicious domain contacted"
EDR: "powershell.exe made a network connection to evil.com"
Proxy: "evil.com accessed, 2.4 MB downloaded"
DNS: "evil.com resolved 30 seconds before the EDR event"
File system (EDR): "payload.exe written to C:\Windows\Temp\"
Process (EDR): "payload.exe executed, spawned cmd.exe"

Full picture: A PowerShell script connected to evil.com, downloaded payload.exe, and executed it. Confirmed malware delivery. True Positive — Critical.

### Step 6 — Make the Decision

Based on your investigation:

Is this a TRUE POSITIVE?
→ Document your findings clearly
→ Classify severity based on actual impact
→ If Critical or High: immediately notify Tier 2 and follow the incident response playbook
→ If Medium or informational: document and monitor

Is this a FALSE POSITIVE?
→ Document WHY it is a false positive (which specific evidence makes it benign)
→ Recommend tuning the rule to reduce future false positives
→ Close the alert

Are you UNCERTAIN?
→ Document what you found and what is unclear
→ Escalate to Tier 2 with your findings
→ NEVER close an unresolved alert as FP just because you could not find evidence of a threat

### Step 7 — Document Everything

Documentation is not optional. In a security incident:
- Your investigation notes are legal evidence
- Future analysts will build on your work
- Management needs reports
- Post-incident analysis requires complete records

Every investigation note should include:
- What triggered the investigation
- What sources you checked
- What you found (or did not find)
- What your conclusion is and why
- What actions were taken
- Timestamp of each step

---

## Common Analyst Mistakes (With Corrections)

Mistake 1: Closing alerts too quickly to keep the queue clean.
Reality: A missed true positive is far more dangerous than a slow false positive investigation. Speed must not compromise accuracy.

Mistake 2: Looking at the alert in isolation.
Reality: The alert is the starting point, not the endpoint. Always pivot and correlate.

Mistake 3: Concluding "safe" because no malware hash was detected.
Reality: Fileless attacks, LotL techniques, and novel malware have no hash to detect.

Mistake 4: Trusting the status quo ("It's always been this way, so it must be fine.")
Reality: Attackers often establish themselves slowly and stay persistent. Long-term presence can normalize.

Mistake 5: Not considering insider threats.
Reality: Insider threats are the hardest to detect because their activity looks legitimate.

Mistake 6: Ignoring context.
Reality: A 3 AM login from the CFO's account might be the CFO on a business trip (legitimate) OR an attacker (malicious). Without context, you cannot tell.

Mistake 7: Not escalating when uncertain.
Reality: Escalation is a strength, not a weakness. Senior analysts are there to help.

---

## The Six Questions Every Analyst Should Ask

For every alert, ask:

1. WHO: Who is the user, system, or entity involved?
2. WHAT: What happened exactly? What was the action?
3. WHEN: When did this happen? Is the timing suspicious?
4. WHERE: Where did this originate? Internal? External? Which country?
5. WHY: Why might this have happened? Benign or malicious?
6. HOW: How did this happen? What is the attack technique or normal explanation?

---

## Summary

Great analysts are skeptical, curious, structured, and patient.
Normal vs anomaly: you must know the baseline to detect deviations.
True Positive, False Positive — always document your reasoning.
Seven-step investigation framework: read → validate → gather context → expand → correlate → decide → document.
Always pivot: every indicator leads to more data.
Document everything — investigations are legal records.

---

## Practice Questions

**Easy:**
1. What are the 6 questions every analyst should ask for every alert?
2. What is alert fatigue and why is it dangerous?
3. What is a false negative?

**Medium:**
4. You receive an alert: "Impossible travel — user sarah.jones logged in from New York at 9 AM, then from Tokyo at 10 AM (same day)." Is this definitely a compromise? What are the possible benign explanations? What would you investigate to determine which is true?
5. An analyst closes every alert within 2 minutes to keep the queue "clean." Why is this dangerous? What should the analyst do instead?

**Thinking Questions:**
6. You are investigating an alert about a PowerShell execution on a finance executive's laptop. You find nothing malicious in the execution. You check the network, find a connection to an unusual IP but it is categorized as "business software." You check the file system and find no new files. You are about to close as FP. What additional check might reveal something you missed? What is the most dangerous thing you could do at this point?
7. Design a mental checklist for investigating a "suspicious login" alert. What are the 8-10 specific questions you would answer before making a TP/FP decision?
