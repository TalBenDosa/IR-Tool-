# Phase 6 Quiz — Introduction to the SOC

**Time limit:** 20 minutes
**Total questions:** 12
**Passing score:** 10/12

---

**Question 1:** An alert fires in the SIEM. It appears to be a false positive based on initial review. What should a Tier 1 analyst do?

A) Close the alert immediately without documentation
B) Escalate to Tier 2 immediately
C) Close the alert WITH documentation explaining the reasoning
D) Wait 24 hours to confirm it is a false positive

---

**Question 2:** What is the primary advantage of EDR over traditional antivirus?

A) EDR is cheaper
B) EDR uses behavior-based detection that can catch novel attacks and fileless malware
C) EDR uses signature updates more frequently
D) EDR only works on servers

---

**Question 3:** SIEM normalization means:

A) Making all alerts the same priority
B) Converting logs from different formats into a common format for unified analysis
C) Removing duplicate alerts
D) Encrypting log data in transit

---

**Question 4:** Which security tool specifically monitors web application traffic for SQL injection and XSS attacks?

A) Firewall
B) IDS
C) WAF (Web Application Firewall)
D) DLP

---

**Question 5:** Mean Time to Detect (MTTD) measures:

A) How quickly analysts resolve tickets
B) How long it takes from when an attack starts to when the SOC detects it
C) How many alerts are handled per hour
D) How fast logs are ingested by the SIEM

---

**Question 6:** True or False — A SIEM collects logs only from Windows systems.

True / False

---

**Question 7:** True or False — EDR can isolate a compromised endpoint from the network remotely, without physical access.

True / False

---

**Question 8 (2 points):**
You receive this SIEM alert:
```
Rule: Brute Force Detected
User: sarah.jones@company.com
Failed Logins: 12 in 3 minutes
Source IPs: 185.220.101.47, 185.220.101.48, 185.220.101.50
Service: VPN
Final event: Login SUCCESS at 14:22:47 from 185.220.101.47
```
Is this a true positive or false positive? What is the immediate risk? What are your next three actions?

---

**Question 9 (2 points):**
Explain the difference between IDS and IPS. If an IDS detects a SQL injection attempt against your web server, what does it do? What would an IPS do instead?

---

**Question 10 (2 points):**
A SOC analyst is investigating an alert. The SIEM shows a failed login attempt. The EDR shows nothing on the device. The proxy shows the user visited a legitimate site. Should the analyst close this as a false positive?

What additional information should they check before deciding?

---

**Question 11:**
What does DLP stand for and what does it do?

---

**Question 12:**
You are a Tier 1 analyst and cannot determine from your investigation whether an alert is a true positive or false positive. What should you do?

A) Close it as a false positive to keep the queue clear
B) Leave it open indefinitely
C) Escalate to Tier 2 with your findings and the reason for uncertainty
D) Ask the user if they did anything suspicious

---

## Answer Key

1. C — Always document false positive closures (builds institutional knowledge, tracks alert patterns)
2. B — Behavior-based detection for novel and fileless attacks
3. B — Converting different log formats into a common format
4. C — WAF protects web applications at Layer 7
5. B — Time from attack start to SOC detection
6. False — SIEM collects from all systems: firewalls, network devices, cloud services, Linux, Windows, applications, etc.
7. True — EDR can remotely isolate endpoints from the network while maintaining the management connection
8. (2 points) TRUE POSITIVE. 12 failed logins from 3 different IPs in 3 minutes = brute force/credential stuffing. The final successful login is the most critical element — the attack succeeded. Immediate risk: sarah.jones's VPN account is compromised. An attacker is now inside the network. Next three actions: (1) Immediately disable sarah.jones's VPN session and account; (2) Check what the attacker did after logging in — what systems were accessed? (3) Force password reset and enable MFA on the account; and notify Tier 2 for deeper investigation of what the attacker accessed during their session.
9. (2 points) IDS (Intrusion Detection System) is passive — it monitors traffic and generates alerts but does not block. An IDS detecting SQL injection would create an alert for analysts to review while the traffic continues to the server. IPS (Intrusion Prevention System) is active — it sits inline and blocks traffic matching attack signatures in real-time. An IPS detecting SQL injection would drop the malicious request before it reaches the web server. Trade-off: IPS blocks attacks in real-time but can have false positives that block legitimate traffic.
10. (2 points) Not necessarily — a single data point is not enough. Additional information to check: (1) How many failed attempts were there before this event — is there a brute force pattern? (2) Where is the source IP? Is it the user's normal location? (3) What time did this occur — is it the user's normal work hours? (4) Has the user been seen logging in from this IP before? (5) Did anything happen after the failed login — was there a later successful login? The SIEM, DHCP logs, authentication logs, and threat intel all need to be checked before closing.
11. DLP = Data Loss Prevention. It monitors and controls data movement to prevent sensitive data from leaving the organization without authorization. Examples: blocking emails with credit card numbers, preventing uploads of confidential files to personal cloud storage, alerting on large data transfers.
12. C — Escalate to Tier 2 with your findings and the reason for uncertainty. Never close an alert you are uncertain about — escalation is the professional and responsible action.
