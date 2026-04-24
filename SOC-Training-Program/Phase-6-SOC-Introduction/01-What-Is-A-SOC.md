# Lesson 6.1 — What Is a SOC and Security Tools Overview

**Phase:** 6 — Introduction to the SOC
**Prerequisite:** All Phase 5 lessons
**Time to complete:** 45 minutes

---

## What Is a SOC? (Simple)

A Security Operations Center (SOC) is a centralized team — and often a physical location — dedicated to monitoring, detecting, analyzing, and responding to cybersecurity incidents.

Think of it as the security command center for an organization. While other teams build, maintain, and operate IT systems, the SOC watches over all of it, looking for threats, and responding when something goes wrong.

Some organizations have their own in-house SOC. Others outsource to an MSSP (Managed Security Service Provider) that runs a SOC as a service.

---

## SOC Team Roles

### Tier 1 — Alert Analyst (That is You)

This is the starting point for SOC analysts.

Responsibilities:
- Monitor the SIEM and EDR dashboard for alerts
- Triage incoming alerts (determine initial priority)
- Perform initial investigation (true positive or false positive?)
- Follow playbooks for common alert types
- Escalate confirmed threats to Tier 2
- Document investigation findings in the ticketing system

Skills needed:
- Understand common alerts and what they mean
- Read logs from multiple sources
- Know common attack patterns
- Use security tools efficiently
- Communicate findings clearly

This is the highest-volume, highest-intensity role. Tier 1 analysts handle dozens of alerts per shift.

### Tier 2 — Incident Responder

Responsibilities:
- Receive escalated alerts from Tier 1
- Deep-dive investigation of confirmed incidents
- Threat hunting (proactively looking for hidden threats)
- Malware analysis
- Develop new detection rules
- Guide containment and remediation

Skills needed:
- Deep log analysis across all systems
- Malware analysis (static and dynamic)
- Forensic investigation
- Advanced threat hunting
- Understanding of complex attack patterns

### Tier 3 — Threat Hunter / Security Expert

Responsibilities:
- Proactive threat hunting based on intelligence
- Red team exercises (simulating attacks)
- Developing detection strategies
- Building automation
- Incident response leadership for major incidents

Skills needed:
- Expert-level knowledge of attack techniques
- Custom tool development
- Advanced forensics and malware analysis
- Threat intelligence integration

### SOC Manager / Lead

Responsibilities:
- Oversee SOC operations
- Define processes and metrics
- Manage the team
- Communicate with executive leadership
- Manage vendor relationships and tool selection

---

## SOC Processes and How They Work Together

### Alert Triage Flow

Alert fires in SIEM or EDR
→ Tier 1 analyst picks up the alert
→ Initial investigation (2-5 minutes): Is this a known false positive? Known attack pattern?
→ If false positive: Close with documentation
→ If true positive or unclear: Deeper investigation (15-30 minutes)
→ If confirmed incident: Escalate to Tier 2, begin containment
→ Tier 2 leads incident response
→ After resolution: Post-incident review, lessons learned, new detections created

### Shift Operations

SOCs operate 24/7. Typically three shifts:
- Day shift (8 AM - 4 PM)
- Evening shift (4 PM - 12 AM)
- Night shift (12 AM - 8 AM)

Shift handover is critical — open incidents are briefed to the incoming team.

### SLAs (Service Level Agreements)

SOCs have defined response times:
- Critical alert: Acknowledged in 5 minutes, initial investigation within 15 minutes
- High alert: Acknowledged in 15 minutes, investigation within 1 hour
- Medium alert: Investigation within 4 hours
- Low alert: Investigation within 24 hours

### KPIs (Key Performance Indicators)

How SOC performance is measured:
- Mean Time to Detect (MTTD) — how quickly are threats found?
- Mean Time to Respond (MTTR) — how quickly are threats contained?
- Alert volume and false positive rate
- Incidents escalated vs total alerts (escalation rate)

---

## SIEM — Security Information and Event Management

### What Is SIEM? (Simple)

A SIEM is a system that collects logs from all your security tools and systems in one place, and helps you find security events among billions of log entries.

Without a SIEM: You would have to log into each system separately, manually reviewing each log — impossible at enterprise scale.
With a SIEM: All logs flow into one system. You write detection rules. The SIEM alerts you when something matches.

### How SIEM Works Internally

Data Collection:
Logs are sent from all sources to the SIEM via:
- Syslog (UDP/TCP 514) — for firewalls, network devices, Linux systems
- Windows Event Forwarding (WEF) — forwards Windows events to a central collector
- Agents (small programs installed on endpoints that send logs)
- API connections (for cloud services like Microsoft 365, AWS)

Normalization:
Different log sources have different formats. A Windows login event looks different from a Linux login event. SIEM normalizes them into a common format so you can query across all sources.

Correlation:
The SIEM applies detection rules that look for patterns across multiple events.
Example rule: "If the same user fails to authenticate 10 times in 1 minute across any system, create an alert."
This correlates events from multiple systems (Windows, VPN, email) for the same user.

Alerting:
When a rule fires, it creates an alert (often called a "case" or "ticket") in the SIEM.
Analysts review the alert queue.

Retention:
Logs are stored in the SIEM for a defined retention period (often 90 days online, 1 year archived).
Long retention allows historical investigation.

### Common SIEM Examples

Microsoft Sentinel — Cloud-native, integrates deeply with Microsoft 365 and Azure.
Wazuh — Open source SIEM with EDR capabilities.
Splunk — Industry standard, highly flexible and powerful.
IBM QRadar — Enterprise SIEM with advanced analytics.
Elastic SIEM (Elastic Stack) — Open source, highly customizable.
LogRhythm — Enterprise SIEM focused on automation.

### What SOC Analysts Do in SIEM

Write detection rules (correlation rules / analytics)
Example: "Alert when more than 5 failed logins in 2 minutes for the same account"

Build dashboards: Visual overview of security posture
Example: Top alert types this week, alerts by severity, geographic IP map

Investigate alerts: Pivot through related logs
"This alert fired for IP 192.168.1.55 — show me all events for this IP in the last 24 hours."

Hunt for threats: Proactive queries
"Show me all PowerShell executions with -enc flag from the past week."

---

## EDR — Endpoint Detection and Response

### What Is EDR? (Simple)

EDR is software installed on every endpoint (laptop, server, workstation) that monitors what is happening on that device in detail and can respond to threats.

While antivirus looks for known malware signatures, EDR:
- Monitors all process behavior
- Records all file operations
- Records all network connections
- Records all registry changes
- Uses behavioral analysis to detect suspicious patterns
- Can respond: isolate the machine, kill a process, quarantine a file

### How EDR Works Internally

EDR agents monitor at a very low level:
- System call monitoring: Every call to the OS kernel is recorded
- Process injection detection: Monitors memory for code injection
- File system monitoring: Every file read, write, create, delete
- Network monitoring: Every network connection made
- Registry monitoring: Every registry key read or written

All this data is sent to a central EDR console.
Machine learning and behavioral rules analyze the data.
Suspicious patterns generate alerts.

### EDR vs Antivirus

Antivirus:
- Signature-based (matches against known malware patterns)
- Reactive (you must have seen the malware before to detect it)
- Limited to files on disk
- Cannot see memory-only attacks (fileless malware)

EDR:
- Behavior-based (detects suspicious behavior regardless of file)
- Proactive (detects novel attack patterns through behavior)
- Sees everything: files, memory, processes, network, registry
- Can detect fileless malware (malware that runs only in memory)
- Can respond: isolate, kill process, roll back changes

Modern endpoint security combines both antivirus and EDR in one product.

### Common EDR Examples

Microsoft Defender for Endpoint (MDE) — deeply integrated with Windows.
CrowdStrike Falcon — cloud-native, widely used enterprise EDR.
SentinelOne — autonomous response capabilities.
Carbon Black — Palo Alto's EDR solution.
Elastic EDR — open source option built on Elastic Stack.

### SIEM vs EDR — The Difference

SIEM:
- Collects logs from EVERYWHERE (network, cloud, email, endpoints, everything)
- Network-level visibility
- Best for correlation across multiple systems
- Cannot see what is happening INSIDE a process
- Log analysis tool

EDR:
- Deep visibility INTO each endpoint
- Sees exactly what every process is doing (memory, files, network, registry)
- Best for endpoint-level investigation
- Cannot see what is happening in the network or other systems
- Real-time endpoint monitoring and response tool

Together, they provide complete visibility: SIEM shows the big picture, EDR shows the deep detail on each device.

---

## Other Key Security Tools

### Firewall

Controls network traffic based on rules.
Traditional firewall: Rules based on IP address and port number.
Next-Generation Firewall (NGFW): Can inspect application-layer traffic, perform SSL inspection, identify users.
Generates logs showing: allowed/blocked traffic, source/destination IP/port.

### IDS/IPS

IDS (Intrusion Detection System): Monitors network traffic and alerts on known attack signatures. Passive — detects but does not block.
IPS (Intrusion Prevention System): Actively blocks traffic matching attack signatures. Inline in the traffic flow.

Signature-based: Matches against a database of known attack patterns.
Anomaly-based: Detects deviations from normal behavior baseline.

Common: Snort, Suricata (open source), Palo Alto, Cisco Firepower.

### DLP — Data Loss Prevention

Monitors and controls data movement to prevent unauthorized exfiltration.
Can monitor: email attachments, USB drives, web uploads, printing.
Example rule: "Block any email containing more than 20 credit card numbers from leaving the network."

### Email Security

Scans incoming email for: malware in attachments, phishing URLs, spoofed senders.
Applies SPF/DKIM/DMARC validation.
May sandbox attachments (open in an isolated environment to see if they are malicious).
Examples: Microsoft Defender for Office 365, Proofpoint, Mimecast.

### Web Application Firewall (WAF)

Protects web applications from Layer 7 attacks.
Detects and blocks: SQL injection, XSS, path traversal, malformed requests.
Sits in front of web servers.

### Cloud Security

CASB (Cloud Access Security Broker): Controls and monitors access to cloud services (Office 365, Salesforce, etc.).
Azure Security Center / Microsoft Defender for Cloud: Cloud-native security monitoring.
AWS Security Hub: Aggregates security findings across AWS services.

### Identity Protection

Microsoft Entra ID Protection (formerly Azure AD Identity Protection): Detects risky sign-ins, compromised accounts.
Privileged Identity Management (PIM): Controls access to high-privilege roles.
CyberArk / Beyond Trust (PAM): Privileged Access Management — manages and monitors privileged accounts.

---

## Summary

A SOC monitors, detects, analyzes, and responds to security threats 24/7.
Tier 1 analysts triage alerts. Tier 2 investigates confirmed incidents. Tier 3 hunts threats.
SIEM: collects all logs in one place, correlates events, generates alerts. Broad visibility.
EDR: deep endpoint monitoring and response. Narrow but very detailed visibility.
Together, SIEM + EDR + Firewall + IDS/IPS + Email Security + DLP form the layered defense.
As a Tier 1 analyst, your main tools are SIEM and EDR.

---

## Practice Questions

**Easy:**
1. What are the three tiers of SOC analysts and what does each do?
2. What is MTTD and MTTR?
3. What is the difference between SIEM and EDR?

**Medium:**
4. Why is correlation in a SIEM powerful? Give an example of an attack that would only be detected through log correlation (not any single log alone).
5. Why can EDR detect fileless malware when traditional antivirus cannot?

**Thinking Questions:**
6. A small organization (50 employees) asks you whether they need a SOC. What would you recommend and why? What is the minimum viable security monitoring for a small organization?
7. You are a Tier 1 analyst and receive an alert: "High — 10 failed login attempts for user john.smith from IP 185.220.101.47 in the last 2 minutes." Walk through your complete investigation process. What information do you gather? What are the possible outcomes and your actions for each?
