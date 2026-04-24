# Lesson 8.1 — What Is a Log and Why Logs Exist

**Phase:** 8 — Log Reading and Analysis
**Prerequisite:** All Phase 7 lessons
**Time to complete:** 25 minutes

---

## Simple Explanation

A log is a record of something that happened.

Every time a computer performs an action — a user logs in, a file is opened, a network connection is made, a program runs — it can create a record of that event. This record is a log entry.

A collection of these records is called a log file.

Think of a log file as a security camera recording. It does not prevent crimes — but it records everything that happens. If something goes wrong, you review the recording to understand what happened.

---

## Why Logs Exist

Logs serve multiple purposes:

Troubleshooting: When something breaks, logs show what went wrong.
Auditing: Prove compliance with regulations (GDPR, HIPAA, PCI-DSS require specific logging).
Security investigation: After an attack, logs are your evidence.
Detection: Real-time analysis of logs is how SIEM detects threats.
Accountability: Logs prove who did what, when, and from where.

As a SOC analyst, logs are your primary evidence source. They are the digital fingerprints left behind by every action — legitimate or malicious.

---

## The Structure of a Log Entry

Every log entry, regardless of source, contains some version of these fundamental fields:

Timestamp: When did this happen?
Source: What system generated this log?
Event Type / ID: What type of event is this?
Actor: Who or what performed the action? (User, process, system)
Action: What happened?
Target: What was the action performed on?
Result / Status: Did it succeed or fail?
Context: Additional details

Different log sources express these differently, but the concepts are universal.

---

## Log Quality — What Makes a Good Log

Not all logs are equally useful. Good logs have:

Accuracy: The event is recorded correctly.
Completeness: All relevant fields are included.
Consistency: The same type of event always produces the same format.
Timestamps with timezone: Logs from different systems must be comparable.
Tamper evidence: Logs stored in ways that prevent modification.
Retention: Logs kept long enough to be useful for investigations.

The biggest problem with logs in investigations:

Time synchronization: If System A's clock is 10 minutes ahead of System B's clock, correlating events between them is inaccurate. NTP (Network Time Protocol) keeps all clocks synchronized. Without NTP, cross-system log correlation is unreliable.

Log deletion: Attackers often delete logs to cover their tracks. Windows Event ID 1102 (Security log cleared) is itself a logged event — but if all logs are deleted, this is gone too. Off-system log storage (sending to a SIEM immediately) prevents this.

---

## Types of Logs by Source

Windows Security Event Log: Authentication, process creation, object access, policy changes.
Windows System Log: Hardware events, service changes, driver issues.
Windows Application Log: Application-specific events.
Sysmon Log: Detailed process creation, network connections, file creation, registry changes.
Active Directory Logs: Domain authentication, account changes, group membership, replication.
Office 365 / Microsoft 365 Logs: Email activity, SharePoint access, Teams activity, admin changes.
Azure AD / Entra ID Logs: Cloud authentication, conditional access, MFA events.
EDR Logs: Process behavior, file operations, network connections (all on the endpoint).
Firewall Logs: Network connections allowed/blocked at the perimeter.
Proxy Logs: Web traffic (URLs, user agents, bytes transferred).
DNS Logs: Every domain resolution request.
Email Security Logs: Phishing detection, malware in attachments, SPF/DKIM/DMARC results.
VPN Logs: Remote access connections.
Web Server Logs (Apache/Nginx): HTTP requests to web servers.
Database Logs: SQL queries, login attempts, schema changes.
Cloud Logs (AWS CloudTrail, Azure Activity Log): Cloud API calls and configuration changes.

---

## Log Analysis Mental Model

Before diving into specific logs, adopt this mental model:

When you see a log entry, ask:
1. What happened?
2. Who did it?
3. When did it happen?
4. From where?
5. Was it successful?
6. Is this normal for this who/what/when/where combination?

The last question is the most important. You are not just reading what happened — you are judging whether it makes sense given all the context.

---

## Summary

A log is a record of an event. Logs are your primary evidence source as a SOC analyst.
Good logs include: timestamp (with timezone), actor, action, target, result, and context.
Time synchronization is critical for cross-system log correlation.
Log deletion is a common attacker technique — use off-system log storage (SIEM).
You will analyze logs from many sources: Windows, AD, O365, Azure, EDR, Firewall, Proxy, DNS, Email.

---

## Practice Questions

**Easy:**
1. What is a log?
2. Name five different sources of security logs in an enterprise.
3. Why is time synchronization critical for log analysis?

**Medium:**
4. An attacker clears the Windows Security event log on a compromised server. What event ID would you look for in the logs to know this happened? If the logs are all cleared, how could you still investigate?
5. Why is sending logs to a centralized SIEM in real-time important for security?

**Thinking Question:**
6. You are investigating an incident that happened 45 days ago. Your SIEM only retains logs for 30 days. What is the impact of this on your investigation? What should organizations do to prevent this problem?
