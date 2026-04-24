# Lesson 8.3 — Office 365, Azure AD, and Cloud Logs

**Phase:** 8 — Log Reading and Analysis
**Prerequisite:** Lesson 8.2
**Time to complete:** 45 minutes

---

## Why Cloud Logs Matter

Most organizations today use Microsoft 365 (formerly Office 365) for email, Teams, SharePoint, and OneDrive. Azure Active Directory (now called Microsoft Entra ID) handles authentication for these cloud services.

Cloud logs are different from on-premises Windows logs in important ways:
- They are generated in Microsoft's cloud, not on your domain controllers
- They capture rich context about logins: device, location, browser, risk level
- They include activity across all M365 services (email, SharePoint, Teams, etc.)
- They may be the ONLY log source for an attacker who bypasses on-premises systems entirely

Attackers increasingly target cloud identity directly, bypassing corporate networks through:
- Password spray attacks against M365 logins
- Phishing to steal M365 credentials
- Consent phishing to get app permissions
- Compromising cloud-only admins

---

## Microsoft 365 Unified Audit Log (UAL)

The Unified Audit Log captures activity across all Microsoft 365 services.

You access it through:
- Microsoft 365 Compliance Center (portal.compliance.microsoft.com)
- Security & Compliance PowerShell
- Microsoft Sentinel (if integrated)

### Key M365 Audit Log Operations

Authentication:
UserLoggedIn — successful login
UserLoginFailed — failed login

Email:
Send — email sent
Create — email created
MoveToDeletedItems — email moved to deleted items
HardDelete — email permanently deleted
MessageBind — email accessed
UpdateFolderPermissions — mailbox permissions changed
Add-MailboxPermission — access granted to mailbox

File/SharePoint:
FileAccessed — file opened or downloaded
FileDownloaded — file downloaded
FileUploaded — file uploaded
FileSyncDownloadedFull — file synced to device (OneDrive sync)
FileDeleted — file deleted
SiteCollectionCreated — new SharePoint site created

Admin:
Add member to role — user added to admin role
Set-AdminAuditLogConfig — audit log configuration changed
New-InboxRule — email inbox rule created

---

## Azure AD Sign-In Logs — Complete Analysis

Azure AD Sign-In logs capture every authentication attempt to any Microsoft service.

### Normal Sign-In Log Entry:
```json
{
  "createdDateTime": "2024-03-15T09:00:01.234Z",
  "userDisplayName": "John Smith",
  "userPrincipalName": "john.smith@company.com",
  "appDisplayName": "Microsoft Teams",
  "appId": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
  "ipAddress": "192.168.1.55",
  "clientAppUsed": "Browser",
  "deviceDetail": {
    "deviceId": "abc12345",
    "displayName": "LAPTOP-JSMITH",
    "operatingSystem": "Windows 10",
    "browser": "Chrome 122.0.0",
    "isCompliant": true,
    "isManaged": true
  },
  "location": {
    "city": "New York",
    "state": "New York",
    "countryOrRegion": "US",
    "geoCoordinates": {
      "latitude": 40.7128,
      "longitude": -74.0060
    }
  },
  "status": {
    "errorCode": 0,
    "additionalDetails": "MFA requirement satisfied by claim in the token"
  },
  "riskDetail": "none",
  "riskLevelAggregated": "none",
  "riskState": "none",
  "mfaDetail": {
    "authMethod": "Phone app notification",
    "authDetail": "Success"
  },
  "conditionalAccessStatus": "success",
  "authenticationRequirement": "multiFactorAuthentication"
}
```

Fields to analyze:
- userPrincipalName: Who logged in?
- ipAddress: From where?
- location: Which city/country?
- deviceDetail: Known/managed device or unknown?
- isCompliant: Is the device compliant with security policies?
- riskLevelAggregated: Microsoft's machine-learned risk score (none, low, medium, high)
- mfaDetail: Did they pass MFA? How?
- conditionalAccessStatus: Was the login subject to and compliant with access policies?

### Suspicious Sign-In Indicators

Password spray attack:
```json
[
  {"time": "03:00:01", "user": "a.adams@company.com", "status": {"errorCode": 50126}},
  {"time": "03:00:02", "user": "b.baker@company.com", "status": {"errorCode": 50126}},
  {"time": "03:00:03", "user": "c.campbell@company.com", "status": {"errorCode": 50126}},
  {"time": "03:00:04", "user": "d.davis@company.com", "status": {"errorCode": 50126}},
  [continues through all users alphabetically]
  {"time": "03:08:44", "user": "s.smith@company.com", "status": {"errorCode": 0}},
]
```
Alphabetical order through all users with the same password attempt = password spray. One success = compromised.

Important Azure AD error codes:
50126 — Invalid credentials (wrong password)
50053 — Account locked
50057 — Account disabled
50074 — MFA required but failed
53004 — Blocked due to risk
0 — Success

### Impossible Travel:
```json
[
  {
    "time": "2024-03-15T09:00:00Z",
    "user": "sarah.jones@company.com",
    "ipAddress": "192.168.1.45",
    "location": {"city": "New York", "countryOrRegion": "US"}
  },
  {
    "time": "2024-03-15T09:15:00Z",
    "user": "sarah.jones@company.com",
    "ipAddress": "41.225.252.10",
    "location": {"city": "Lagos", "countryOrRegion": "NG"}
  }
]
```
New York at 9:00 AM, Lagos at 9:15 AM. Physically impossible — 15 minutes, 11,000 km.
Azure AD Identity Protection detects this automatically (risk detection: ImpossibleTravel).

### Unfamiliar Sign-In Properties:
```json
{
  "user": "john.smith@company.com",
  "ipAddress": "185.220.101.47",
  "location": {"city": "Bucharest", "countryOrRegion": "RO"},
  "deviceDetail": {
    "deviceId": null,
    "displayName": null,
    "isManaged": false,
    "isCompliant": false,
    "browser": "Firefox 102.0 ESR (Linux)"
  },
  "riskLevelAggregated": "high",
  "riskDetail": "unfamiliarFeatures"
}
```
Unknown, unmanaged Linux device from Romania — John Smith normally uses a Windows laptop from New York. High risk. This is likely account compromise.

---

## Microsoft Defender for Office 365 — Email Logs

### Threat Explorer / Email Entity

When investigating a suspicious email, Defender for O365 shows:

```
Email Details:
  Message ID: <BN9PR06MB6279...@mail.company.com>
  Sender: malicious-sender@evil-domain.com
  Display Name: "IT Support <it-support@company.com>"  ← Spoofed display name
  Recipients: accounting@company.com
  Subject: Urgent Invoice Payment Required
  
Authentication:
  SPF: Fail (evil-domain.com not authorized for company.com)
  DKIM: Fail
  DMARC: Fail (action: none — no enforcement!)
  Composite Auth: Fail
  
Threat Analysis:
  Threat Type: Phishing
  Detection Tech: URL malicious reputation
  Delivery Action: Delivered to inbox  ← Despite failing auth!
  Delivery Location: Inbox (DMARC policy is p=none)
  
URLs found:
  http://company-secure-login.net/verify  → Malicious (Phishing)
  
Attachments:
  Invoice-2024-03-15.docm → Malicious (Macro)
  SHA256: a4b5c6d7e8f90a1b2c3d4e5f...
```

### Inbox Rules — Attacker Persistence in Email

When attackers compromise an email account, they often create inbox rules to:
- Forward all emails to an external address (ongoing surveillance)
- Delete emails matching certain keywords (hide their activity)
- Move security alerts to trash (prevent the victim from seeing breach notifications)

Audit log entry — suspicious inbox rule created:
```
Operation: New-InboxRule
User: john.smith@company.com
RuleName: "Auto Archive"
Conditions: All messages
Actions: Forward to attacker@protonmail.com
DeleteMessage: True  ← Delete original (victim does not see it was forwarded)
```

This is the signature of a compromised email account that is being silently monitored.

---

## SharePoint and OneDrive Logs — Data Exfiltration Detection

### FileAccessed at Unusual Scale:
```
Operation: FileAccessed
User: sarah.jones@company.com
Time: 03:14:00
Site: company.sharepoint.com/sites/Finance
Item: /Q4-Financial-Statements.xlsx

Operation: FileDownloaded
User: sarah.jones@company.com
Time: 03:14:01
Site: company.sharepoint.com/sites/Finance
Item: /Q4-Financial-Statements.xlsx

[47 more FileDownloaded events in 3 minutes]
```
48 files downloaded from the Finance SharePoint at 3:14 AM = data exfiltration.

### External Sharing:
```
Operation: AddedToSecureLink
User: john.smith@company.com
Item: /sites/Engineering/ProductRoadmap-2025.docx
SharedWith: attacker@gmail.com  ← External personal email!
```
Sensitive engineering documents shared with a personal Gmail account = insider threat or compromised account.

---

## Azure Activity Log — Cloud Infrastructure Changes

The Azure Activity Log records all control plane operations in Azure:
Who did what to which Azure resource, when.

### Suspicious Azure Activity Examples:

New admin role assignment:
```json
{
  "time": "2024-03-15T03:22:00Z",
  "operationName": "Microsoft.Authorization/roleAssignments/write",
  "caller": "john.smith@company.com",
  "properties": {
    "principalId": "attacker-service-principal-id",
    "roleDefinitionId": "Owner",
    "scope": "/subscriptions/[subscription-id]"
  }
}
```
john.smith assigned "Owner" role (highest Azure privilege) to an external service principal at 3:22 AM. This is almost certainly an attacker using john.smith's compromised account to establish persistence in Azure.

Virtual machine created in unusual region:
```json
{
  "operationName": "Microsoft.Compute/virtualMachines/write",
  "caller": "john.smith@company.com",
  "location": "northkorea-hypothetical",
  "vmSize": "Standard_D32s_v3"  ← 32 CPU core VM
}
```
Large VMs created in unusual regions = crypto mining or attack infrastructure.

Network security group modified to allow all inbound:
```json
{
  "operationName": "Microsoft.Network/networkSecurityGroups/write",
  "properties": {
    "securityRules": [{
      "name": "allow_all",
      "protocol": "*",
      "sourceAddressPrefix": "*",
      "access": "Allow",
      "direction": "Inbound"
    }]
  }
}
```
Opening all inbound traffic = intentional exposure of resources.

---

## Microsoft Sentinel Analytic Rules Examples

This is how SIEM rules look for the cloud scenarios above:

Password spray detection:
```kql
SigninLogs
| where ResultType != "0"
| summarize FailedAttempts = count(), 
            DistinctUsers = dcount(UserPrincipalName) 
            by IPAddress, bin(TimeGenerated, 10m)
| where FailedAttempts > 50 and DistinctUsers > 10
| extend AlertTitle = "Password Spray Detected"
```

Impossible travel detection:
```kql
SigninLogs
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, Location, IPAddress
| order by UserPrincipalName, TimeGenerated
| serialize
| extend PrevTime = prev(TimeGenerated), 
         PrevLocation = prev(Location),
         PrevUser = prev(UserPrincipalName)
| where PrevUser == UserPrincipalName
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiff < 60 and Location != PrevLocation
| project TimeGenerated, UserPrincipalName, Location, PrevLocation, TimeDiff
```

---

## Complete Investigation Example — BEC (Business Email Compromise)

Alert: SIEM detects sign-in from unusual location for CFO account.

Step 1 — Azure AD Sign-In Logs:
```
User: cfo.anderson@company.com
Time: 03:14:00 UTC
IP: 185.220.101.47 (Romania — threat intel: known attacker infrastructure)
Device: Unknown, unmanaged
MFA: Not required (conditional access gap — trusted network exception applied)
Status: Success
Risk: High
```

Step 2 — Unified Audit Log — What did they do?
```
03:14:22 — New-InboxRule: "Archive Important" → Forward all emails to cfo.exfil@protonmail.com
03:14:45 — FileDownloaded: /Finance/Q1-Budget-2024.xlsx
03:14:47 — FileDownloaded: /Finance/Payroll-March-2024.xlsx
03:14:49 — FileDownloaded: /Finance/Banking-Credentials.docx
03:15:02 — Send: From cfo.anderson@company.com To accounting@company.com
          Subject: "Urgent - Wire Transfer"
```

Step 3 — Check the email sent to accounting:
```
From: "CFO Anderson" <cfo.anderson@company.com>
To: accounting@company.com
Subject: Urgent - Wire Transfer
Body: "I need you to urgently wire $450,000 to account... I am in a meeting, do not call me."
```

Full picture: Attacker logged into CFO's account from Romania, set up email forwarding, stole financial documents, and sent a fraudulent wire transfer request — all in under 2 minutes.

Immediate response:
1. Disable CFO's account
2. Block IP 185.220.101.47
3. Delete the inbox forwarding rule
4. Warn accounting team NOT to process the wire
5. Contact bank if wire was already initiated
6. Force MFA re-enrollment for CFO
7. Review which other accounts may have been compromised

---

## Summary

M365 and Azure AD logs capture cloud authentication, email, file access, and admin activity.
Azure AD Sign-In logs: risk level, location, device compliance, MFA status.
Key attacks to detect: password spray (many users, same source), impossible travel, unfamiliar device logins.
Inbox rules are a critical persistence mechanism — always check for forwarding rules on compromised accounts.
SharePoint/OneDrive logs reveal data exfiltration via bulk downloads or external sharing.
Azure Activity Log tracks infrastructure changes — unauthorized admin assignments, VM creation, firewall changes.

---

## Practice Exercises

**Exercise 1:**
A sign-in log shows: user: ceo@company.com, location: North Korea, device: unknown, MFA: not required, result: success. What actions do you take? List them in priority order.

**Exercise 2:**
The audit log shows 50 FileDownloaded events from the legal department's SharePoint, followed by Files being shared to gmail.com addresses, all by the same departing employee who gave notice yesterday. Is this concerning? What do you do?

**Exercise 3:**
Azure sign-in logs for admin.user@company.com show:
- Day 1: Failed × 200 from IP 45.142.212.100 (USA)
- Day 1: Success from same IP (password spray succeeded)
- Day 1: MFA method changed from "Phone call" to "Authenticator app"
What happened? Why is the MFA change significant?
