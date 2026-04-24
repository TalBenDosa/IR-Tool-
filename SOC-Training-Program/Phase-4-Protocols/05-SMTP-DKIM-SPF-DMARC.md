# Lesson 4.5 — SMTP, DKIM, SPF, and DMARC — Email Security Deep Dive

**Phase:** 4 — Protocols
**Prerequisite:** Lesson 4.4
**Time to complete:** 45 minutes

---

## Why Email Security Matters

Email is the #1 attack vector for initial access.

According to multiple industry reports, 90%+ of all cyberattacks start with a phishing email. Business Email Compromise (BEC) costs organizations billions of dollars per year. Ransomware is almost always delivered via email.

Understanding how email works — and how it can be abused — is critical for every SOC analyst.

---

# PART A: SMTP — Simple Mail Transfer Protocol

## What Is SMTP? (Simple)

SMTP is the protocol used to send email.

When you click "Send" in your email client, SMTP is what carries your message from your email client to your email server, and from your email server to the recipient's email server.

Ports:
- 25 — SMTP server-to-server (MTA to MTA)
- 587 — SMTP with STARTTLS for user submission (client to mail server, encrypted)
- 465 — SMTP over SSL (older standard for submission)

IMAP (port 143/993) and POP3 (port 110/995) are for RECEIVING email — different from SMTP.

---

## How SMTP Works (Complete Flow)

### The Email Journey

Scenario: john.smith@company.com sends email to jane.doe@partner.com

1. John composes the email in Outlook and clicks Send.

2. Outlook connects to company's mail server (e.g., mail.company.com) on port 587 using SMTP with STARTTLS (encrypted).
   Outlook authenticates with john.smith's credentials.
   Outlook submits the email to the mail server.

3. Company's mail server (MTA — Mail Transfer Agent) looks up where to send email for partner.com.
   It queries the DNS MX record: `partner.com. IN MX 10 mail.partner.com.`
   The mail server connects to mail.partner.com on port 25.

4. Server-to-server SMTP conversation:
```
→ EHLO mail.company.com
← 250-mail.partner.com Hello mail.company.com
← 250-STARTTLS
← 250-SIZE 52428800
← 250 OK

→ STARTTLS
← 220 Ready to start TLS
[TLS handshake]

→ MAIL FROM: <john.smith@company.com>
← 250 OK

→ RCPT TO: <jane.doe@partner.com>
← 250 OK

→ DATA
← 354 Start mail input; end with <CRLF>.<CRLF>

[email headers and body sent here]
.
← 250 OK: Message queued as abc123

→ QUIT
← 221 Bye
```

5. Partner's mail server receives the email and puts it in Jane's mailbox.

6. Jane opens her email client (Outlook, Thunderbird), which connects to the mail server using IMAP/POP3 to download the email.

---

## Email Headers — The Full Story

Email headers contain the complete history of an email's journey. They are crucial for investigating phishing and BEC attacks.

An email header contains:
- The original sender's IP address
- Every mail server that handled the email
- Timestamps at each hop
- Authentication results (SPF, DKIM, DMARC)
- The "real" From address vs the displayed From address

### Reading Email Headers (Example)

```
Return-Path: <john.smith@company.com>
Received: from mail.company.com (mail.company.com [203.0.113.50])
        by mail.partner.com (Postfix) with ESMTPS id 4A3B2C4D5E
        for <jane.doe@partner.com>; Fri, 15 Mar 2024 10:22:31 +0000

Received: from LAPTOP-JSMITH.company.local ([192.168.1.55])
        by mail.company.com with MAPI id 15.02.1258.000;
        Fri, 15 Mar 2024 10:22:28 +0000

From: John Smith <john.smith@company.com>
To: Jane Doe <jane.doe@partner.com>
Subject: Q1 Financial Report
Date: Fri, 15 Mar 2024 10:22:28 +0000
Message-ID: <BN9PR06MB62791A6B3A72B24D3ACDB5B5A8CB2@BN9PR06MB6279.namprd06.prod.outlook.com>

Authentication-Results: mail.partner.com;
        spf=pass smtp.mailfrom=company.com
        dkim=pass header.d=company.com
        dmarc=pass action=none header.from=company.com
```

Reading headers from bottom to top gives you the email's journey from source to destination.

Key fields:
- "Received" headers — each mail server that handled the email (read bottom-up for chronological order)
- "From" — displayed sender (can be forged)
- "Return-Path" — where bounced emails go (harder to forge)
- "X-Originating-IP" or earliest Received header — the true source IP
- "Authentication-Results" — SPF/DKIM/DMARC results

---

## Email Spoofing — How Attackers Fake the Sender

SMTP by default does not verify that the "From" address is legitimate. Anyone can set any From address.

This means an attacker can send an email that appears to come from ceo@company.com — even without accessing the CEO's account.

How it works:
```
MAIL FROM: <attacker@evil.com>    ← The real sender (used for bounces, SPF checks)
→ DATA
From: CEO John Smith <ceo@company.com>    ← The displayed sender (what the recipient sees)
```

The recipient sees "CEO John Smith <ceo@company.com>" in their inbox.
The "MAIL FROM" (which is different) is what SPF checks — but if SPF is not configured, there is nothing to check.

---

# PART B: SPF — Sender Policy Framework

## What Is SPF? (Simple)

SPF is a DNS record that tells the world which mail servers are authorized to send email on behalf of your domain.

If someone tries to send email claiming to be from company.com but uses a server not listed in company.com's SPF record, receiving mail servers will know it is fake.

---

## How SPF Works

1. Company publishes a TXT record in DNS:
```
company.com. IN TXT "v=spf1 ip4:203.0.113.50 include:spf.protection.outlook.com -all"
```
This says: "Email from company.com should only come from IP 203.0.113.50 or from Microsoft's Office 365 servers. Reject everything else (-all)."

2. When a receiving mail server gets an email claiming to be from company.com, it:
   a. Extracts the IP address of the sending mail server
   b. Looks up company.com's SPF record in DNS
   c. Checks if the sending IP is in the list

3. SPF result:
   Pass — IP is in the SPF record → email is from an authorized server
   Fail — IP is NOT in the SPF record → email is unauthorized
   SoftFail (~all) — Fail but treat with suspicion rather than reject
   Neutral (?all) — No policy
   None — No SPF record exists

### SPF Qualifier Mechanisms:
- -all (hard fail) — Reject emails from unauthorized servers
- ~all (soft fail) — Accept but mark as suspicious
- ?all (neutral) — No policy
- +all (pass all) — Authorize ALL servers (terrible practice — makes SPF useless)

### SPF Limitations

SPF only checks the "MAIL FROM" (envelope sender), not the "From" header (what you see in your email client). This is the key weakness.

An attacker can:
1. Send from attacker@evil.com (passes SPF for evil.com)
2. But display "From: ceo@company.com" in the email

SPF passes (for evil.com) but the visible sender is company.com. This is called display name spoofing or header spoofing. DMARC addresses this.

---

# PART C: DKIM — DomainKeys Identified Mail

## What Is DKIM? (Simple)

DKIM adds a digital signature to emails. The signature proves that:
1. The email was authorized by the domain it claims to come from
2. The email has not been modified in transit

---

## How DKIM Works

1. The sending mail server signs the email with a private key.
   The signature covers specific headers and the body.
   The signature is added as a header: DKIM-Signature: ...

2. The signature is verified by checking against the public key in DNS:
```
selector1._domainkey.company.com. IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA..."
```

3. The receiving server:
   a. Gets the public key from DNS
   b. Verifies the signature against the email content
   c. If valid → email was authorized and not modified
   d. If invalid → the signature is broken (email was modified) or the email is forged

### DKIM Header Example:
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=company.com; s=selector1;
    h=From:To:Subject:Date:Message-ID;
    bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
    b=AbCdEfGhIjKlMnOpQrStUvWxYz...
```

Fields:
- d= domain signing the email
- s= selector (which public key to use — allows key rotation)
- h= headers covered by the signature
- bh= hash of the email body
- b= the actual signature

### Why DKIM Matters

DKIM specifically proves the email content has not been tampered with. If an attacker intercepts an email and changes "transfer $100" to "transfer $100,000," the DKIM signature becomes invalid.

However, DKIM alone does not tell receivers WHAT to do with failed signatures — that is DMARC's job.

---

# PART D: DMARC — Domain-based Message Authentication, Reporting, and Conformance

## What Is DMARC? (Simple)

DMARC is the policy layer that ties SPF and DKIM together and tells receiving mail servers what to do when an email fails those checks.

DMARC answers the question: "If an email fails SPF or DKIM, should I accept it, quarantine it, or reject it?"

DMARC also enables reporting — you can receive reports about who is sending email on behalf of your domain.

---

## How DMARC Works

DMARC alignment concept:
DMARC checks that the "From" domain in the email header ALIGNS with the domain that passed SPF or DKIM.

This is what makes DMARC powerful — it closes the gap that SPF alone cannot close.

Without DMARC:
- SPF passes for evil.com (the real MAIL FROM)
- From header shows company.com (the spoofed visible sender)
- The email is delivered with the spoofed sender

With DMARC:
- SPF passes for evil.com, but evil.com does not align with company.com (the From header)
- DMARC fails because alignment fails
- DMARC policy determines what happens next

### DMARC Policy Values:
```
company.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-reports@company.com; ruf=mailto:dmarc-forensic@company.com; pct=100"
```

- p=none — Monitor mode. Do nothing, just collect reports. Good for first implementation.
- p=quarantine — Treat failing emails as suspicious (send to spam/junk).
- p=reject — Reject failing emails outright. The strongest protection.
- rua= — Where to send aggregate reports (daily summaries)
- ruf= — Where to send forensic reports (individual failing email reports)
- pct= — Percentage of email to apply the policy to (100 = all email)

### DMARC Pass/Fail Logic:

DMARC passes if:
- SPF passes AND the SPF domain aligns with the From: header domain
- OR DKIM passes AND the DKIM d= domain aligns with the From: header domain

DMARC fails if:
- Both SPF and DKIM fail
- OR neither domain aligns with the From: header

---

## Email Security Investigation — Complete Workflow

### Scenario: Suspicious email received by accounting@company.com

Step 1 — Extract and read email headers.

Step 2 — Check SPF result:
```
Authentication-Results: spf=fail smtp.mailfrom=company.com
```
SPF failed → the sending server is not authorized to send as company.com.

Step 3 — Check DKIM result:
```
Authentication-Results: dkim=fail reason="signature verification failed" header.d=company.com
```
DKIM failed → the signature is invalid.

Step 4 — Check DMARC result:
```
Authentication-Results: dmarc=fail action=quarantine header.from=company.com
```
DMARC failed and the policy quarantined the email — but the user may have still retrieved it from spam.

Step 5 — Trace the original sending IP:
```
Received: from 185.220.101.47 (unknown [185.220.101.47])
```
External IP. Look up in threat intelligence.

Step 6 — Check domain age, WHOIS:
The From domain "company.com" is legitimate. But is it spoofed?
The sending server 185.220.101.47 is not in company.com's SPF record → confirmed spoofing.

Step 7 — Check the content:
Does the email contain urgent requests, links, attachments?
Links: Where do they lead? Check VirusTotal.
Attachments: What type? Is the hash known malicious?

Step 8 — Determine impact:
Did the user click any links? Submit any credentials?
Did other users receive the same email?

---

## SMTP Attack Patterns

### Business Email Compromise (BEC)

Attacker sends email that appears to be from the CEO or CFO to the accounting team:
"I need you to urgently transfer $250,000 to this account for a confidential acquisition. Do not discuss with anyone."

Investigation:
- From: ceo@company.com (displayed)
- MAIL FROM: ceo@company-corp.com (different domain — typosquatted)
- SPF: pass for company-corp.com (legitimate for THEIR domain)
- DKIM: pass for company-corp.com
- DMARC: fail (company-corp.com ≠ company.com)
- Reply-To: attacker@evil.com (replies go to attacker)

### Email-Based Malware Delivery

```
From: "HR Department" <hr@company.com>
Subject: Updated Benefits Package 2024
Attachment: Benefits-2024.pdf.exe  ← double extension — .exe hidden
```

Or:
```
Subject: Invoice #2024-0315
Attachment: Invoice.docx  ← Contains malicious macro
```

Investigation:
- Hash the attachment and check VirusTotal
- Check if other users received it
- Check EDR logs — was the file executed?

### SMTP Log Example — Internal Email Server:

```
2024-03-15 10:22:31 SMTP: john.smith@company.com → jane.doe@partner.com [OK]
2024-03-15 10:22:45 SMTP: ceo@company.com → accounting@company.com [FROM:attacker@company-corp.com]
```
The second email — the From and the MAIL FROM do not match — this is spoofed.

---

## Summary

SMTP sends email: client → mail server (port 587), server → server (port 25).
Email headers contain the full journey — read bottom-to-top for chronological order.
SPF: DNS record of authorized sending servers. Checks MAIL FROM, not displayed From.
DKIM: Digital signature proving the email was authorized and unmodified.
DMARC: Policy that ties SPF and DKIM together and requires alignment with the From header. Enables reject/quarantine of spoofed emails.
90%+ of attacks start with email. Analyzing email headers is a core SOC skill.
Always check: SPF/DKIM/DMARC results, sending IP reputation, domain age, attachment hashes.

---

## Practice Questions

**Easy:**
1. What port does SMTP use for server-to-server email delivery?
2. What does SPF check?
3. What is the difference between DKIM and SPF?

**Medium:**
4. An email arrives claiming to be from ceo@company.com. SPF passes. The email is a request to wire $100,000. Should you trust it? Why or why not?
5. A DMARC report shows that 500 emails per day are being sent from external servers claiming to be from company.com and failing DMARC. What does this indicate?

**Thinking Questions:**
6. An accounting employee receives an email: From: "John Smith CEO" <ceo@company.com>, asking for an urgent wire transfer. The email passed SPF and DKIM but failed DMARC. How is this possible? (Hint: think about what SPF and DKIM check separately vs what DMARC adds.)
7. Design the ideal email security configuration for a company. What would you configure for SPF (what qualifier), DKIM, and DMARC (what policy)? Explain your reasoning.
