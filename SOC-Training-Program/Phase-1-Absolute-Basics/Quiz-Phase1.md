# Phase 1 Quiz — Absolute Basics

**Instructions:** Answer all questions. After completing, check your answers against the answer key at the bottom. Score yourself honestly. A score of 80% or above means you are ready to proceed to Phase 2.

**Time limit:** 30 minutes
**Total questions:** 20
**Passing score:** 16/20

---

## Section A — Multiple Choice (1 point each)

**Question 1:**
What is the correct definition of a computer?

A) A device that thinks and makes decisions on its own
B) A machine that follows instructions
C) A device only used for browsing the internet
D) A machine that runs only one program at a time

---

**Question 2:**
Which of the following is hardware?

A) Windows operating system
B) Microsoft Word
C) RAM (Random Access Memory)
D) A web browser

---

**Question 3:**
What is the main job of an operating system?

A) To display websites
B) To protect against viruses only
C) To manage hardware, processes, files, and users
D) To connect to the internet

---

**Question 4:**
A process called "svchost.exe" is running from C:\Users\Admin\Downloads\svchost.exe. What is suspicious about this?

A) The name svchost.exe is unusual
B) The process is running from an unexpected location — it should run from C:\Windows\System32\
C) The process is running as Admin
D) Nothing is suspicious

---

**Question 5:**
What is a file hash used for?

A) To compress files
B) To encrypt files
C) To uniquely identify the content of a file and detect tampering
D) To track who opened a file

---

**Question 6:**
Which of the following is a private IP address?

A) 8.8.8.8
B) 203.0.113.42
C) 192.168.10.55
D) 85.214.132.117

---

**Question 7:**
What does DNS do?

A) Assigns IP addresses to computers automatically
B) Translates domain names into IP addresses
C) Encrypts internet traffic
D) Blocks malicious websites

---

**Question 8:**
A newly registered domain (registered 2 days ago) sends an email to your finance team with an attachment. This is:

A) Normal — all domains are new at some point
B) Low risk because new domains are monitored by ISPs
C) Highly suspicious and potentially a phishing or BEC attack
D) Only suspicious if it comes from another country

---

**Question 9:**
What is the parent process and why does it matter?

A) The first process that ever ran on a computer; it does not matter for security
B) The process that started another process; it is critical for detecting malware behavior
C) The process with the highest CPU usage
D) The operating system kernel process

---

**Question 10:**
Which statement about packets is correct?

A) A packet is the entire file or message sent at once
B) Packets are only used for video streaming
C) A packet is a small piece of data with source/destination IP and content
D) Packets are only used on internal networks

---

## Section B — True or False (1 point each)

**Question 11:**
A process named "chrome.exe" is always the real Google Chrome browser.

True / False

---

**Question 12:**
127.0.0.1 is the loopback address and refers to the computer itself.

True / False

---

**Question 13:**
If traffic uses HTTPS, the website is definitely safe and legitimate.

True / False

---

**Question 14:**
A computer making DNS queries to hundreds of random-looking domain names in one minute is likely infected with DGA malware.

True / False

---

**Question 15:**
NAT allows multiple internal computers to share one public IP address.

True / False

---

## Section C — Short Answer (2 points each)

**Question 16:**
Explain the difference between a file and a process. Use your own words and an analogy if it helps.

---

**Question 17:**
A log shows that Word (winword.exe) spawned PowerShell (powershell.exe) on an employee's computer. Explain why this is suspicious and what it might indicate.

---

**Question 18:**
You are investigating an alert. The source IP is 10.0.5.32. What does this tell you about whether the threat is internal or external? What log would you check to identify the specific computer?

---

**Question 19:**
Explain typosquatting. Give an example. Why is it effective as an attack?

---

**Question 20:**
An employee's computer is making 400 DNS queries per minute to domains like "rplxvnq.com", "qzxkjmn.net", "wbmrpx.org" — all returning NXDOMAIN (not found). What is happening and why?

---

## Answer Key

**Section A:**
1. B
2. C
3. C
4. B
5. C
6. C
7. B
8. C
9. B
10. C

**Section B:**
11. False — Attackers name malware after legitimate processes. Always check the file path and hash.
12. True
13. False — HTTPS encrypts the connection but does not guarantee the site is legitimate.
14. True
15. True

**Section C (Scoring guide — award full 2 points if both concepts are covered):**

16. A file is data stored on disk (passive, does nothing). A process is a file that has been loaded into memory and is actively running. Analogy: file = recipe book, process = chef cooking. (2 points)

17. Word does not normally launch PowerShell. This behavior indicates a malicious macro was embedded in a Word document and executed when opened. The macro launched PowerShell to likely download malware, run commands, or exfiltrate data. This is a common malware delivery technique. (2 points)

18. 10.0.5.32 is a private/internal IP address (10.x.x.x range), meaning the activity originated from inside the network — either a compromised internal device or a malicious insider. DHCP logs should be checked to identify which computer held that IP address at the time of the incident. (2 points)

19. Typosquatting is when attackers register domain names that look like real domains but have small spelling errors or character substitutions (paypa1.com instead of paypal.com). It is effective because users often glance at domain names quickly and miss subtle differences, especially in emails or when they make typing mistakes. (2 points)

20. This is almost certainly a DGA (Domain Generation Algorithm) infection. The computer is running malware that automatically generates random domain names trying to find the attacker's command-and-control server. The NXDOMAIN responses mean those particular domains are not active yet. The sheer volume and randomness of the queries is the key indicator. (2 points)

---

## Score Interpretation

18–20: Excellent. You have a strong grasp of the fundamentals. Proceed to Phase 2.
16–17: Good. Review your incorrect answers before proceeding.
14–15: Fair. Re-read the lessons on topics you struggled with, then retake the quiz.
Below 14: Please re-read all Phase 1 lessons carefully before continuing.
