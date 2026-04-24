# Lesson 1.3 — What Is a File and What Is a Process?

**Phase:** 1 — Absolute Basics
**Prerequisite:** Lessons 1.1 and 1.2
**Time to complete:** 25 minutes

---

## Part A: What Is a File?

### Simple Explanation

A file is a container for stored information.

Everything saved on a computer is stored in a file. Documents, images, videos, programs, settings — all of it is stored in files. Files live on the hard drive or SSD. When you turn off the computer, files remain. They are permanent storage.

Files have:
- A name (example: report.docx)
- A type or extension (the .docx part tells you what kind of file it is)
- Content (the actual information inside)
- Metadata (information about the file, like when it was created, who created it, when it was last changed)

### Real-World Analogy

A file is like a physical folder in a filing cabinet.

The filing cabinet is the hard drive.
Each folder has a label (the file name), a type (contract, invoice, report), and content inside (the actual documents).
Files are organized in directories (folders), which are like the drawers and sections of the filing cabinet.

### Why Files Matter in Security

Attackers use files in many ways:
- Malware is delivered as a file (a malicious .exe, .pdf, .docx, .js file)
- Attackers read sensitive files (passwords, customer data, financial records)
- Attackers modify files (changing configurations, adding backdoors)
- Attackers delete files (destroying evidence or causing damage)

Important file types to know:

.exe — Executable file (a program). Running an .exe tells the computer to execute the instructions inside it.
.dll — Dynamic Link Library. A file containing code that other programs share and reuse.
.bat — Batch file. A text file with a list of commands for Windows to run.
.ps1 — PowerShell script. A powerful command file that can automate almost anything.
.pdf — PDF document. Can contain hidden malicious code in some attacks.
.docx / .xlsx — Office documents. Can contain macros (mini-programs) that attackers abuse.
.zip / .rar — Compressed archives. Often used to package malware and bypass detection.

### Technical Breakdown — File Metadata

Every file has metadata that the OS tracks:

Created time — when the file was first created
Modified time — when the content was last changed
Accessed time — when the file was last opened
Owner — which user account owns the file
Permissions — who can read, write, or execute the file
Hash — a unique fingerprint of the file's content (we will explain this more)

A hash is critical for security. A file's hash (like an MD5 or SHA256 hash) is a unique number calculated from the file's content. If you change even one character in the file, the hash changes completely. This lets us verify if a file has been tampered with and identify known malware.

Example:
SHA256 hash of a clean version of notepad.exe: abc123def456...
If the hash on a suspicious computer is different, the file has been modified — this is a major red flag.

---

## Part B: What Is a Process?

### Simple Explanation

A process is a program that is currently running.

A file sits quietly on the hard drive doing nothing. When you double-click it to open it, the OS loads it into memory and starts executing its instructions. At that moment, it becomes a process.

Think of it this way:
- A recipe book = a file (sitting on the shelf, doing nothing)
- A chef cooking from that recipe = a process (active, doing something right now)

### Real-World Analogy

Imagine a factory:

The blueprint (file) describes how to build a car.
The assembly line (process) is actively building cars right now, using workers (CPU) and materials (memory).

Multiple assembly lines can use the same blueprint at the same time.
Similarly, multiple processes can run from the same file simultaneously.

### Technical Breakdown

When a process starts, it gets:
- A Process ID (PID) — a unique number the OS assigns (e.g., PID 1234)
- A Parent Process ID (PPID) — the PID of the process that started it
- Memory space — a section of RAM dedicated to this process
- CPU time — the OS schedules how much CPU time this process gets
- Threads — units of execution within the process

The parent-child relationship between processes is crucial for security:

Normal behavior:
explorer.exe (Windows shell) → opens → chrome.exe (browser)
Parent: explorer.exe → Child: chrome.exe

Suspicious behavior:
word.exe (Microsoft Word) → opens → powershell.exe → downloads a file
Parent: word.exe → Child: powershell.exe
Why is this suspicious? Word should not be launching PowerShell. If it does, it likely means Word was used to deliver malware (through a malicious macro).

### Key Windows Processes

These are normal, expected processes on every Windows computer:

System — The core OS process. PID is always 4.
smss.exe — Session Manager. Manages user sessions.
csrss.exe — Client/Server Runtime. Manages the Windows environment.
wininit.exe — Windows Initialization.
services.exe — Service Control Manager. Manages Windows services.
lsass.exe — Local Security Authority. Handles authentication. This is a prime target for attackers.
svchost.exe — Service Host. Runs Windows services. Multiple copies run simultaneously — this is normal.
explorer.exe — Windows Explorer. The graphical shell (desktop, file explorer).
taskmgr.exe — Task Manager.

Attackers often name their malware to look like these legitimate processes:
- svch0st.exe (zero instead of the letter O)
- lsass_.exe (extra underscore)
- explorer32.exe (fake variant)

### SOC Perspective

As a SOC analyst, understanding processes lets you answer:

"What is this program? Should it be running? Who started it? What is it doing?"

Process analysis involves:

1. Is this a known, legitimate process?
2. Is it running from the expected location?
   (svchost.exe should run from C:\Windows\System32\ — if it runs from C:\Users\john\, that is suspicious)
3. Who is the parent process?
   (Word spawning PowerShell = suspicious)
4. What is the process doing?
   (Making network connections? Reading sensitive files? Injecting into other processes?)
5. What is the hash of the executable?
   (Does it match the known-good hash of the legitimate program?)

---

## Real Examples

Example 1 — Normal:
```
Process: chrome.exe
PID: 4521
Parent: explorer.exe
Location: C:\Program Files\Google\Chrome\Application\chrome.exe
User: john.smith
```
Normal. Chrome opened from the desktop (explorer.exe) from its expected location.

Example 2 — Suspicious:
```
Process: powershell.exe
PID: 7892
Parent: winword.exe
Location: C:\Windows\System32\powershell.exe
User: john.smith
Command: powershell.exe -enc JABjAGwAaQBlAG4AdA...
```
Suspicious. Word (winword.exe) spawned PowerShell. The command line is encoded (the -enc flag means it is base64 encoded — attackers do this to hide what they are doing).

Example 3 — Malware disguise:
```
Process: svchost.exe
PID: 9234
Parent: explorer.exe
Location: C:\Users\john\AppData\Roaming\svchost.exe
User: john.smith
```
Suspicious. The real svchost.exe runs from C:\Windows\System32\. This one runs from the user's AppData folder. The parent is explorer.exe (not services.exe as expected). This is almost certainly malware.

---

## Common Mistakes Beginners Make

Mistake 1: Confusing a file with a process.
Reality: A file is data at rest. A process is a file that has been loaded into memory and is actively running.

Mistake 2: Assuming a process is safe because the name looks familiar.
Reality: Attackers name malware after legitimate processes. Always check the location and parent process.

Mistake 3: Ignoring the parent process.
Reality: The parent-child relationship is one of the most powerful clues in malware investigation.

Mistake 4: Not knowing where legitimate processes should run from.
Reality: A process running from an unexpected location is a major red flag. Learn the expected locations of common Windows processes.

---

## Summary

A file is data stored on disk. It does nothing until opened.
A process is an actively running program in memory.
Files have metadata: creation time, modification time, hash, owner.
Processes have PIDs, parent processes, locations, and command lines.
Attackers abuse both files and processes — disguising malware as legitimate files and processes.
As a SOC analyst, you will investigate processes to find malware and understand what attackers did.

---

## Practice Questions

**Easy:**
1. What is the difference between a file and a process?
2. What does a file extension tell you?
3. What is a PID?

**Medium:**
4. You see a process called "svchost.exe" running from C:\Users\Administrator\Desktop\svchost.exe. Is this suspicious? Why?
5. What is a file hash and why is it useful for detecting malware?

**Thinking Questions:**
6. Microsoft Word (winword.exe) has spawned a process called cmd.exe, which then ran a command downloading a file from the internet. Walk through why this is suspicious, step by step.
7. An attacker wants to hide their malware on a Windows computer. What filename and location would make the most sense to use to blend in with normal processes?
