# Lesson 1.5 — What Is an IP Address?

**Phase:** 1 — Absolute Basics
**Prerequisite:** Lesson 1.4
**Time to complete:** 30 minutes

---

## Simple Explanation

An IP address is the unique address of a computer on a network.

Every device connected to a network — your laptop, your phone, your company's servers — has an IP address. It is how devices find and communicate with each other.

IP stands for Internet Protocol. It is the fundamental addressing system of the internet and all networks.

---

## Real-World Analogy

An IP address is like a street address for a computer.

Just as every house has a unique address (123 Main Street, Springfield), every computer on a network has a unique IP address.

When you send a letter, you write the recipient's address on the envelope. When a computer sends data, it includes the destination IP address in every packet. Routers use that address to deliver the packet to the right place.

---

## What Does an IP Address Look Like?

There are two versions of IP addresses:

IPv4 (the most common):
Format: Four numbers separated by dots, each between 0 and 255.
Example: 192.168.1.100

IPv6 (newer, used when IPv4 addresses ran out):
Format: Eight groups of four hexadecimal characters.
Example: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
You will see IPv4 most often in SOC work.

---

## Types of IP Addresses

Understanding the difference between these types is critical for your SOC work.

PUBLIC IP ADDRESS:
- Unique across the entire internet
- Assigned by your ISP
- Visible to the outside world
- Example: 85.214.132.117 (the address of your company as seen from the internet)
- When you visit google.com, Google sees your public IP, not your internal IP

PRIVATE IP ADDRESS (also called internal or RFC1918):
- Used inside a private network (home, office)
- Not routable on the public internet
- Ranges:
  10.0.0.0 to 10.255.255.255 (10.x.x.x)
  172.16.0.0 to 172.31.255.255 (172.16-31.x.x)
  192.168.0.0 to 192.168.255.255 (192.168.x.x)
- If you see any of these in a log, the traffic is internal

LOOPBACK ADDRESS:
- 127.0.0.1 (also written as "localhost")
- Refers to the computer itself
- Used for testing — communicating with yourself
- If you see a process connecting to 127.0.0.1, it is talking to something else on the same machine

SPECIAL ADDRESSES:
- 0.0.0.0 — Used to represent "all addresses" or "unspecified"
- 255.255.255.255 — Broadcast address (sends to all devices on the local network)

---

## How IP Addresses Are Assigned

DHCP (Dynamic Host Configuration Protocol):
Most computers get their IP address automatically from a DHCP server.
When your computer connects to a network, it says "Hello, I need an address." The DHCP server responds with a temporary IP address, a subnet mask, and other configuration.
These addresses can change each time a device connects.

Static IP:
Servers, network devices, and security appliances usually have fixed (static) IP addresses that never change. This makes them easier to manage and find.

DHCP Lease:
The IP address given by DHCP is temporary, called a "lease." After a period of time, the lease expires and the device may get a different IP address.

Why this matters for SOC:
If you see an alert from IP address 192.168.1.154, you need to know:
- What computer was assigned that address at the time of the incident?
- Is it still assigned to the same computer today?
- DHCP logs tell you who had which IP address at what time

---

## Subnets and Subnet Masks

A subnet is a group of IP addresses within a network.

Example:
Your company has IP addresses from 10.0.0.1 to 10.0.0.254.
The IT department is on 10.0.1.0/24
The Finance department is on 10.0.2.0/24
The HR department is on 10.0.3.0/24

The /24 notation (called CIDR notation) means the first 24 bits of the address are the network part, and the last 8 bits identify individual computers. This gives 254 usable addresses in that subnet.

Why subnets matter in SOC:
- Traffic should generally stay within its subnet or go through controlled points
- An HR computer talking directly to an IT server in an unusual way may be suspicious
- "Lateral movement" (an attacker moving from computer to computer) shows up as cross-subnet traffic

---

## NAT — Why Your Internal IP is Hidden

Your company might have 500 computers, all with private IP addresses. But the internet only sees one public IP address.

This is done through NAT (Network Address Translation). Your firewall/router translates internal private addresses to the company's single public IP address when traffic goes out.

This means:
- An attacker on the internet cannot directly connect to 192.168.1.100 (private)
- They can only see and try to connect to the public IP
- NAT provides a layer of protection (though not a complete defense)

In logs, you will see:
- Firewall logs showing the public IP for outbound traffic
- DHCP logs showing which internal computer had which private IP

Correlating these is a key analyst skill.

---

## IP Addresses as Evidence in SOC Work

IP addresses appear in almost every log. They are fundamental evidence.

What you do with an IP address:

1. Determine if it is internal or external.
   192.168.x.x = internal. 85.214.x.x = external.

2. For external IPs — look them up.
   - Geolocation: What country is this IP from?
   - Threat intelligence: Is this IP known to be malicious? Is it on any blocklists?
   - WHOIS: Who owns this IP? What company? What ISP?
   - Reputation: Has this IP been seen in other attacks?

3. For internal IPs — identify the device.
   - Check DHCP logs to find which computer had this IP at the time
   - Check Active Directory to find the computer name and user

---

## Real Examples

Example 1 — Internal traffic (normal):
```
Source IP: 192.168.1.55
Destination IP: 192.168.1.1
Port: 80
```
Internal computer talking to the internal gateway. Normal.

Example 2 — External connection from suspicious country:
```
Source IP: 203.0.113.42 (China — unknown organization)
Destination IP: 10.0.5.22 (company web server)
Port: 22 (SSH)
Time: 04:17:33
```
Suspicious. Someone from an unknown Chinese IP is trying to connect to your web server via SSH at 4 AM. This warrants investigation.

Example 3 — DHCP correlation:
Alert says: IP 192.168.1.154 made 5,000 failed login attempts on the file server.

You check DHCP logs:
```
192.168.1.154 was assigned to hostname: LAPTOP-JSMITH
User: john.smith@company.com
Lease start: 2024-03-15 08:00:00
Lease end: 2024-03-15 20:00:00
```
Now you know: John Smith's laptop made those failed login attempts. Was John's laptop compromised, or is John himself trying to brute force the server?

---

## Common Mistakes Beginners Make

Mistake 1: Assuming the IP in a log is always the attacker's real IP.
Reality: Attackers often route through VPNs, proxies, or Tor, hiding their real IP. The IP in the log may be a relay, not the attacker's actual location.

Mistake 2: Thinking an internal IP means the threat is internal.
Reality: Malware on an internal computer has an internal IP. External attackers who have compromised an internal system appear with internal IPs.

Mistake 3: Ignoring IP geolocation anomalies.
Reality: If a user who always logs in from New York suddenly appears from Nigeria, that is a serious red flag — even if they use the correct password.

Mistake 4: Not checking DHCP logs when investigating an IP.
Reality: DHCP leases change. The computer that had 192.168.1.154 yesterday might have a different IP today. Always match IPs to devices using DHCP logs at the exact time of the incident.

---

## Summary

An IP address is the unique address of a device on a network.
Private IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x) are internal.
Public IPs are assigned by ISPs and visible on the internet.
DHCP assigns IPs automatically; static IPs are fixed.
Correlating IPs with DHCP logs tells you which device was at that address.
IP addresses are fundamental evidence — they appear in every log you will read.

---

## Practice Questions

**Easy:**
1. What is an IP address?
2. Is 192.168.10.50 a public or private IP?
3. What does DHCP do?

**Medium:**
4. An alert shows suspicious traffic from internal IP 10.0.2.88. What logs would you check to find out which computer or user this was?
5. Why might an attacker's real IP address not appear in your logs?

**Thinking Questions:**
6. A user account that normally logs in from IP addresses registered to New York, USA suddenly logs in from an IP registered to Romania. The login time is 2:30 AM and the username and password are correct. Is this suspicious? What are the possible explanations? What would you do?
7. You see outbound traffic from internal IP 172.16.5.40 to external IP 91.108.4.100 on port 443 (HTTPS). The volume is 800 MB in 10 minutes at 1 AM. Walk through your thinking step by step.
