# Lesson 1.4 — What Is the Internet?

**Phase:** 1 — Absolute Basics
**Prerequisite:** Lessons 1.1–1.3
**Time to complete:** 25 minutes

---

## Simple Explanation

The internet is a massive network of computers connected to each other all around the world.

Every time you open a website, watch a video, or send an email, your computer is communicating with another computer somewhere else on the planet. The internet is the infrastructure that makes this communication possible.

Think of the internet as a global postal system — but instead of delivering letters and packages, it delivers digital information at nearly the speed of light.

---

## Real-World Analogy

Imagine every city in the world had a post office. Every home had a mailbox. Every piece of information you wanted to share — a document, a photo, a message — you put it in an envelope and mailed it.

The postal roads connect every city to every other city. The postal workers sort the letters and make sure they reach the right destination.

The internet is the same, except:
- The letters are called "packets" (small chunks of data)
- The roads are cables (fiber optic, copper), wireless signals, and satellite links
- The postal workers are called routers (devices that direct traffic)
- Every destination has an address called an IP address

---

## How the Internet Works (Step by Step)

Step 1: You type a website address into your browser (like www.google.com).

Step 2: Your computer does not know where google.com is located. It asks a DNS server (a special computer that knows the addresses of all websites). The DNS server replies with Google's IP address (e.g., 142.250.80.4).

Step 3: Your computer breaks your request into small pieces called packets. Each packet contains:
- Where it came from (your IP address)
- Where it is going (Google's IP address)
- A piece of the actual message

Step 4: The packets leave your computer and travel through your router, then through your Internet Service Provider (ISP), through a series of routers, and eventually reach Google's servers.

Step 5: Google's servers process your request and send back the webpage — also broken into packets.

Step 6: Your computer receives the packets, reassembles them in the right order, and displays the webpage.

This entire process happens in milliseconds.

---

## Deeper Explanation — The Infrastructure

The internet is built on physical infrastructure:

Cables:
Most internet traffic travels through cables. Across continents, massive undersea fiber optic cables carry trillions of bits per second. These cables are critical infrastructure — cutting one can disrupt internet service for entire countries.

ISPs (Internet Service Providers):
Your internet connection goes through a company that provides internet access (like Comcast, AT&T, or Vodafone). They connect your home or office to the broader internet.

Routers:
Routers are the traffic directors of the internet. They receive packets and decide the best path to forward them. A packet from London to Tokyo might travel through 15 or 20 different routers.

Data Centers:
Websites and services live on servers in massive buildings called data centers. Google, Amazon, Microsoft, and other companies have data centers all over the world.

---

## Technical Breakdown — Packets and Protocols

When your computer sends data, it does not send it all at once. It breaks the data into packets. Each packet is typically 1,500 bytes or smaller.

Why use packets?
- Efficiency: Multiple conversations can share the same cable simultaneously
- Reliability: If one packet is lost, only that small piece needs to be re-sent, not the entire file
- Routing flexibility: Different packets from the same conversation can take different paths through the internet

Protocols define the rules for how packets are formatted and sent. The most important protocol is called TCP/IP — you will learn this in depth in Phase 3.

---

## The Difference Between the Internet and a Network

A network is a group of computers connected to each other in a specific location (like your office or home).

The internet is a network of networks — billions of individual networks all connected together.

Your company has its own internal network. That network connects to the internet through a router and firewall. The firewall controls what traffic can enter or leave the company network.

This distinction matters because:
- Attacks can come from the internet (external threats)
- Attacks can also come from inside the company network (insider threats or malware already inside)
- Your job as a SOC analyst includes monitoring traffic in both directions

---

## SOC Perspective

The internet is both the company's connection to the world and the primary attack surface.

Most attacks originate from the internet:
- Phishing emails come from external email servers
- Malware is downloaded from external servers
- Hackers connect to company systems from external IP addresses
- Data exfiltration (stealing data) goes out to external servers

As a SOC analyst, you will constantly be looking at:

Inbound traffic — what is coming INTO the network from the internet?
Is anyone trying to connect to our systems? From what countries? On what ports?

Outbound traffic — what is going OUT from the network to the internet?
Is any internal computer talking to a suspicious server? Sending unusual amounts of data?

Your tools (SIEM, firewall logs, proxy logs) give you visibility into this traffic.

Key questions you will ask:
- Is this IP address known malicious?
- Has this domain been seen in threat intelligence feeds?
- Is this user connecting to somewhere they never connect to?
- Is data being sent out at unusual times or in unusual volumes?

---

## Real Examples

Example 1 — Normal outbound traffic:
```
Source: 192.168.1.45 (internal workstation, john.smith)
Destination: 216.58.204.100 (google.com)
Port: 443 (HTTPS)
Time: 09:23:14
```
Normal. An employee browsing Google during work hours.

Example 2 — Suspicious outbound traffic:
```
Source: 192.168.1.45 (internal workstation, john.smith)
Destination: 185.220.101.47 (Tor exit node — anonymous network)
Port: 9001
Time: 02:14:33
```
Very suspicious. Why is an employee's computer connecting to the Tor network at 2 AM? This could indicate:
- The computer is compromised and is receiving instructions from attackers
- The user is trying to exfiltrate data anonymously

Example 3 — Data exfiltration:
```
Source: 192.168.1.112 (server — file storage)
Destination: 45.142.212.100 (unknown IP in Russia)
Protocol: HTTPS
Data volume: 4.7 GB transferred in 3 minutes
Time: 03:45:00
```
Critical alert. 4.7 GB of data leaving a file server to an unknown external IP at 3:45 AM is almost certainly data theft.

---

## Common Mistakes Beginners Make

Mistake 1: Thinking the internet is just "websites."
Reality: The internet carries all kinds of traffic — websites, email, file transfers, remote access, video calls, and also attack traffic.

Mistake 2: Thinking "it came from the internet" means it is external.
Reality: Once malware is inside your network, it communicates back to the internet. Attacks are not just inbound — the outbound traffic reveals compromised systems.

Mistake 3: Ignoring internal network traffic.
Reality: Once an attacker gets inside, they move laterally (computer to computer) within the internal network. You must monitor internal traffic too.

---

## Summary

The internet is a global network of connected computers.
Data travels in small packets guided by routers.
DNS translates domain names to IP addresses.
The internet is both essential and the primary source of cyber threats.
SOC analysts monitor both inbound traffic (attacks coming in) and outbound traffic (data going out or malware communicating).

---

## Practice Questions

**Easy:**
1. What is a packet?
2. What does a router do?
3. What is an ISP?

**Medium:**
4. Why does data travel in packets rather than as one continuous stream?
5. What is the difference between your company's internal network and the internet?

**Thinking Questions:**
6. A computer in your organization is sending 2 GB of data every night at midnight to an IP address in a foreign country. No user is logged in. What does this suggest?
7. An attacker is already inside your network (they got in through a phishing email). What kinds of internet traffic would you look for to detect their presence?
