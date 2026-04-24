# Lesson 2.3 — What Is a Network?

**Phase:** 2 — IT & Networking Foundations
**Prerequisite:** Lesson 1.4
**Time to complete:** 30 minutes

---

## Simple Explanation

A network is a group of computers and devices that can communicate with each other.

When your office has 200 employees and all their computers can share files, print to the same printers, and access the same servers — they are on a network.

The network is the infrastructure that makes this communication possible. It includes physical cables (or wireless signals), switches, routers, firewalls, and the rules that govern how data flows.

---

## Real-World Analogy

Think of a network like the road system in a city.

Roads connect buildings. Cars (data packets) travel on roads from one building (computer) to another. Traffic lights and signs (network rules/protocols) control how cars move. The highway (backbone connections) carries lots of traffic between neighborhoods.

When you add a new building (computer) to the city, you connect it to the road network. The road system handles getting data where it needs to go.

---

## Types of Networks

LAN — Local Area Network:
A small network in one location — your home, your office floor, a school.
All devices are nearby and connected by cables or Wi-Fi.
Fast: typically 1 Gbps or more.
Example: All computers in one office building sharing the same network.

WAN — Wide Area Network:
A network that spans large geographic areas — connecting multiple offices across a city, country, or the world.
The internet is the largest WAN.
Slower than LAN due to distance.
Example: A company's network connecting its New York and London offices.

MAN — Metropolitan Area Network:
Between a LAN and WAN — covers a city.
Less common term in practice.

WLAN — Wireless LAN:
A LAN that uses Wi-Fi instead of cables.
In office environments, wireless access points connect wireless devices to the wired network.

VLAN — Virtual LAN:
A logically separated network within the same physical network.
Example: The IT department and Finance department are on the same physical switches, but configured as separate VLANs so their traffic is isolated.
VLANs are important for security segmentation.

DMZ — Demilitarized Zone:
A special network zone for servers that must be accessible from the internet (web servers, email servers).
Isolated from the internal network to limit the damage if a DMZ server is compromised.

---

## Key Network Devices

Switch:
Connects devices within the same LAN. When computer A wants to talk to computer B on the same network, the switch handles it.
Switches work at Layer 2 (using MAC addresses — explained in Phase 3).
Think of a switch as a post office for a single building.

Router:
Connects different networks. When your computer wants to talk to a computer on a different network (or the internet), the router handles it.
Routers work at Layer 3 (using IP addresses).
Think of a router as the highway system connecting different cities.

Firewall:
Controls what traffic is allowed to pass between networks.
Has rules: "Allow this, block that."
Is the security gate between the internet and your internal network (and often between internal zones).
Can be hardware or software.

Access Point (AP):
Provides Wi-Fi connectivity. Wireless devices connect to an AP, which connects them to the wired network.

Proxy Server:
Acts as an intermediary between users and the internet.
Employees' web traffic goes through the proxy, which can filter, log, and inspect it.
Critical for SOC — proxy logs show every URL visited by every employee.

Load Balancer:
Distributes traffic across multiple servers.
If one server gets too much traffic, the load balancer redirects some to other servers.
Also provides high availability.

---

## Network Segmentation — The Security Concept

Segmentation means dividing a network into zones with different trust levels and controlling traffic between them.

Why segmentation matters:
If an attacker compromises one computer, segmentation limits how far they can move.
Without segmentation, one compromised computer can easily attack all others.
With segmentation, the attacker is contained in one zone.

Common enterprise zones:

Internet Zone:
Completely untrusted. Everything from the internet lives here.

DMZ (Demilitarized Zone):
Semi-trusted. Public-facing servers (web, email, VPN) live here.
Can be reached from the internet but has restricted access to internal resources.

Internal Network:
Trusted. Employee workstations, printers, internal services.
Divided into sub-zones by department (IT, Finance, HR, etc.)

Server Zone:
Highly controlled. Critical servers (file servers, database servers, Active Directory).
Only specific, authorized traffic should reach here.

Restricted Zone:
Most sensitive. Domain Controllers, payroll systems, PCI-scoped systems.
Access is tightly controlled and logged.

---

## SOC Perspective — Why Networks Matter

As a SOC analyst, you monitor network traffic to detect:

1. External attacks hitting the perimeter (firewall):
   - Port scanning
   - Brute force attempts against public-facing services
   - Exploitation of vulnerabilities in public servers

2. Malware communicating out (C2 traffic):
   - Infected computers "calling home" to attacker servers
   - Data exfiltration to external servers

3. Lateral movement (attacker moving inside):
   - An attacker compromises Computer A, then tries to reach Computer B, C, D
   - Unusual traffic between systems that do not normally communicate

4. Policy violations:
   - Employees accessing prohibited websites
   - Unauthorized software communicating on the network

Your network visibility tools:
- Firewall logs — what was allowed/blocked at the perimeter
- Proxy logs — what URLs employees visited
- IDS/IPS — detected attack signatures in network traffic
- NetFlow — summary statistics of all network conversations (who talked to whom, how much data)

---

## Real Examples

Example 1 — Normal network traffic:
```
Source: 192.168.1.50 (employee workstation)
Destination: 192.168.10.5 (file server)
Protocol: SMB
Port: 445
Action: Allow
```
Employee accessing a file share. Normal.

Example 2 — Lateral movement:
```
Source: 192.168.1.50 (employee workstation — LAPTOP-JSMITH)
Destination: 192.168.1.51 (LAPTOP-KBROWN) — another workstation
Protocol: SMB
Port: 445
Time: 03:22:14
Action: Allow
```
One workstation scanning another workstation via SMB at 3 AM. Workstations typically do not communicate with each other. This is likely lateral movement.

Example 3 — Port scan:
```
Source: 45.142.212.100 (external IP)
Destination: 203.0.113.50 (company firewall / public IP)
Events: SYN to port 22, 80, 443, 3389, 8080, 8443, 3306, 1433 (within 2 seconds)
Action: Block (most ports)
```
An attacker scanning common ports on the company's public IP. The firewall blocked most ports, but this tells the attacker which services are publicly accessible.

---

## Common Mistakes Beginners Make

Mistake 1: Thinking the firewall protects everything.
Reality: The firewall controls perimeter traffic but cannot see encrypted traffic without additional inspection. It also does not protect against threats that are already inside.

Mistake 2: Ignoring internal (east-west) traffic.
Reality: Once an attacker is inside, they move laterally on the internal network. Monitor internal traffic, not just traffic crossing the perimeter.

Mistake 3: Not understanding VLANs.
Reality: When an alert says "traffic crossed VLAN boundaries," that is significant. It may mean an attacker is trying to escape their segment.

---

## Summary

A network connects computers so they can communicate.
Key network types: LAN, WAN, WLAN, VLAN, DMZ.
Key devices: switch, router, firewall, proxy, access point.
Network segmentation limits how far an attacker can move after a compromise.
SOC analysts monitor network traffic at the perimeter (firewall), at the proxy (web traffic), and internally (lateral movement).

---

## Practice Questions

**Easy:**
1. What is the difference between a switch and a router?
2. What is a DMZ?
3. What is network segmentation and why is it important?

**Medium:**
4. Why would an attacker care about which VLANs exist in a target network?
5. A firewall log shows an internal workstation (192.168.5.22) is trying to connect to every other computer in the network in sequence (192.168.5.1, .2, .3, .4... .254). What is this behavior called and what does it indicate?

**Thinking Questions:**
6. A company has no network segmentation — all computers are on the same flat network. An attacker compromises one employee's laptop via a phishing email. What can the attacker do from there that they could not do in a segmented network?
7. Proxy logs show an employee's computer visited 1,200 different websites in one hour at 2 AM. The employee is not in the office. What is likely happening?
