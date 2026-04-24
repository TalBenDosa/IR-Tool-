# Forensic Master-Analyzer v4.0

Autonomous Windows forensic investigator. Inspects RAM, crash dumps,
Windows event logs (Security + Sysmon + PowerShell + AppLocker +
CodeIntegrity + TerminalServices + BITS), registry, autoruns (Run
keys + Winlogon + AppInit + IFEO + Startup folders), WMI persistence,
Windows Defender state + MPLog history, scheduled tasks, prefetch,
BAM/DAM execution history, SRUM, browser artifacts (Chrome/Edge/
Firefox/Brave), Chromium password stores, LNK / recent-docs, USB
device history, COM hijack indicators, ETW tampering, Volume Shadow
Copies, BITS jobs, LSA/SAM access indicators, the live process tree,
and the $MFT — then emits a single HTML report with concrete
verdicts and a Sigma rule engine on top.

## What's new in v4.0

- **Collapsible-card report UX** — every section (15 in total) is
  a click-to-open `<details>` element. High-signal sections open
  by default, noisy ones (Informational, Super-Timeline, Process
  Tree, Event ID Overview, Network Activity, System Information)
  collapse by default. Toolbar buttons Expand all / Collapse all.
- **Per-finding Deep-Dive panel** — every High/Critical finding
  card now contains a collapsible deep-analysis block with:
  - Kill-chain phase (Credential Access, Persistence, Lateral,
    Defense Evasion, Exfil, etc.)
  - Confidence score 0-100 with gradient bar and reason list
    (SHA256 computed, Authenticode status, YARA match,
    correlation count, IoC match, etc.)
  - MITRE ATT&CK mapping table with live links to attack.mitre.org
    for every technique
  - Impact assessment specific to the attack phase
  - Immediate Actions + Hardening Actions playbook
  - Hunting queries (Splunk SPL / Azure Sentinel KQL / Elastic EQL)
    pre-rendered for the fleet
  - Threat-intel panel (VirusTotal, AbuseIPDB, GeoIP) when API keys
    are supplied
- **VirusTotal / AbuseIPDB / GeoIP enrichment** (opt-in via
  API keys / mmdb path) — every hash and IP in the findings gets
  reputation-scored and geolocated.
- **Baseline / Delta mode** — `--baseline prev.json` annotates
  each finding with `NEW-since-baseline` or `known-since-baseline`
  tags for clean cross-run comparison.
- **NTDS.dit offline parser** (`--ntds PATH`) — extracts account
  inventory, flags AS-REP-roastable accounts, `PASSWD_NOTREQD`,
  dormant accounts (>90d no logon).
- **Driver Authenticode audit** — enumerates 400+ loaded kernel
  drivers, verifies Authenticode signature on each, flags unsigned
  / hash-mismatch / user-path drivers as BYOVD indicators.
- **Optional pcap capture** — `--pcap-duration N` triggers a
  built-in Windows pktmon capture during triage.
- **PDF export** — `--pdf` renders the full HTML via headless
  Edge/Chrome. `--exec-pdf` emits a 1-page executive summary PDF
  suitable for CISO handoff.
- **Triage state per finding** — every High/Critical card has a
  clickable triage badge (Open / Confirmed / False-Positive /
  Dismissed / Escalated) with state saved to localStorage;
  "Export JSON" button on the toolbar downloads all triage
  decisions.
- **Theme + RTL toggles** — Dark ↔ Light theme + LTR ↔ RTL
  layout toggles; `--lang he` defaults to RTL for Hebrew clients.

## What's in v3.1 (carried forward)

- **Parallel evtx parsing** — 6 log files processed concurrently;
  noticeably faster than sequential on multi-core hosts.
- **Sigma rule engine** — simplified YAML-ish matcher with a
  curated bundled ruleset (PsExec service, encoded-PS download
  cradles, LSASS comsvcs MiniDump, VSS deletion, Defender
  disablement, WDigest enablement, external RDP, suspicious
  scheduled-task actions, temp-path service installs). Add
  custom rules by extending `BUNDLED_SIGMA_RULES` or passing
  them to `SigmaEngine` directly.
- **SRUM body parsing** — reads SRUDB.dat network & application
  usage tables when `dissect.esedb` is installed (auto-bootstrapped);
  produces a per-app bandwidth summary. Falls back to a presence
  report otherwise.
- **Windows Defender MPLog ingestion** — parses MPLog-*.log files
  for historical detections and exclusion events.
- **USB device history** — USBSTOR enum from SYSTEM hive + setupapi
  device-install log.
- **COM hijack analyzer** — walks HKCU CLSID overrides; flags any
  that shadow a system CLSID with a user-writable DLL (T1546.015).
- **ETW tampering checks** — PS script-block logging disabled?
  Defender AntiSpyware policy disabled? EventLog-Security
  autologger killed?
- **WDAC / AppLocker channels** — Code Integrity + AppLocker EXE/DLL
  + AppLocker MSI/Script event logs added to default ingest.
- **Volume Shadow Copy enumeration** — `vssadmin list shadows`
  parsed; points responder at historical versions of key artifacts.
- **LNK / JumpList parser** — recent-docs shortcuts (Windows +
  Office) parsed for target path, network share, arguments,
  MAC timestamps. Flags shortcuts to network shares or transient
  paths.
- **BITS jobs** — `bitsadmin /list /allusers /verbose` parsed.
  Jobs with completion-command triggers flagged as persistence
  (T1197).
- **Outlook profile / PST inventory** — registry + file-system
  enumeration. Foundation for deeper rule parsing.
- **Chromium password-store inventory** — Local State + Login Data
  presence, encrypted-key length, mtime.
- **Browser artifacts** — Chrome / Edge / Brave / Firefox history
  + downloads via SQLite. Script / shortcut downloads flagged
  (HTA/VBS/JS/PS1/LNK). Container-format downloads from non-cloud
  hosts (ISO/IMG/VHD/CHM). Onion-domain visits. Public-IP-literal
  URL visits (excluding localhost/RFC1918/cloud-CDN).
- **LSA Secrets / SAM access indicators** — event-pattern search
  for references to SAM / SECURITY hive paths (T1003.002/004).

## What's in v3.0 (carried forward)

- **File enrichment**: SHA256 + Authenticode + YARA scanning on every
  flagged binary. Signed-vendor binaries soften severity; YARA hits on
  carved PEs escalate to Critical.
- **YARA integration** with a built-in ruleset (Mimikatz, Cobalt Strike,
  Meterpreter, PowerSploit, AMSI-bypass). Add your own with
  `--yara-rules`.
- **IoC ingestion**: `--iocs iocs.json` cross-matches IPs, domains,
  hashes, and filenames against every finding; any hit becomes a
  Critical IoC-match finding.
- **Sysmon detectors**: process-access-to-lsass (EID 10), DLL
  sideloading (7), process tampering / hollowing (25), Cobalt-Strike-
  shaped pipes (17), DGA-shaped DNS queries (22) from
  `Microsoft-Windows-Sysmon/Operational`.
- **BAM/DAM analysis**: every program that ran with timestamp, from
  `HKLM\SYSTEM\...\bam\State\UserSettings`. Survives after Prefetch
  ages out.
- **SRUM presence report**: flags SRUDB.dat (60-day process+network
  history) for follow-up parsing.
- **Super-Timeline section**: unified chronological view across
  findings, events, BAM, Prefetch, and crash dumps.
- **MITRE ATT&CK heatmap**: tactic-grouped technique coverage.
- **Interactive HTML filter**: type-to-search across the entire
  report.
- **Chain-of-custody manifest** (`report.manifest.json`) with SHA256
  of outputs, collector identity, and platform info for legal
  retention.
- **Redaction mode** (`--anonymize`): strips usernames, IPs, SIDs, and
  hostnames from the report before it leaves the host.
- **Severity threshold** (`--min-severity high`): render only findings
  at or above the chosen level.
- **Cloud-IP allowlist**: drops ~90% of benign outbound to Microsoft,
  Google, Cloudflare, AWS, Akamai, Apple, Meta from "dormant C2"
  detection.

## What's explicitly NOT in v3.1 (roadmap)

- **PyInstaller single-exe distribution** — requires external build.
- **Unit tests** — require sample-artifact corpus.
- **Fleet orchestration / SIEM push (Splunk/Sentinel)** — requires a
  central server.
- **evtx_dump (Rust) integration** — would cut evtx parse time
  another 5-10×; pending a bundled binary.
- **Kernel-callback rootkit detection** — would need custom
  Volatility3 symbols for modern Windows 11.
- **Full Outlook PST / MSG rule parsing** — MAPI / Exchange Online
  rule extraction; v3.1 limits to profile/PST inventory.
- **DPAPI master-key cracking** — offline decryption of browser
  password stores; we detect store presence only.
- **Baseline / delta mode** — compare two runs; pending.
- **Interactive timeline visualization** (D3.js) — current timeline
  is tabular.
- **GeoIP / STIX-TAXII / VirusTotal API integration** — pending.
- **Hebrew / RTL UI, PDF export** — pending.

## Requirements

- **Windows 10 / 11**
- **Python 3.9 or newer** ([download](https://www.python.org/downloads/)) —
  tick *"Add Python to PATH"* during install.

First run auto-installs: `psutil`, `pefile`, `python-evtx`,
`python-registry`, `volatility3`, `yara-python`.

## Quick start

**Double-click** `Run-Analysis.bat` — report opens on your Desktop as
`ForensicReport.html`.

**Right-click** `Run-Analysis-Admin.ps1` → *Run with PowerShell* for
the fuller version with Amcache / Shimcache / UserAssist / BAM (admin
required; the script auto-elevates, snapshots the locked hives with
`reg save` and `esentutl /y /vss`, runs the analyzer, wipes its
snapshot, and opens the report).

## Command-line usage

```powershell
# Default live run
python forensic_master_analyzer.py

# With offline memory image (Volatility3 plugins activate)
python forensic_master_analyzer.py --memory C:\IR\mem.raw

# With operator IoC feed
python forensic_master_analyzer.py --iocs C:\IR\iocs.json

# Only show HIGH/CRITICAL findings
python forensic_master_analyzer.py --min-severity high

# Anonymized report for external sharing
python forensic_master_analyzer.py --anonymize

# Full invocation
python forensic_master_analyzer.py `
    --memory       C:\IR\mem.raw `
    --system-hive  C:\IR\SYSTEM `
    --amcache      C:\IR\Amcache.hve `
    --ntuser       C:\IR\NTUSER.DAT `
    --mft          C:\IR\MFT `
    --iocs         C:\IR\iocs.json `
    --yara-rules   C:\IR\custom.yar `
    --output       C:\IR\report.html `
    --verbose
```

### IoC JSON format

```json
{
  "ips":              ["45.9.148.99", "194.165.16.77"],
  "domains":          ["evil.com", "bad.actor.tk"],
  "hashes_sha256":    ["abc...", "def..."],
  "hashes_md5":       ["123...", "456..."],
  "filenames":        ["payload.exe", "stealer.dll"],
  "yara":             ["C:/IR/campaign.yar"]
}
```

### All flags

| Flag | Meaning |
|---|---|
| `--memory PATH` | Offline memory image (.raw/.dmp/.lime) for Volatility3 |
| `--live` | Force live triage even with `--memory` |
| `--dumps PATH…` | Explicit dump files (auto-discovery is default) |
| `--evtx PATH…` | Event log files (default: winevt\Logs including Sysmon) |
| `--amcache / --system-hive / --ntuser PATH` | Hive snapshots |
| `--mft PATH` | Raw $MFT extract |
| `--prefetch DIR` | Prefetch folder |
| `--tasks DIR` | Scheduled Tasks root |
| `--iocs PATH` | Operator IoC feed (JSON) |
| `--yara-rules PATH…` | Extra YARA rule files |
| `--min-severity {info,low,medium,high,critical}` | Drop below threshold |
| `--anonymize` | Redact PII before writing the report |
| `--no-enrichment` | Skip hash/Authenticode/YARA (faster) |
| `--output PATH` | Output HTML path |
| `--workdir DIR` | Carved-artifact work directory |
| `--verbose` | Progress to stdout |
| `--no-bootstrap` | Skip auto pip-install |

## Report contents

1. **Executive Summary** — findings-first, each with investigator
   conclusion and severity pill.
2. **Threat Severity Score** (0–100, dedup + per-category decay).
3. **Coverage table** — what was inspected and what wasn't.
4. **MITRE ATT&CK heatmap** — tactic-grouped technique coverage.
5. **Memory Forensics section** — RAM / live process-tree / crash dumps.
6. **Confirmed Malicious Findings** — HIGH + CRITICAL cards with clean
   evidence tables, IoC-enrichment panels (SHA256, Authenticode, YARA
   hits), correlated events, and collapsed raw JSON.
7. **Security Event ID Overview** — 50+ Event IDs grouped by MITRE
   attack phase with counts, channel, first/last seen, and analyst
   explanation.
8. **Super-Timeline** — unified chronological view across all sources.
9. **Additional Observations** (Medium, collapsed).
10. **Informational** (Low, collapsed).
11. **Remediation Plan**.

## Output artifacts

Next to `--output`:

- `report.html` — visual report (with interactive filter bottom-right).
- `report.json` — structured findings + event overview + timeline.
- `report.manifest.json` — chain-of-custody: tool, collector,
  host, SHA256 of each output.
- `workdir/memdumps/*.bin` — PE buffers carved from RAM (if
  `--memory` was supplied and malfind produced hits).

## False-positive hardening

- Signed-vendor whitelist for services (60+ vendors).
- Authenticode signature check softens severity on signed binaries.
- Known-flaky-app crash filter (WhatsApp / Chrome / LockApp / Teams).
- Runtime-module filter (ucrtbase / Xaml / ntdll / CLR).
- Detector-script recognition (EDR hunt scripts don't FP on their own
  IoC strings).
- Windows session-init pseudo-accounts (umfd-*, dwm-*) in 4648.
- Cloud-IP allowlist (Microsoft/Google/AWS/Cloudflare/Akamai/Apple).
- Keyboard-typo detector for failed-logon bursts.

## License

Provided to the client as-is for internal incident-response use.
