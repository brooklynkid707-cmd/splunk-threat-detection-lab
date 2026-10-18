# TDL-025 DNS Query From Scripting Or LOLBin Process

**Severity:** medium (`alert.severity = 3`)  
**Schedule:** `*/15 * * * *` over `-30m` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** DNS From LOLBin

## Description

Sysmon DNS query (22) issued by PowerShell, rundll32, regsvr32, mshta, wscript/cscript, certutil, bitsadmin or msbuild. Browsers, mail clients and svchost resolve names all day; living-off-the-land binaries doing it usually means a downloader or C2 stage.

Keeps Sysmon 22 DNS events whose issuing image is PowerShell, `rundll32`, `regsvr32`, `mshta`, a script host, `certutil`, `bitsadmin` or `msbuild`, and aggregates per host and process with the queried names listed. Browsers and mail clients resolve names constantly; these binaries doing so usually means a downloader or C2 stage.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Command and Control | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS |
| Defense Evasion | [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution |

NIST CSF: DE.CM-4

## Data source

- **Source:** Sysmon operational log
- **Macros:** `sysmon`
- **Fields used:** `process`, `query`, `user`, `host`

## Search (SPL)

```spl
`sysmon` EventCode=22 process IN ("*\\powershell.exe", "*\\pwsh.exe", "*\\rundll32.exe", "*\\regsvr32.exe", "*\\mshta.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\certutil.exe", "*\\bitsadmin.exe", "*\\msbuild.exe") 
| stats count as queries, dc(query) as unique_domains, values(query) as domains, values(user) as users, min(_time) as first_seen by host, process 
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S") 
| table first_seen, host, process, users, unique_domains, domains, queries
```

## Tuning and false positives

- Administrative PowerShell that calls `Invoke-WebRequest`, `Test-NetConnection` or module updates from the PowerShell Gallery resolves legitimate names. Allowlist by queried domain (your package repositories, update services) rather than by process.
- `rundll32.exe` is used by Windows for some URL handling and by `certutil` for CRL checks; destination names ending in a Microsoft or CA domain are expected.
- Configuration management agents running PowerShell on a schedule will show the same few domains every run; use `dc(query)` and new-domain logic to focus on first-seen names.

## Response steps

1. Review `domains`: newly registered, high-entropy or dynamic-DNS names are the priority; your own infrastructure can be dismissed.
2. Pivot to the process's full command line (Sysmon 1 by ProcessGuid) and, if PowerShell, to script block logs (4104).
3. Check Sysmon 3 for the connection that followed the resolution and TDL-017 for a threat-intel match on the answer.
4. If a stage was downloaded, locate the file (Sysmon 11 by the same process) and hash it.
5. Block the domains at the resolver and hunt for the same names from other hosts.

## Validation

Planted scenario `lolbin_dns` in `scripts/generate_logs.py`: powershell.exe issues DNS queries for staging domains.

Result from `python -m harness.run_detections --only TDL-025` on `data/sample/` (1 row):

```json
{
  "first_seen": "2026-10-14 09:48:00",
  "host": "WS-HR-03",
  "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "users": "CORP\\onelson",
  "unique_domains": 3,
  "domains": [
    "api.example-mirror.net",
    "cdn-stage.example.net",
    "files.example-mirror.net"
  ],
  "queries": 3
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-025]` and `::test_detection_is_quiet_on_benign_data[TDL-025]`.
