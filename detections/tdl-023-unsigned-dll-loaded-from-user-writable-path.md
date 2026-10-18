# TDL-023 Unsigned DLL Loaded From User-Writable Path

**Severity:** medium (`alert.severity = 3`)  
**Schedule:** `*/15 * * * *` over `-30m` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** Unsigned DLL From User Path

## Description

Sysmon ImageLoad (7) where the DLL is unsigned and lives in Temp, AppData, Users\Public, ProgramData or Downloads. Legitimate software loads signed DLLs from Program Files or System32; this pattern is typical of DLL side-loading and search-order hijacking.

Filters Sysmon 7 image loads for unsigned DLLs whose path is in Temp, AppData, Users\Public, ProgramData or Downloads, and aggregates per host and DLL with the loading processes listed. Legitimate software loads signed DLLs from Program Files or System32, so an unsigned module from a user-writable path is a strong side-loading or hijacking indicator.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Persistence / Privilege Escalation / Defense Evasion | [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | Hijack Execution Flow: DLL Side-Loading |
| Persistence / Privilege Escalation / Defense Evasion | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | Hijack Execution Flow: DLL Search Order Hijacking |

NIST CSF: DE.CM-4

## Data source

- **Source:** Sysmon operational log
- **Macros:** `sysmon`
- **Fields used:** `ImageLoaded`, `Signed`, `process`, `user`, `host`

## Search (SPL)

```spl
`sysmon` EventCode=7 Signed=false ImageLoaded IN ("*\\Temp\\*", "*\\AppData\\*", "*\\Users\\Public\\*", "*\\ProgramData\\*", "*\\Downloads\\*") 
| stats count as loads, values(process) as loading_processes, values(user) as users, min(_time) as first_seen by host, ImageLoaded, Signed 
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S") 
| table first_seen, host, ImageLoaded, loading_processes, users, loads
```

## Tuning and false positives

- Self-updating applications that install per-user (Chrome, Teams, Slack, Zoom, Electron apps) live in AppData and sometimes ship unsigned helper DLLs. Allowlist by DLL hash or by the loading process's own signature rather than by path.
- Developers building code will load unsigned DLLs from their project directories under `Users`; scope developer workstations differently or exclude `*\source\*` and `*\repos\*`.
- Sysmon 7 is high volume; make sure your Sysmon config includes `Signed=false` as a filter condition so the forwarder is not overwhelmed.

## Response steps

1. Hash the DLL (Sysmon provides it in `Hashes`) and check it against known-good and threat-intel sources.
2. Identify the loading process; a signed, legitimate executable loading an unsigned DLL from its own directory is classic side-loading.
3. Check how the DLL and executable arrived (Sysmon 11 creation events, browser downloads, email attachments).
4. Look for the pair being executed by a scheduled task or startup entry (TDL-008, TDL-024) for persistence.
5. Collect both files and the process memory before remediation; the DLL's exports usually reveal the payload.

## Validation

Planted scenario `unsigned_dll` in `scripts/generate_logs.py`: unsigned DLL loaded from a Temp directory.

Result from `python -m harness.run_detections --only TDL-023` on `data/sample/` (1 row):

```json
{
  "first_seen": "2026-10-14 13:59:00",
  "host": "WS-FIN-07",
  "ImageLoaded": "C:\\Users\\lwright\\AppData\\Local\\Temp\\version.dll",
  "loading_processes": "C:\\Users\\lwright\\AppData\\Local\\Temp\\setup.exe",
  "users": "CORP\\lwright",
  "loads": 2
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-023]` and `::test_detection_is_quiet_on_benign_data[TDL-023]`.
