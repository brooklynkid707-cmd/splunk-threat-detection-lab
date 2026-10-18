# TDL-024 File Dropped In Startup Folder

**Severity:** medium (`alert.severity = 3`)  
**Schedule:** `*/15 * * * *` over `-30m` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** Startup Folder Persistence

## Description

Sysmon FileCreate (11) into a Start Menu\Programs\Startup folder by anything other than an installer. Startup folder entries execute at every logon and are one of the simplest persistence mechanisms.

Matches Sysmon 11 file creations whose target is inside any `Start Menu\Programs\Startup` directory, excluding writes made by `msiexec.exe`. Startup entries run at every logon, so a single event is sufficient to alert.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Persistence / Privilege Escalation | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |

NIST CSF: DE.CM-7

## Data source

- **Source:** Sysmon operational log
- **Macros:** `sysmon`
- **Fields used:** `TargetFilename`, `process`, `user`, `host`

## Search (SPL)

```spl
`sysmon` EventCode=11 TargetFilename="*\\Start Menu\\Programs\\Startup\\*" 
| search NOT process="*\\msiexec.exe" 
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S") 
| table event_time, host, user, process, TargetFilename
```

## Tuning and false positives

- Installers that are not MSI based (NSIS, Inno Setup, Squirrel) write Startup shortcuts for tray applications. Allowlist by installer process signature or by the shortcut name after confirming it once.
- Users pinning their own shortcuts via Explorer produce a `explorer.exe` write; it is benign but worth a quick check of what the shortcut points to.
- Group Policy and login scripts that populate the all-users Startup folder run as SYSTEM from `gpscript.exe` or `cmd.exe`; exclude the GPO script path explicitly.

## Response steps

1. Resolve the shortcut or file: for `.lnk` read the target path and arguments; for scripts read the content.
2. The writing `process` tells the story: PowerShell, a script host or a browser download writing here is malicious until shown otherwise.
3. Collect the target binary and check for related persistence (scheduled task, Run key, service) created by the same process GUID.
4. Remove the entry after collection and check whether it already executed (Sysmon 1 with the shortcut target as `Image` after a logon).
5. Search other hosts for the same file name or hash in Startup folders.

## Validation

Planted scenario `startup_folder` in `scripts/generate_logs.py`: PowerShell writes a .lnk into the Startup folder.

Result from `python -m harness.run_detections --only TDL-024` on `data/sample/` (1 row):

```json
{
  "event_time": "2026-10-14 14:36:00",
  "host": "WS-ENG-05",
  "user": "CORP\\nhill",
  "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "TargetFilename": "C:\\Users\\nhill\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-024]` and `::test_detection_is_quiet_on_benign_data[TDL-024]`.
