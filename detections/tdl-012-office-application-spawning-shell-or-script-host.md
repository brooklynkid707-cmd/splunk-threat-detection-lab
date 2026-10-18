# TDL-012 Office Application Spawning Shell Or Script Host

**Severity:** critical (`alert.severity = 5`)  
**Schedule:** `*/5 * * * *` over `-15m` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** Office Spawns Shell

## Description

Word, Excel, PowerPoint or Outlook spawning cmd, PowerShell, a script host, mshta, rundll32, regsvr32 or certutil (Sysmon 1). Office applications have no business launching these; the pattern is the hallmark of a macro or exploit document.

Matches Sysmon 1 where the parent is Word, Excel, PowerPoint or Outlook and the child is a shell, scripting host, `mshta`, `rundll32`, `regsvr32` or `certutil`. No threshold is applied; the parent/child combination itself is the indicator.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Initial Access | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Phishing: Spearphishing Attachment |
| Execution | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File |

NIST CSF: DE.CM-4

## Data source

- **Source:** Sysmon operational log
- **Macros:** `sysmon`
- **Fields used:** `parent_process`, `process`, `process_cmdline`, `user`, `host`

## Search (SPL)

```spl
`sysmon` EventCode=1 parent_process IN ("*\\winword.exe", "*\\excel.exe", "*\\powerpnt.exe", "*\\outlook.exe") process IN ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\mshta.exe", "*\\rundll32.exe", "*\\regsvr32.exe", "*\\certutil.exe") 
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S") 
| table event_time, host, user, parent_process, process, process_cmdline
```

## Tuning and false positives

- Legitimate add-ins and finance macros occasionally run `cmd.exe` or `wscript.exe` from Excel. Fingerprint them by the full `process_cmdline` and script path and allowlist those exact strings; do not allowlist the parent/child pair.
- Outlook spawning `rundll32.exe` for certain MAPI operations is seen on some builds; verify the command line references a Microsoft DLL in `System32`.
- Document-conversion servers that automate Office are a special case and should be scoped out of the macro.

## Response steps

1. Find the document: the parent command line names the file that was open; collect it and its email (Message-ID) before it is deleted.
2. Read the child command line; it typically downloads a stage with `certutil`, `bitsadmin` or encoded PowerShell (TDL-007).
3. Check Sysmon 3/22 for the child's network activity and TDL-017 for a threat-intel match.
4. Isolate the host, block the sender and attachment hash at the mail gateway, and search the mail store for other recipients.
5. Verify macro security settings for the user's group and whether the file came through a trusted location.

## Validation

Planted scenario `office_shell` in `scripts/generate_logs.py`: Excel spawns cmd.exe and a script host.

Result from `python -m harness.run_detections --only TDL-012` on `data/sample/` (2 rows):

```json
{
  "event_time": "2026-10-14 09:47:00",
  "host": "WS-HR-03",
  "user": "CORP\\onelson",
  "parent_process": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "process_cmdline": "powershell.exe -NoP -NonI -W Hidden -Enc bABhAGIALQBwAGwAYQBjAGUAaABvAGwAZABlAHIALQBlAG4AYwBvAGQAZQBkAC0AYwBvAG0AbQBhAG4AZAAtAHQAZQB4AHQALQBmAG8AcgAtAGQAZQB0AGUAYwB0AGkAbwBuAC0AdABlAHMAdABpAG4AZwA="
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-012]` and `::test_detection_is_quiet_on_benign_data[TDL-012]`.
