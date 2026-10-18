# TDL-008 Scheduled Task Created By Interactive User

**Severity:** medium (`alert.severity = 3`)  
**Schedule:** `*/15 * * * *` over `-30m` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** Scheduled Task Created

## Description

A scheduled task is created either through the Security log (4698) or by schtasks.exe /create seen in Sysmon. Tasks created by computer accounts or under the \Microsoft\Windows\ tree are excluded because Windows and its updaters create those constantly.

Unions two evidence sources: Windows 4698 (task created) and Sysmon 1 for `schtasks.exe /create`. Tasks created by computer accounts (`user=*$`) and under the `\Microsoft\Windows\` tree are excluded because the OS and its updaters create those continuously.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Execution / Persistence / Privilege Escalation | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task |

NIST CSF: DE.CM-7

## Data source

- **Source:** Sysmon operational log; Windows Security event log
- **Macros:** `sysmon`, `wineventlog_security`
- **Fields used:** `Task_Name / process_cmdline`, `user`, `host`, `parent_process`

## Search (SPL)

```spl
(`wineventlog_security` EventCode=4698) OR (`sysmon` EventCode=1 process="*\\schtasks.exe" process_cmdline="*/create*") 
| eval task=coalesce(Task_Name, process_cmdline) 
| search NOT user="*$" NOT Task_Name="\\Microsoft\\Windows\\*" 
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S") 
| table event_time, host, user, EventCode, task, parent_process
```

## Tuning and false positives

- Software installers register their own updater tasks (browsers, Office, Adobe). These have an `msiexec.exe` or setup parent and a vendor-named path; add them to an allowlist lookup keyed on task name prefix.
- Endpoint management agents that create tasks on behalf of users will show the agent service as `user` if it runs as SYSTEM but the computer account exclusion only covers `*$`; add the agent account explicitly.
- Administrators creating ad-hoc tasks for maintenance are expected on servers; consider lowering severity for members of an admin lookup while keeping workstations at medium.

## Response steps

1. Read the task action: the `/tr` argument or `Task_Command` names the executable; locate and hash it.
2. Check the task trigger (`/sc minute`, at logon, on idle) for signs it was designed for persistence rather than a one-off job.
3. Check the executable's path; anything in `Users\Public`, `ProgramData`, `AppData` or `Temp` is suspicious (TDL-023 and TDL-024 cover similar paths).
4. Remove the task and the binary only after collecting them; capture the task XML from `C:\Windows\System32\Tasks`.
5. Look for the parent chain that created it: a task created by `cmd.exe` spawned from an Office document ties back to TDL-012.

## Validation

Planted scenario `schtask` in `scripts/generate_logs.py`: interactive user creates a scheduled task outside the Microsoft tree.

Result from `python -m harness.run_detections --only TDL-008` on `data/sample/` (2 rows):

```json
{
  "event_time": "2026-10-14 12:14:00",
  "host": "WS-FIN-07",
  "user": "CORP\\lwright",
  "EventCode": "1",
  "task": "schtasks.exe /create /sc minute /mo 15 /tn \"OneDriveSync\" /tr \"C:\\Users\\Public\\sync.exe\" /f",
  "parent_process": "C:\\Windows\\System32\\cmd.exe"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-008]` and `::test_detection_is_quiet_on_benign_data[TDL-008]`.
