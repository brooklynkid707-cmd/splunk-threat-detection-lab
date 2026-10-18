# TDL-015 Windows Event Log Cleared

**Severity:** critical (`alert.severity = 5`)  
**Schedule:** `*/5 * * * *` over `-15m` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** Event Log Cleared

## Description

The Security log was cleared (1102) or wevtutil / Clear-EventLog was executed. Attackers clear logs to remove evidence after an intrusion; there is almost no legitimate reason for this outside of planned maintenance.

Three evidence paths are combined: the 1102 audit-log-cleared event, Sysmon 1 for `wevtutil.exe cl`/`clear-log`, and PowerShell `Clear-EventLog`. Each row carries the host, user and the command line or a fixed description so the analyst sees which path fired.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Defense Evasion | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Indicator Removal: Clear Windows Event Logs |

NIST CSF: DE.CM-4

## Data source

- **Source:** Sysmon operational log; Windows Security event log
- **Macros:** `sysmon`, `wineventlog_security`
- **Fields used:** `EventCode`, `user`, `host`, `process_cmdline`

## Search (SPL)

```spl
(`wineventlog_security` EventCode=1102) OR (`sysmon` EventCode=1 process="*\\wevtutil.exe" (process_cmdline="* cl *" OR process_cmdline="* clear-log *")) OR (`sysmon` EventCode=1 process="*\\powershell.exe" process_cmdline="*Clear-EventLog*") 
| eval detail=coalesce(process_cmdline, "Security audit log cleared (EventCode 1102)"), event_time=strftime(_time, "%Y-%m-%d %H:%M:%S") 
| table event_time, host, user, EventCode, detail
```

## Tuning and false positives

- Log rotation scripts on servers with small log sizes sometimes clear logs on purpose; these run as a service account on a schedule and should be fixed by raising the log size, not by excluding the account.
- System imaging and sysprep clear logs at build time; scope out build VLANs or hosts younger than a day.
- An administrator clearing a log on a lab machine is legitimate but still worth a ticket; keep severity high and accept the occasional confirmed-benign close.

## Response steps

1. Pull everything from the host for the hour before the clear from other sources (Sysmon, forwarder copies, EDR) since the local log is gone.
2. Check whether the forwarder had shipped the events before the clear; if yes the evidence is in Splunk, if not note the gap.
3. Identify the `user` and how they got there (last 4624 for that account on the host).
4. Treat the host as compromised and preserve it; log clearing is rarely the first action an attacker takes.
5. Check for the same user clearing logs on other hosts and for other anti-forensic actions (`fsutil usn deletejournal`, `cipher /w`, shadow-copy deletion).

## Validation

Planted scenario `log_cleared` in `scripts/generate_logs.py`: wevtutil clears the Security log (1102 follows).

Result from `python -m harness.run_detections --only TDL-015` on `data/sample/` (2 rows):

```json
{
  "event_time": "2026-10-14 18:55:00",
  "host": "WS-FIN-07",
  "user": "CORP\\lwright",
  "EventCode": "1",
  "detail": "wevtutil.exe cl Security"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-015]` and `::test_detection_is_quiet_on_benign_data[TDL-015]`.
