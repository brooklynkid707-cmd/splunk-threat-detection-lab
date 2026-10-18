# TDL-006 Lateral Movement - SMB Fan-Out From One Host

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `*/10 * * * *` over `-30m` to `now`  
**Suppression:** `src_ip` for 1h  
**ES label:** SMB Lateral Movement

## Description

A single host initiates outbound TCP 445 connections to five or more distinct internal hosts inside ten minutes (Sysmon 3). Workstations normally talk SMB to a couple of file servers and domain controllers; fan-out to many peers indicates PsExec style movement, share enumeration or worm behaviour.

Looks at Sysmon network connections initiated to TCP 445 and counts distinct destination addresses per source host in ten-minute buckets. Workstations normally reach a few file servers and domain controllers; five or more distinct peers in ten minutes is characteristic of share enumeration, PsExec-style execution or worm propagation.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Lateral Movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Remote Services: SMB/Windows Admin Shares |

NIST CSF: DE.AE-1

## Data source

- **Source:** Sysmon operational log
- **Macros:** `sysmon`
- **Fields used:** `src_ip`, `host`, `dest_ip`, `process`, `user`

## Search (SPL)

```spl
`sysmon` EventCode=3 Initiated=true dest_port=445 
| bin _time span=10m 
| stats dc(dest_ip) as unique_dests, values(dest_ip) as dests, values(process) as processes, values(user) as users by src_ip, host, _time 
| where unique_dests>=5 
| eval window_start=strftime(_time, "%Y-%m-%d %H:%M") 
| table window_start, host, src_ip, unique_dests, dests, processes, users
```

## Tuning and false positives

- Software deployment, vulnerability scanners and backup agents legitimately touch many hosts over SMB. Enrich with an `authorized_scanners` lookup keyed on `src_ip` or `process` (e.g. the SCCM client) and exclude in the macro layer.
- Administrators running `net view` or `Get-ADComputer | Test-Connection` from their workstation produce the same shape. The `processes` column tells you whether it was `explorer.exe` opening shares or a scripting host doing something automated.
- Printers and multi-function devices scanning to many shares can also appear; they usually have no Sysmon, so they will not alert here.

## Response steps

1. Check `processes` and `users`: an interactive user browsing shares differs from `cmd.exe`, `powershell.exe` or an unknown binary doing it.
2. Review the destination list for pattern (sequential addresses mean a scan; servers only means targeted movement).
3. On the source host collect process creation, named-pipe events (Sysmon 17/18) and service installs (7045) across the window.
4. Check the destinations for 4624 type 3 logons from `src_ip` and for new services or scheduled tasks created right after.
5. If PsExec-style movement is confirmed, treat the credentials used as compromised and rotate them.

## Validation

Planted scenario `smb_lateral` in `scripts/generate_logs.py`: one workstation opens SMB to 12 peers in four minutes.

Result from `python -m harness.run_detections --only TDL-006` on `data/sample/` (1 row):

```json
{
  "window_start": "2026-10-14 10:30",
  "host": "WS-FIN-07",
  "src_ip": "10.20.1.55",
  "unique_dests": 12,
  "dests": [
    "10.10.0.21",
    "10.10.0.31",
    "10.20.2.49",
    "10.20.2.50",
    "10.20.2.51",
    "... (7 more)"
  ],
  "processes": "C:\\Windows\\System32\\net.exe",
  "users": "CORP\\lwright"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-006]` and `::test_detection_is_quiet_on_benign_data[TDL-006]`.
