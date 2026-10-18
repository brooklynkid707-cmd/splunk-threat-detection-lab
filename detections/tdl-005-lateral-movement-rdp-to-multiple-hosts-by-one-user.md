# TDL-005 Lateral Movement - RDP To Multiple Hosts By One User

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `*/15 * * * *` over `-2h` to `now`  
**Suppression:** `user` for 2h  
**ES label:** RDP Lateral Movement

## Description

One account completes RemoteInteractive (logon type 10) logons to four or more distinct hosts within an hour. Administrators usually RDP to one or two systems per hour; fanning out across many hosts is how an operator moves laterally with stolen credentials.

Counts distinct destination hosts per account for RemoteInteractive (type 10) logons in one-hour buckets. Four or more unique hosts in an hour is unusual for interactive administration and typical of an operator pivoting with stolen credentials.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Lateral Movement | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Services: Remote Desktop Protocol |

NIST CSF: DE.AE-1

## Data source

- **Source:** Windows Security event log
- **Macros:** `wineventlog_security`
- **Fields used:** `user`, `dest`, `src_ip`, `logon_type`

## Search (SPL)

```spl
`wineventlog_security` EventCode=4624 logon_type=10 
| bin _time span=1h 
| stats dc(dest) as unique_hosts, values(dest) as hosts, values(src_ip) as src_ips, count as logons by user, _time 
| where unique_hosts>=4 
| eval window_start=strftime(_time, "%Y-%m-%d %H:%M") 
| table window_start, user, unique_hosts, hosts, src_ips, logons
```

## Tuning and false positives

- Help-desk staff and patch administrators during a maintenance window will RDP to many hosts legitimately. Either allowlist named admin accounts during the change window or raise the threshold for members of a `tier1_admins` lookup.
- Jump hosts that proxy RDP make every session look like it comes from one `src_ip`; the `user` grouping still works but check that `src_ip` is the jump host and the real origin is logged there.
- Session-broker reconnects (RDS farms) can log several 4624 type 10 events for one logical session. Deduplicate by `dest` within a minute if this is common.

## Response steps

1. Identify where the chain started: the earliest `dest` in the window and the `src_ips` that reached it.
2. Verify with the account owner whether the sessions are theirs; if not, disable the account and kill the RDP sessions (`query session` / `logoff`).
3. On each `hosts` entry, collect process creation and file writes around the logon time to find tooling and staging directories.
4. Check the account's privilege level; a domain admin fanning out implies the attacker already has what they need and is positioning for impact.
5. Consider hunting for the same `src_ips` using other lateral channels: SMB (TDL-006), WinRM (5985/5986), WMI.

## Validation

Planted scenario `rdp_lateral` in `scripts/generate_logs.py`: one user RDPs to six servers in 25 minutes.

Result from `python -m harness.run_detections --only TDL-005` on `data/sample/` (1 row):

```json
{
  "window_start": "2026-10-14 11:00",
  "user": "mchen",
  "unique_hosts": 6,
  "hosts": [
    "DC-02",
    "FS-01",
    "SRV-APP-01",
    "SRV-BACKUP-01",
    "SRV-DB-01",
    "... (1 more)"
  ],
  "src_ips": "10.20.1.55",
  "logons": 6
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-005]` and `::test_detection_is_quiet_on_benign_data[TDL-005]`.
