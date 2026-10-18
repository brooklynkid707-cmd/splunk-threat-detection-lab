# TDL-019 Privilege Escalation Attempt Via runas To Admin Account

**Severity:** medium (`alert.severity = 3`)  
**Schedule:** `*/15 * * * *` over `-30m` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** runas Privilege Escalation

## Description

runas.exe launched with /user: pointing at an administrator or root style account. Interactive users elevating to a different privileged account from a workstation is unusual and often follows credential theft.

Keeps Sysmon 1 for `runas.exe`, extracts the `/user:` argument with `rex` into `target_account`, and alerts when the target contains `admin`, is `administrator`, or contains `root`. The requesting user, command line and parent are returned.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Defense Evasion / Persistence / Privilege Escalation / Initial Access | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Valid Accounts: Domain Accounts |
| Privilege Escalation / Defense Evasion | [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism |

NIST CSF: DE.CM-3

## Data source

- **Source:** Sysmon operational log
- **Macros:** `sysmon`
- **Fields used:** `target_account`, `user`, `process_cmdline`, `parent_process`, `host`

## Search (SPL)

```spl
`sysmon` EventCode=1 process="*\\runas.exe" 
| rex field=process_cmdline "(?i)/user:(?<target_account>\S+)" 
| search target_account IN ("*admin*", "*\\administrator", "administrator", "*root*") 
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S") 
| table event_time, host, user, target_account, process_cmdline, parent_process
```

## Tuning and false positives

- Administrators who follow least privilege use `runas` to elevate from their daily account to their admin account, which is exactly this pattern. Allowlist pairs where `user` is `jsmith` and `target_account` is `jsmith-adm` using a naming-convention regex.
- Help-desk tools that wrap `runas` for installs will show the tool as the parent; allowlist the parent image by full path.
- The account-name match is loose on purpose (`*admin*` catches `sqladmin`, `vmadmin`); tune the list to your naming standard.

## Response steps

1. Confirm the `user` is entitled to the `target_account`; mismatched people or a service account targeting Administrator is the priority case.
2. Check whether the elevation succeeded: a 4624 with `logon_type=2` or `9` for `target_account` on `host` right after.
3. Review what the elevated process did (child processes of the `runas` target via Sysmon 1 parent GUID).
4. If the credential should not be known to the user, treat the admin password as compromised and rotate it.
5. Review how the user learned the password; shared admin passwords in scripts or wikis are a common root cause.

## Validation

Planted scenario `runas_admin` in `scripts/generate_logs.py`: runas /user:CORP\administrator from a workstation.

Result from `python -m harness.run_detections --only TDL-019` on `data/sample/` (1 row):

```json
{
  "event_time": "2026-10-14 12:48:00",
  "host": "WS-FIN-07",
  "user": "CORP\\lwright",
  "target_account": "CORP\\administrator",
  "process_cmdline": "runas.exe /user:CORP\\administrator \"cmd.exe /k whoami\"",
  "parent_process": "C:\\Windows\\System32\\cmd.exe"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-019]` and `::test_detection_is_quiet_on_benign_data[TDL-019]`.
