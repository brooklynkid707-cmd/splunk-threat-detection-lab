# TDL-021 Linux SSH Success After Repeated Failures

**Severity:** critical (`alert.severity = 5`)  
**Schedule:** `*/10 * * * *` over `-1h` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** SSH Success After Failures

## Description

A source address accumulates five or more SSH failures within 30 minutes and then authenticates successfully. This is the "brute force that worked" case and is far more urgent than the failures alone.

Orders SSH failures and successes by source and time, then uses `streamstats time_window=30m` to count prior failures from the same source. A success preceded by five or more failures in the last 30 minutes is a brute force that worked, which is why severity is critical even though the counts are small.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing |
| Defense Evasion / Persistence / Privilege Escalation / Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts |

NIST CSF: DE.CM-1

## Data source

- **Source:** Linux auth.log (sshd, sudo, useradd, usermod)
- **Macros:** `linux_auth`
- **Fields used:** `src_ip`, `user`, `host`, `auth_method`, `prior_failures`

## Search (SPL)

```spl
`linux_auth` process=sshd (action=Failed OR action=Accepted) 
| sort 0 src_ip, _time 
| streamstats time_window=30m count(eval(action="Failed")) as prior_failures by src_ip 
| where action="Accepted" AND prior_failures>=5 
| eval event_time=strftime(_time, "%Y-%m-%d %H:%M:%S") 
| table event_time, host, src_ip, user, auth_method, prior_failures
```

## Tuning and false positives

- A user who mistypes their password several times and then gets it right is the obvious benign case. Five failures in 30 minutes is a lot for a human; three would be noisy. Look at whether the failures spanned several usernames (`invalid user`) before escalating.
- Automation that retries with multiple keys before the right one produces `Failed publickey` lines followed by `Accepted publickey`; exclude `auth_method=publickey` failures from the counter if this is common.
- The 30-minute window is per source address; a NAT gateway shared by many users will mix their failures together.

## Response steps

1. Treat the account as compromised: disable it or rotate its password and key immediately.
2. Review what the session did (`sudo` lines, shell history, `auditd`) from the `Accepted` timestamp onward.
3. Check for persistence on the host: new keys in `authorized_keys`, cron entries, new users (TDL-022).
4. Block `src_ip` and search for the same source attempting other hosts.
5. If the account had sudo rights, rebuild the host rather than clean it.

## Validation

Planted scenario `ssh_success_after_failures` in `scripts/generate_logs.py`: eight SSH failures followed by a password success.

Result from `python -m harness.run_detections --only TDL-021` on `data/sample/` (1 row):

```json
{
  "event_time": "2026-10-14 05:45:20",
  "host": "srv-web-01",
  "src_ip": "203.0.113.90",
  "user": "deploy",
  "auth_method": "password",
  "prior_failures": 8
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-021]` and `::test_detection_is_quiet_on_benign_data[TDL-021]`.
