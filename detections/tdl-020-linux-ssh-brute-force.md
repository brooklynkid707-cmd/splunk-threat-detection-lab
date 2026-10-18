# TDL-020 Linux SSH Brute Force

**Severity:** medium (`alert.severity = 3`)  
**Schedule:** `*/10 * * * *` over `-30m` to `now`  
**Suppression:** `src_ip, host` for 1h  
**ES label:** Linux SSH Brute Force

## Description

20 or more failed SSH authentications from one source address against one host inside ten minutes. Internet-facing SSH is constantly scanned, so the threshold is deliberately higher than the Windows equivalent and the alert groups by host.

Counts failed SSH authentications per source and host in ten-minute buckets and alerts at 20 or more. The threshold is higher than the Windows equivalent because internet-facing SSH is scanned constantly, and the grouping by host separates a broad scan from a focused attack on one system.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing |

NIST CSF: DE.CM-1

## Data source

- **Source:** Linux auth.log (sshd, sudo, useradd, usermod)
- **Macros:** `linux_auth`
- **Fields used:** `src_ip`, `host`, `user`, `auth_method`

## Search (SPL)

```spl
`linux_auth` process=sshd action=Failed 
| bin _time span=10m 
| stats count as failures, dc(user) as unique_users, values(user) as users by src_ip, host, _time 
| where failures>=20 
| eval window_start=strftime(_time, "%Y-%m-%d %H:%M") 
| table window_start, host, src_ip, failures, unique_users, users
```

## Tuning and false positives

- Internet background noise will trigger this on any public SSH endpoint several times per day. Move SSH behind a VPN or bastion with key-only auth, or raise the threshold for internet sources and keep 20 for internal ones.
- Monitoring systems with a rotated or expired key will fail repeatedly from one internal address; the `users` column will show one account and `auth_method=publickey`.
- Fail2ban-style blocking on the host stops the stream after a handful of attempts, so a 20-failure burst usually means the host is not protected.

## Response steps

1. Check for an `Accepted` from the same `src_ip` within the window or shortly after (TDL-021).
2. Review the `users` list: `root`, `admin` and distribution defaults mean a generic scan; your real usernames mean reconnaissance happened first.
3. Confirm password authentication is disabled on the host if it should be key-only; the alert is also a configuration finding.
4. Block the source at the edge or via the host firewall and add it to the lab threat feed if it is persistent.
5. If internal, the source host is compromised or running an unauthorised tool; pivot to its Sysmon or auditd data.

## Validation

Planted scenario `ssh_brute` in `scripts/generate_logs.py`: 40 SSH failures from one IP against the bastion.

Result from `python -m harness.run_detections --only TDL-020` on `data/sample/` (1 row):

```json
{
  "window_start": "2026-10-14 04:20",
  "host": "srv-bastion-01",
  "src_ip": "192.0.2.77",
  "failures": 40,
  "unique_users": 4,
  "users": [
    "admin",
    "deploy",
    "root",
    "ubuntu"
  ]
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-020]` and `::test_detection_is_quiet_on_benign_data[TDL-020]`.
