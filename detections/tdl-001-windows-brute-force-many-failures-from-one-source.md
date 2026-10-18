# TDL-001 Windows Brute Force - Many Failures From One Source

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `*/5 * * * *` over `-15m` to `now`  
**Suppression:** `src_ip` for 1h  
**ES label:** Windows Brute Force

## Description

10 or more Windows logon failures (4625) from a single source address against three or fewer accounts inside five minutes. Few accounts and many attempts is the signature of brute force rather than spraying.

Buckets 4625 events into five-minute windows per source address and counts failures and distinct target accounts. Ten or more failures against three or fewer accounts is treated as brute force; the `unique_users<=3` clause separates it from spraying (TDL-002), which hits many accounts a few times each.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing |

NIST CSF: DE.CM-1

## Data source

- **Source:** Windows Security event log
- **Macros:** `wineventlog_security`
- **Fields used:** `src_ip`, `user`, `dest`, `EventCode`, `Status / Sub_Status`

## Search (SPL)

```spl
`wineventlog_security` EventCode=4625 
| bin _time span=5m 
| stats count as failures, dc(user) as unique_users, values(user) as users, values(dest) as targets by src_ip, _time 
| where failures>=10 AND unique_users<=3 
| eval window_start=strftime(_time, "%Y-%m-%d %H:%M") 
| table window_start, src_ip, failures, unique_users, users, targets
```

## Tuning and false positives

- Service accounts with an expired password cached by a scheduled task or an application pool will fail every few seconds from one server. Fix the credential rather than suppressing; if you must, exclude the host:account pair with a lookup.
- VPN concentrators and load balancers can present one source address for many real clients. If `src_ip` is a NAT address, raise the threshold for that address or key on `Workstation_Name` instead.
- Vulnerability scanners performing credentialed checks produce bursts of 4625 with `Sub_Status=0xC000006A` right after a password rotation. Exclude the scanner subnet in the macro layer, not in the search.
- The default threshold (10 in 5 minutes) is tuned for the lab; in a 20k-user estate start at 25 and review the `failures` distribution for a week before lowering.

## Response steps

1. Pivot on `src_ip`: is it internal (compromised host or misconfigured service) or external (exposed RDP/SMB, VPN portal)?
2. Check for a 4624 from the same `src_ip` for any of the targeted `users` after the burst (TDL-021 covers the equivalent on Linux); a success converts this to an incident.
3. If external, block the address at the edge and confirm whether the targeted service should be internet-facing at all.
4. If internal, isolate the host, collect process creation around the window and look for the credential tool that generated the attempts.
5. Reset the targeted account(s) if any success is found; otherwise force a reset only if the account is privileged.

## Validation

Planted scenario `win_brute_force` in `scripts/generate_logs.py`: 60 failed logons against one account from one external IP in three minutes.

Result from `python -m harness.run_detections --only TDL-001` on `data/sample/` (1 row):

```json
{
  "window_start": "2026-10-14 02:10",
  "src_ip": "203.0.113.45",
  "failures": 60,
  "unique_users": 1,
  "users": "svc_backup",
  "targets": "DC-01"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-001]` and `::test_detection_is_quiet_on_benign_data[TDL-001]`.
