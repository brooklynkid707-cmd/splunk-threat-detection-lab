# TDL-002 Windows Password Spraying - One Source, Many Accounts

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `*/10 * * * *` over `-30m` to `now`  
**Suppression:** `src_ip` for 1h  
**ES label:** Windows Password Spraying

## Description

A single source produces failed logons (4625) against 10 or more distinct accounts in a ten-minute window with a low failures-per-account ratio. Spraying tries one or two common passwords across many users to stay under lockout thresholds.

Groups 4625 events per source in ten-minute windows and compares the number of distinct accounts with the total failures. Ten or more accounts with at most three failures each is the low-and-slow pattern spraying tools produce to avoid lockouts.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Credential Access | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying |

NIST CSF: DE.CM-1

## Data source

- **Source:** Windows Security event log
- **Macros:** `wineventlog_security`
- **Fields used:** `src_ip`, `user`, `EventCode`

## Search (SPL)

```spl
`wineventlog_security` EventCode=4625 
| bin _time span=10m 
| stats dc(user) as unique_users, count as failures, values(user) as users by src_ip, _time 
| eval failures_per_user=round(failures/unique_users, 2) 
| where unique_users>=10 AND failures_per_user<=3 
| eval window_start=strftime(_time, "%Y-%m-%d %H:%M") 
| table window_start, src_ip, unique_users, failures, failures_per_user, users
```

## Tuning and false positives

- Single-sign-on gateways, Exchange/OWA front ends and Citrix StoreFront authenticate on behalf of many users and will look like one source hitting many accounts. Those sources should be enriched with a `known_auth_proxy` lookup and excluded, or the search should key on the client address they forward.
- Monday-morning password resets can produce one failure per user from a shared terminal server; the `failures_per_user<=3` filter does not help here. Check whether the targeted accounts are random or alphabetical (sprays often walk a list).
- A spray from outside normally hits a perimeter service (VPN, OWA). If the `dest` is a domain controller the source is already inside the network, which raises severity.

## Response steps

1. Enumerate the targeted `users` and check each for a subsequent 4624 from the same `src_ip`.
2. Identify the authentication path (VPN, OWA, RDP, SMB) from `Logon_Type` and `Workstation_Name` and block the source there.
3. Check whether any targeted account has MFA disabled or is a service account; those are the ones a successful spray will land on.
4. Review the account list against recent data exposures: sprays frequently use a leaked employee list.
5. Tighten the lockout and smart-lockout policies if the attacker stayed under them by design.

## Validation

Planted scenario `password_spray` in `scripts/generate_logs.py`: one failed logon each against 30 accounts from one IP in eight minutes.

Result from `python -m harness.run_detections --only TDL-002` on `data/sample/` (1 row):

```json
{
  "window_start": "2026-10-14 03:00",
  "src_ip": "198.51.100.23",
  "unique_users": 30,
  "failures": 30,
  "failures_per_user": 1.0,
  "users": [
    "chall",
    "cking",
    "cward",
    "hwright",
    "ibell",
    "... (25 more)"
  ]
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-002]` and `::test_detection_is_quiet_on_benign_data[TDL-002]`.
