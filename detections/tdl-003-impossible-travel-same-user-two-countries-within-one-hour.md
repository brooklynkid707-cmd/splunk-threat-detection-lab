# TDL-003 Impossible Travel - Same User, Two Countries Within One Hour

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `*/15 * * * *` over `-2h` to `now`  
**Suppression:** `user` for 4h  
**ES label:** Impossible Travel

## Description

Successful network or RDP logons (4624) for the same account from public source addresses that geolocate to two different countries less than an hour apart. Uses the ip_geo CIDR lookup; internal ranges are ignored.

Keeps successful network and RDP logons from public addresses, geolocates the source through the `ip_geo` CIDR lookup, orders by user and time, and uses `streamstats` to carry forward the previous country for each user. A country change inside 3600 seconds raises the alert. Internal ranges resolve to `internal` and are dropped so VPN-to-LAN transitions do not trigger it.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Defense Evasion / Persistence / Privilege Escalation / Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts |
| Defense Evasion / Persistence / Privilege Escalation / Initial Access | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts |

NIST CSF: DE.AE-2

## Data source

- **Source:** Windows Security event log
- **Macros:** `wineventlog_security`
- **Fields used:** `user`, `src_ip`, `dest`, `logon_type`, `country (lookup)`

## Search (SPL)

```spl
`wineventlog_security` EventCode=4624 logon_type IN (3, 10) src_ip=* 
| lookup ip_geo ip AS src_ip OUTPUT country 
| where isnotnull(country) AND country!="internal" 
| sort 0 user, _time 
| streamstats current=f last(country) as prev_country, last(src_ip) as prev_src_ip, last(_time) as prev_time by user 
| where isnotnull(prev_country) AND country!=prev_country AND (_time-prev_time)<=3600 
| eval minutes_between=round((_time-prev_time)/60, 1), logon_time=strftime(_time, "%Y-%m-%d %H:%M:%S") 
| table logon_time, user, prev_src_ip, prev_country, src_ip, country, minutes_between, dest
```

## Tuning and false positives

- Mobile carriers and corporate proxies that egress from a different country than the user sits in are the main source of noise. Add those egress ranges to `ip_geo.csv` with the country the users actually live in.
- Travelling staff who connect from an airport then from the aircraft Wi-Fi really do move countries in under an hour. Correlate with HR travel data or ask the user before escalating.
- The lab `ip_geo.csv` is tiny; in production swap it for a MaxMind-style CIDR table, keep `match_type = CIDR(ip)`, and consider adding a `distance_km` column to express the rule as speed rather than country change.
- Shared or generic accounts legitimately used from multiple countries at once should be eliminated, not allowlisted.

## Response steps

1. Confirm both logons with the user through an out-of-band channel; do not rely on email if the mailbox may be compromised.
2. Compare the `prev_src_ip` and `src_ip` reputation and ASN; a residential ISP followed by a hosting provider is a strong sign of a stolen session or password.
3. Revoke active sessions and VPN tokens for the account, then reset the password and re-enrol MFA if either logon is unexplained.
4. Search for what the second session did: process creation on `dest`, file-share access and mailbox rules.
5. If the account has privileged group membership, treat as a potential domain compromise and widen scope.

## Validation

Planted scenario `impossible_travel` in `scripts/generate_logs.py`: VPN logons for the same user from the US and Brazil 15 minutes apart.

Result from `python -m harness.run_detections --only TDL-003` on `data/sample/` (2 rows):

```json
{
  "logon_time": "2026-10-14 10:25:00",
  "user": "mchen",
  "prev_src_ip": "203.0.113.77",
  "prev_country": "US",
  "src_ip": "192.0.2.55",
  "country": "BR",
  "minutes_between": 15.0,
  "dest": "SRV-VPN-01"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-003]` and `::test_detection_is_quiet_on_benign_data[TDL-003]`.
