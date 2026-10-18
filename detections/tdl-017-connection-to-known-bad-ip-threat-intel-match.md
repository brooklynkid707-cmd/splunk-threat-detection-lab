# TDL-017 Connection To Known-Bad IP (Threat Intel Match)

**Severity:** critical (`alert.severity = 5`)  
**Schedule:** `*/5 * * * *` over `-15m` to `now`  
**Suppression:** `src_ip, dest_ip` for 4h  
**ES label:** Threat Intel IP Match

## Description

Any firewall event whose destination matches the known_bad_ips lookup (C2, exfil, malware distribution, phishing). Aggregated per source/destination so one alert summarises the whole conversation including bytes out and whether the firewall allowed or denied it.

Joins every firewall event to the `known_bad_ips` lookup on the destination address and keeps matches, then aggregates per source/destination so an analyst sees the whole conversation in one row: connection count, bytes out, ports, and whether the firewall allowed or denied it.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Command and Control | [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol |
| Command and Control | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer |

NIST CSF: DE.CM-1

## Data source

- **Source:** Edge firewall connection log
- **Macros:** `firewall`
- **Fields used:** `src_ip`, `dest_ip`, `threat_category`, `confidence`, `action`, `dest_port`, `bytes_out`

## Search (SPL)

```spl
`firewall` 
| lookup known_bad_ips ip AS dest_ip OUTPUT threat_category, threat_source, confidence 
| where isnotnull(threat_category) 
| stats count as connections, sum(bytes_out) as bytes_out, values(dest_port) as dest_ports, values(action) as actions, min(_time) as first_seen, max(_time) as last_seen by src_ip, dest_ip, threat_category, threat_source, confidence 
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S") 
| table first_seen, last_seen, src_ip, dest_ip, threat_category, confidence, actions, dest_ports, connections, bytes_out
```

## Tuning and false positives

- Stale indicators are the main problem: a C2 address becomes a legitimate cloud VM a week later. Keep `first_seen` in the lookup and age out entries older than 30 to 90 days depending on category.
- Shared hosting and CDN addresses on a feed will match legitimate browsing. Prefer feeds that provide ports or URLs and downgrade `confidence=low` matches to a dashboard instead of an alert.
- Security tools themselves (sandboxes, sinkhole checkers) talk to bad addresses deliberately; exclude the analysis subnet.
- Denied connections still fire; this is intentional (the host tried) but the severity can be reduced when `actions` contains only `deny`.

## Response steps

1. Read `actions`: `allow` with non-trivial `bytes_out` means the host talked to the infrastructure; `deny` only means it tried.
2. Isolate `src_ip` if the category is `c2` or `exfil` and traffic was allowed.
3. Find the process (Sysmon 3) and whether DNS resolution preceded it (Sysmon 22, TDL-025).
4. Review the indicator's `notes` and `threat_source`; pull the full report for the campaign and hunt for its other indicators.
5. Block the address at the edge and resolver, then search 30 days back for earlier contact from any host.

## Validation

Planted scenario `threat_intel_ip` in `scripts/generate_logs.py`: traffic to an address on the known-bad feed.

Result from `python -m harness.run_detections --only TDL-017` on `data/sample/` (2 rows):

```json
{
  "first_seen": "2026-10-14 01:05:59",
  "last_seen": "2026-10-14 01:45:00",
  "src_ip": "10.20.2.52",
  "dest_ip": "203.0.113.66",
  "threat_category": "c2",
  "confidence": "high",
  "actions": "allow",
  "dest_ports": "443",
  "connections": 40,
  "bytes_out": 12156
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-017]` and `::test_detection_is_quiet_on_benign_data[TDL-017]`.
