# TDL-011 Beaconing - Regular Interval Outbound Connections

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `0 * * * *` over `-4h` to `now`  
**Suppression:** `src_ip, dest_ip` for 12h  
**ES label:** Beaconing

## Description

A source/destination pair with 20 or more outbound connections whose inter-arrival times are nearly constant (coefficient of variation below 0.2, mean interval at least 30 seconds). Human and application traffic is bursty; C2 implants check in on a timer.

For every source/destination pair, orders outbound allowed connections by time and uses `streamstats` to compute the gap to the previous connection. The mean and standard deviation of those gaps give a jitter ratio; twenty or more connections with a mean gap of at least 30 seconds and a ratio below 0.2 indicates a timer-driven implant. The destination is enriched from `known_bad_ips` but a match is not required.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Command and Control | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols |
| Command and Control | [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port |

NIST CSF: DE.AE-1

## Data source

- **Source:** Edge firewall connection log
- **Macros:** `firewall`
- **Fields used:** `src_ip`, `dest_ip`, `dest_port`, `bytes_out`

## Search (SPL)

```spl
`firewall` action=allow direction=outbound 
| sort 0 src_ip, dest_ip, _time 
| streamstats current=f last(_time) as prev_time by src_ip, dest_ip 
| eval delta=_time-prev_time 
| where isnotnull(delta) 
| stats count as connections, avg(delta) as avg_interval, stdev(delta) as stdev_interval, values(dest_port) as dest_ports, min(_time) as first_seen, max(_time) as last_seen by src_ip, dest_ip 
| eval jitter_ratio=round(stdev_interval/avg_interval, 3), avg_interval=round(avg_interval, 1) 
| where connections>=20 AND avg_interval>=30 AND jitter_ratio<0.2 
| lookup known_bad_ips ip AS dest_ip OUTPUTNEW threat_category 
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S") 
| table src_ip, dest_ip, dest_ports, connections, avg_interval, jitter_ratio, first_seen, last_seen, threat_category
```

## Tuning and false positives

- NTP, monitoring agents, mail polling, software update checks and VPN keepalives are legitimately periodic. Build a `periodic_services` allowlist keyed on `dest_ip` and `dest_port` from the first week of results.
- The 0.2 jitter ceiling is deliberately tight; Cobalt Strike with 50 percent jitter will evade it. Loosen to 0.5 only after allowlisting known periodic services, or add a second detection keyed on byte-size constancy.
- Hosts behind a NAT will be aggregated under one `src_ip`; if your firewall logs the internal address after translation, make sure `src_ip` is that address.
- Low connection counts over long windows (one beacon per hour) will not reach 20 inside the four-hour dispatch window; a daily version of this search with `connections>=12` covers slow beacons.

## Response steps

1. Treat a `threat_category` match as confirmed C2 and isolate `src_ip`.
2. Without a match, check the destination's reputation, ASN, certificate and age of the domain that resolved to it.
3. On the host find the process owning the connections (Sysmon 3 by `dest_ip`) and its parent chain.
4. Capture the beacon traffic for the IR team; the user agent, URI pattern and sizes identify the framework.
5. Hunt for the same `dest_ip` and `avg_interval` across all hosts; implants are rarely deployed to one machine.

## Validation

Planted scenario `beacon` in `scripts/generate_logs.py`: 40 outbound connections on a 60-second timer to a listed C2 address.

Result from `python -m harness.run_detections --only TDL-011` on `data/sample/` (1 row):

```json
{
  "src_ip": "10.20.2.52",
  "dest_ip": "203.0.113.66",
  "dest_ports": "443",
  "connections": 39,
  "avg_interval": 60.0,
  "jitter_ratio": 0.022,
  "first_seen": "2026-10-14 01:06:58",
  "last_seen": "2026-10-14 01:45:00",
  "threat_category": "c2"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-011]` and `::test_detection_is_quiet_on_benign_data[TDL-011]`.
