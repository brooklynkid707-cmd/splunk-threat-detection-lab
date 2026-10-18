# TDL-016 Outbound Connection On Rare Destination Port

**Severity:** medium (`alert.severity = 3`)  
**Schedule:** `*/15 * * * *` over `-1h` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** Rare Outbound Port

## Description

Allowed outbound connections to a destination port that is not in the common-port macro and is used by five or fewer connections across the whole window. Reverse shells and C2 frameworks frequently use ports like 4444, 1337 or 50050 that nothing else in the environment touches. Enriched with the known_bad_ports lookup.

Starts from allowed outbound firewall events, removes the common ports defined in the `common_ports` macro, then uses `eventstats` to count connections and distinct sources per destination port across the window. Ports used by five or fewer connections are kept and aggregated per source; the `known_bad_ports` lookup adds a description for known listener defaults.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Command and Control | [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port |
| Command and Control | [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol |

NIST CSF: DE.AE-1

## Data source

- **Source:** Edge firewall connection log
- **Macros:** `common_ports`, `firewall`
- **Fields used:** `src_ip`, `dest_port`, `dest_ip`, `bytes_out`, `port_description (lookup)`

## Search (SPL)

```spl
`firewall` action=allow direction=outbound 
| search NOT `common_ports` 
| eventstats count as connections_on_port, dc(src_ip) as sources_using_port by dest_port 
| where connections_on_port<=5 
| stats count as connections, values(dest_ip) as dest_ips, sum(bytes_out) as bytes_out, min(_time) as first_seen by src_ip, dest_port, connections_on_port, sources_using_port 
| lookup known_bad_ports port AS dest_port OUTPUTNEW description AS port_description 
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S") 
| table first_seen, src_ip, dest_port, dest_ips, connections, sources_using_port, bytes_out, port_description
```

## Tuning and false positives

- Every new SaaS integration, game, or developer tool will show up on first use. Expect a steady trickle; use the `sources_using_port` column to prioritise single-host oddities over estate-wide rollouts.
- Passive-mode FTP, SIP/RTP and some VoIP clients negotiate random high ports. Exclude those `src_ip` ranges (phones, conferencing gateways) or add their port ranges to the macro.
- The `connections_on_port<=5` rule is relative to the window; on a quiet night everything is rare. Keep the one-hour window and compare against a weekly baseline before escalating.

## Response steps

1. Check `port_description`: a Metasploit, Cobalt Strike or Tor default is high priority regardless of volume.
2. Identify the owning process on the host with Sysmon 3 (`dest_port` and `dest_ip`).
3. Check the destination's reputation and whether it is in `known_bad_ips` (TDL-017).
4. Review `bytes_out`; a reverse shell is chatty but small, a tunnel or exfil channel is large.
5. If malicious, block the destination at the edge and add the port to the firewall's egress deny list if nothing legitimate needs it.

## Validation

Planted scenario `rare_port` in `scripts/generate_logs.py`: outbound connections on TCP 4444.

Result from `python -m harness.run_detections --only TDL-016` on `data/sample/` (1 row):

```json
{
  "first_seen": "2026-10-14 19:12:00",
  "src_ip": "10.20.4.50",
  "dest_port": "4444",
  "dest_ips": "203.0.113.88",
  "connections": 3,
  "sources_using_port": 1,
  "bytes_out": 10200,
  "port_description": "Metasploit default reverse shell listener"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-016]` and `::test_detection_is_quiet_on_benign_data[TDL-016]`.
