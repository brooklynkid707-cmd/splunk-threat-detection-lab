# TDL-010 DNS - Excessive Unique Subdomains For One Base Domain

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `*/10 * * * *` over `-30m` to `now`  
**Suppression:** `src_ip, base_domain` for 4h  
**ES label:** DNS Subdomain Cardinality

## Description

One client resolves 100 or more distinct subdomains of the same base domain inside ten minutes. High subdomain cardinality to a single zone is how DNS exfiltration and fast-flux C2 look even when individual names are short. CDNs and update services are allowlisted by macro.

Extracts the base domain from each query, buckets by ten minutes and counts distinct full query names per client and zone. One hundred or more unique subdomains in ten minutes is the cardinality signature of DNS exfiltration and fast-flux C2 even when each individual name is short. The `dns_subdomain_allowlist` macro removes CDN and update zones.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Exfiltration | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol |
| Command and Control | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS |

NIST CSF: DE.AE-1

## Data source

- **Source:** Resolver DNS query log
- **Macros:** `dns`, `dns_subdomain_allowlist`
- **Fields used:** `src_ip`, `query`, `base_domain`

## Search (SPL)

```spl
`dns` 
| rex field=query "(?<base_domain>[^.]+\.[^.]+)$" 
| bin _time span=10m 
| stats dc(query) as unique_subdomains, count as queries by src_ip, base_domain, _time 
| where unique_subdomains>=100 
| search NOT `dns_subdomain_allowlist` 
| eval window_start=strftime(_time, "%Y-%m-%d %H:%M") 
| table window_start, src_ip, base_domain, unique_subdomains, queries
```

## Tuning and false positives

- CDNs, telemetry collectors, ad networks and cloud storage front ends generate enormous subdomain cardinality. Maintain the `dns_subdomain_allowlist` macro from a week of `rare`/`top` analysis before enabling alerting.
- Browsers with DNS prefetching on media-heavy pages can hit 100 distinct names in ten minutes against one zone; the names will be human-readable (`img12`, `static-eu`) rather than random.
- Mail servers resolving many DKIM/SPF/DNSBL names should be excluded by `src_ip`.
- The two-label `base_domain` regex treats `co.uk` style suffixes as the base; use a public-suffix lookup if you operate in those TLDs.

## Response steps

1. Sample the queried names: random hex or Base32 means encoding; dictionary words mean a CDN or legitimate app.
2. Pivot to Sysmon 22 on the client to find the process, then to TDL-007/TDL-025 if it is a scripting host.
3. Compare the resolver's response codes; exfiltration zones often answer NXDOMAIN for every name.
4. Sinkhole or block the zone at the resolver and capture a full PCAP from the client if it is still active.
5. Add the zone to the threat-intel lookup so TDL-017 catches direct connections to the same infrastructure.

## Validation

Planted scenario `dns_subdomains` in `scripts/generate_logs.py`: 150 distinct subdomains of one zone in eight minutes.

Result from `python -m harness.run_detections --only TDL-010` on `data/sample/` (1 row):

```json
{
  "window_start": "2026-10-14 15:20",
  "src_ip": "10.20.4.57",
  "base_domain": "example.org",
  "unique_subdomains": 150,
  "queries": 150
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-010]` and `::test_detection_is_quiet_on_benign_data[TDL-010]`.
