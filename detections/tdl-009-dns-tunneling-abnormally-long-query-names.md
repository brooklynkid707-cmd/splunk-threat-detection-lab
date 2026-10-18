# TDL-009 DNS Tunneling - Abnormally Long Query Names

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `*/15 * * * *` over `-1h` to `now`  
**Suppression:** `src_ip, base_domain` for 4h  
**ES label:** DNS Tunneling Long Queries

## Description

Ten or more DNS queries of 50+ characters from one client to the same base domain. DNS tunnels (iodine, dnscat2, Cobalt Strike DNS beacons) encode data into long subdomain labels; ordinary hostnames are far shorter.

Computes the length of every DNS query name, keeps those of 50 or more characters, extracts the registered domain with `rex` and counts long queries per client and base domain. Ten or more long queries to one zone triggers; `avg_length`, `max_length` and sample names are returned for triage.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Command and Control | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS |
| Exfiltration | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol |

NIST CSF: DE.AE-1

## Data source

- **Source:** Resolver DNS query log
- **Macros:** `dns`
- **Fields used:** `src_ip`, `query`, `base_domain`, `query_length`

## Search (SPL)

```spl
`dns` 
| eval query_length=len(query) 
| where query_length>=50 
| rex field=query "(?<base_domain>[^.]+\.[^.]+)$" 
| stats count as long_queries, avg(query_length) as avg_length, max(query_length) as max_length, dc(query) as unique_queries, values(query) as sample_queries by src_ip, base_domain 
| where long_queries>=10 
| eval avg_length=round(avg_length, 1) 
| table src_ip, base_domain, long_queries, unique_queries, avg_length, max_length, sample_queries
```

## Tuning and false positives

- Anti-virus and reputation services (hash lookups), certificate transparency, some CDNs and cloud load balancers legitimately use long encoded labels. Build an allowlist of those base domains and apply it with the same macro mechanism TDL-010 uses.
- IPv6 reverse lookups (`ip6.arpa`) are always long; exclude `record_type=PTR` or `*.arpa` if they appear in your resolver logs.
- Kerberos, SRV and DKIM lookups can exceed 50 characters but will not reach ten per base domain per client unless something is wrong.
- TXT and NULL record types are a strong corroborating signal: most tunnels use them. Add `record_type` to the `stats` if your resolver logs it.

## Response steps

1. Inspect `sample_queries`: tunnels show high-entropy labels that never repeat; a CDN shows structured, repeating prefixes.
2. Identify the process on `src_ip` that generated the queries using Sysmon 22 (`query` matches the names) and TDL-025.
3. Check the resolver's answers for the zone: tunnels often return NXDOMAIN or tiny TXT replies at a constant rate.
4. Block the `base_domain` at the resolver and record the authoritative name servers; they are the attacker infrastructure.
5. Estimate volume (sum of `query_length` over the period) to inform the data-exfiltration assessment.

## Validation

Planted scenario `dns_tunnel` in `scripts/generate_logs.py`: 40 very long TXT queries to one base domain.

Result from `python -m harness.run_detections --only TDL-009` on `data/sample/` (1 row):

```json
{
  "src_ip": "10.20.4.53",
  "base_domain": "example.net",
  "long_queries": 40,
  "unique_queries": 40,
  "avg_length": 68.0,
  "max_length": 68,
  "sample_queries": [
    "02ojb6n3m46oznvtgsnftpna21tj1iulii1nvmbgl4ukw84uo7k3.tun.example.net",
    "0v1k7hg7u6psxovf49dz1tekbasnog7movu802on4wq6ku0x8lk4.tun.example.net",
    "0x3ia3n50btj6inqzfwfgsq1rdw1vhg8ri5wpwpjmsgui70lj5i0.tun.example.net",
    "1bjs45lfpf7csb3hozc0frmjh6ecb3h86mhotc4jtxg2croodaxb.tun.example.net",
    "1yc7hbsnbjx9z9v1qz419aqu1lm2y41iw4wkousbcenq3uezij4f.tun.example.net",
    "... (35 more)"
  ]
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-009]` and `::test_detection_is_quiet_on_benign_data[TDL-009]`.
