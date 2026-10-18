# TDL-018 Data Exfiltration - Outbound Volume Spike Per Host

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `0 * * * *` over `-24h` to `now`  
**Suppression:** `src_ip` for 4h  
**ES label:** Exfiltration Volume Spike

## Description

A host sends more than 100 MB outbound in one hour and that hour exceeds the host's own mean plus three standard deviations across the search window. Per-host baselining avoids flagging servers that always push a lot of data while still catching a workstation that suddenly uploads gigabytes.

Sums outbound bytes per source host in one-hour buckets, then uses `eventstats` to compute each host's own mean and standard deviation across the search window. An hour must exceed both an absolute floor (100 MB) and the host's mean plus three standard deviations. `fillnull` handles hosts with a single bucket, which can therefore never exceed their own baseline.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Exfiltration | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol |
| Exfiltration | [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel |

NIST CSF: DE.AE-1

## Data source

- **Source:** Edge firewall connection log
- **Macros:** `bytes_to_mb`, `firewall`
- **Fields used:** `src_ip`, `bytes_out`, `dest_ip`, `unique_dests`

## Search (SPL)

```spl
`firewall` action=allow direction=outbound 
| bin _time span=1h 
| stats sum(bytes_out) as bytes_out, dc(dest_ip) as unique_dests, values(dest_ip) as dest_ips by src_ip, _time 
| eventstats avg(bytes_out) as baseline_avg, stdev(bytes_out) as baseline_stdev by src_ip 
| fillnull value=0 baseline_stdev 
| eval threshold=baseline_avg+3*baseline_stdev 
| where bytes_out>104857600 AND bytes_out>threshold 
| eval window_start=strftime(_time, "%Y-%m-%d %H:%M"), mb_out=`bytes_to_mb(bytes_out)`, baseline_mb=`bytes_to_mb(baseline_avg)` 
| table window_start, src_ip, mb_out, baseline_mb, unique_dests, dest_ips
```

## Tuning and false positives

- Backups, cloud sync clients (OneDrive, Dropbox) and video uploads are large and legitimate. Enrich `dest_ip` with a `sanctioned_cloud` lookup and lower severity when every destination is sanctioned.
- Servers that push large volumes constantly have a high baseline and will not trigger; that is by design, but it also means a compromised backup server can exfiltrate unnoticed. Pair this with TDL-017 and TDL-011.
- The 24-hour dispatch window is a short baseline; a host that was off for most of the day has few buckets and an unstable standard deviation. Use a summary index with 30 days of hourly totals for a production version.
- Because the search needs multiple buckets to baseline, it will not fire on a single-hour dataset; the test suite accounts for this.

## Response steps

1. Check `dest_ips`: one unknown destination receiving everything is exfiltration-shaped; many sanctioned destinations is a sync client.
2. Determine what was sent: file-server access logs, Sysmon 11 reads, browser history and the owning process (Sysmon 3 by `dest_ip`).
3. Correlate with staging indicators: large archives created in Temp or ProgramData shortly before the spike.
4. If unexplained, isolate the host and block the destination; preserve the archive for the data-impact assessment.
5. Engage the data owner and legal/privacy if regulated data may be involved; the byte count gives a first size estimate.

## Validation

Planted scenario `exfil_volume` in `scripts/generate_logs.py`: one host uploads ~520 MB in one hour.

Result from `python -m harness.run_detections --only TDL-018` on `data/sample/` (1 row):

```json
{
  "window_start": "2026-10-14 21:00",
  "src_ip": "10.20.2.57",
  "mb_out": 500.93,
  "baseline_mb": 22.87,
  "unique_dests": 1,
  "dest_ips": "203.0.113.37"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-018]` and `::test_detection_is_quiet_on_benign_data[TDL-018]`.
