# TDL-014 LSASS Memory Access By Non-Allowlisted Process

**Severity:** critical (`alert.severity = 5`)  
**Schedule:** `*/5 * * * *` over `-15m` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** LSASS Access

## Description

Sysmon ProcessAccess (10) where a process not on the allowlist opens lsass.exe with an access mask associated with credential dumping (0x1010, 0x1410, 0x1438, 0x143A, 0x1F0FFF, 0x1F1FFF, 0x1F3FFF, 0x1FFFFF). Mimikatz, procdump and comsvcs.dll MiniDump all produce these masks.

Filters Sysmon 10 for handles opened to `lsass.exe`, removes sources on the `lsass_access_allowlist` macro and keeps the access masks that credential-dumping tools request. Results are aggregated per host, user and source image with the call trace preserved for analysts.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Credential Access | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory |

NIST CSF: DE.CM-4

## Data source

- **Source:** Sysmon operational log
- **Macros:** `lsass_access_allowlist`, `sysmon`
- **Fields used:** `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`, `host`, `user`

## Search (SPL)

```spl
`sysmon` EventCode=10 TargetImage="*\\lsass.exe" 
| search NOT `lsass_access_allowlist` 
| search GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143A", "0x1F0FFF", "0x1F1FFF", "0x1F3FFF", "0x1FFFFF") 
| stats count as access_attempts, values(GrantedAccess) as access_masks, values(CallTrace) as call_traces, min(_time) as first_seen by host, user, SourceImage, TargetImage 
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S") 
| table first_seen, host, user, SourceImage, access_masks, access_attempts, call_traces
```

## Tuning and false positives

- EDR and anti-virus engines open LSASS with full access constantly; keep them in the allowlist macro by full path and verify the binary is signed before trusting the path.
- Windows Error Reporting (`WerFault.exe`) and `taskmgr.exe` will request `0x1FFFFF` when a user creates a dump; the former is often genuine, the latter should be investigated.
- Mask `0x1010` (PROCESS_VM_READ|PROCESS_QUERY_LIMITED_INFORMATION) is the most common for dumpers but also for some inventory tools; the `CallTrace` ending in an unknown DLL or `UNKNOWN` is the stronger signal.
- Older Sysmon configs drop event 10 for performance; make sure it is enabled for `lsass.exe` as the target.

## Response steps

1. Treat any non-allowlisted `SourceImage` with these masks as credential theft until proven otherwise; isolate the host.
2. Collect the source binary and its parent chain; look for a `.dmp` file written shortly after (Sysmon 11 in TDL-024 style paths).
3. Assume every credential cached on that host is compromised: list recent interactive and service logons on it and reset those accounts, privileged ones first.
4. Check for lateral movement from the host after the access time (TDL-005, TDL-006).
5. Enable LSA protection (RunAsPPL) and Credential Guard where possible to make the technique fail next time.

## Validation

Planted scenario `lsass_access` in `scripts/generate_logs.py`: unknown binary opens lsass.exe with dump-capable access masks.

Result from `python -m harness.run_detections --only TDL-014` on `data/sample/` (1 row):

```json
{
  "first_seen": "2026-10-14 17:08:00",
  "host": "WS-FIN-07",
  "user": "CORP\\lwright",
  "SourceImage": "C:\\Windows\\Temp\\pd.exe",
  "access_masks": [
    "0x1010",
    "0x1438",
    "0x1FFFFF"
  ],
  "access_attempts": 3,
  "call_traces": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4a4|C:\\Windows\\System32\\KERNELBASE.dll+2c3fe|C:\\Windows\\Temp\\pd.exe+1a2b"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-014]` and `::test_detection_is_quiet_on_benign_data[TDL-014]`.
