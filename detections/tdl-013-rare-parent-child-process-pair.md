# TDL-013 Rare Parent-Child Process Pair

**Severity:** low (`alert.severity = 2`)  
**Schedule:** `0 * * * *` over `-24h` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** Rare Parent Child Process

## Description

Statistically rare parent/child process combinations across the Sysmon 1 population (three or fewer occurrences). This is a hunting-grade detection: it surfaces oddities like mshta spawning rundll32 or wmiprvse spawning PowerShell, but will also show legitimate one-off admin activity, so expect to tune the allowlist macro.

Normalises parent and child image names to lower-case basenames, runs `rare` over the whole Sysmon 1 population, keeps pairs seen three or fewer times, and removes known-rare-but-expected combinations with the `rare_parent_child_allowlist` macro. It is a hunting detection with low severity by design.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Execution | [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter |
| Defense Evasion | [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution |

NIST CSF: DE.AE-1

## Data source

- **Source:** Sysmon operational log
- **Macros:** `rare_parent_child_allowlist`, `sysmon`
- **Fields used:** `parent_name`, `child_name`, `count`, `percent`

## Search (SPL)

```spl
`sysmon` EventCode=1 
| eval parent_name=lower(replace(parent_process, "^.*\\\\", "")), child_name=lower(replace(process, "^.*\\\\", "")) 
| rare limit=25 parent_name, child_name 
| where count<=3 
| search NOT `rare_parent_child_allowlist` 
| table parent_name, child_name, count, percent
```

## Tuning and false positives

- Everything an administrator does for the first time will appear here. The output is a review list, not an alert; feed it to a daily hunting dashboard and add confirmed-benign pairs to the allowlist macro weekly.
- The 24-hour window means a pair that runs once a day is permanently rare. Baseline over 30 days to find pairs that are rare per day but routine per month.
- Expect the planted scenarios in this repository to show up here as well: `winword.exe -> powershell.exe`, `mshta.exe -> rundll32.exe`, `cmd.exe -> wevtutil.exe`.

## Response steps

1. Sort the list by how suspicious the child is: script hosts, LOLBins, and anything in a user-writable path first.
2. For each pair pull the full events (`host`, `user`, `process_cmdline`) and decide benign or not; record the decision.
3. Promote any pair that indicates a real technique into its own high-fidelity detection (TDL-012 was born this way).
4. Add benign pairs to `rare_parent_child_allowlist` with a comment explaining why.
5. Track the size of the daily list; a sudden jump usually means a new software rollout or an intrusion.

## Validation

Planted scenario `rare_parent_child` in `scripts/generate_logs.py`: mshta.exe spawns rundll32.exe.

Result from `python -m harness.run_detections --only TDL-013` on `data/sample/` (7 rows):

```json
{
  "parent_name": "cmd.exe",
  "child_name": "runas.exe",
  "count": 1,
  "percent": 0.146628
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-013]` and `::test_detection_is_quiet_on_benign_data[TDL-013]`.
