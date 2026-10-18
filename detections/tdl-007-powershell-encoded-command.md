# TDL-007 PowerShell Encoded Command

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `*/5 * * * *` over `-15m` to `now`  
**Suppression:** none (every result is a notable)  
**ES label:** PowerShell Encoded Command

## Description

PowerShell launched with an -EncodedCommand style switch (any abbreviation from -e to -encodedcommand) followed by a Base64 blob of 40 or more characters, observed in either Windows 4688 or Sysmon 1. Encoding is used to hide the real script from command-line logging.

Takes process creation from both 4688 and Sysmon 1 (the `process_creation` macro), keeps PowerShell launches and uses `rex` to match any abbreviation of the encoded-command switch followed by a 40+ character Base64 blob. `dedup` collapses the duplicate 4688/Sysmon pair into one row per host, user and command line.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell |
| Defense Evasion | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) | Obfuscated Files or Information: Command Obfuscation |

NIST CSF: DE.CM-4

## Data source

- **Source:** Windows 4688 + Sysmon 1 process creation
- **Macros:** `process_creation`
- **Fields used:** `process_cmdline`, `parent_process`, `user`, `host`

## Search (SPL)

```spl
`process_creation` (process="*\\powershell.exe" OR process="*\\pwsh.exe") 
| rex field=process_cmdline "(?i)\s-(?<enc_flag>e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+(?<encoded_payload>[A-Za-z0-9+/=]{40,})" 
| where isnotnull(encoded_payload) 
| eval payload_length=len(encoded_payload), event_time=strftime(_time, "%Y-%m-%d %H:%M:%S") 
| dedup host, user, process_cmdline 
| table event_time, host, user, parent_process, process_cmdline, payload_length
```

## Tuning and false positives

- Some management tools (SCCM compliance scripts, certain RMM agents, Exchange setup) ship encoded commands. Decode the payload and allowlist by its hash or by the `parent_process`, never by the mere presence of `-enc`.
- Developers testing PowerShell remoting will occasionally produce these; the parent will be `powershell_ise.exe`, `code.exe` or a terminal rather than an Office application or `wscript.exe`.
- A blob of 40 characters is the floor; real malware payloads are usually thousands of characters. Consider adding `payload_length` to the severity logic.

## Response steps

1. Decode the payload (`[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(...))`) in an isolated environment and read it; it usually names the download URL or next stage.
2. Pivot on `parent_process`: an Office or browser parent means a phishing or drive-by chain (see TDL-012).
3. Check Sysmon 3 and 22 from the same process GUID for the network destination (TDL-025 covers DNS from PowerShell).
4. Isolate the host if the decoded script downloads or injects anything; collect PowerShell script block logs (4104) for the full picture.
5. Search the whole estate for the same encoded string; identical blobs on multiple hosts mean a campaign, not a one-off.

## Validation

Planted scenario `ps_encoded` in `scripts/generate_logs.py`: Word launches PowerShell with an -Enc Base64 payload.

Result from `python -m harness.run_detections --only TDL-007` on `data/sample/` (2 rows):

```json
{
  "event_time": "2026-10-14 09:47:00",
  "host": "WS-HR-03",
  "user": "onelson",
  "parent_process": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "process_cmdline": "powershell.exe -NoP -NonI -W Hidden -Enc bABhAGIALQBwAGwAYQBjAGUAaABvAGwAZABlAHIALQBlAG4AYwBvAGQAZQBkAC0AYwBvAG0AbQBhAG4AZAAtAHQAZQB4AHQALQBmAG8AcgAtAGQAZQB0AGUAYwB0AGkAbwBuAC0AdABlAHMAdABpAG4AZwA=",
  "payload_length": 156
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-007]` and `::test_detection_is_quiet_on_benign_data[TDL-007]`.
