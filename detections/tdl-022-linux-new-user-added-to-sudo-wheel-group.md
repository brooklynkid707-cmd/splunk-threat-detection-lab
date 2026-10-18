# TDL-022 Linux New User Added To sudo/wheel Group

**Severity:** high (`alert.severity = 4`)  
**Schedule:** `*/15 * * * *` over `-24h` to `now`  
**Suppression:** `target_user` for 24h  
**ES label:** Linux New sudo User

## Description

A user account is created with useradd and the same account is added to the sudo, wheel or admin group within the search window. Mirrors the Windows new-admin detection for Linux hosts.

Reads `useradd` and `usermod` syslog lines, normalises the subject account into `target_user`, and counts creations and additions to `sudo`, `wheel` or `admin` per account. Both must be present for the alert, mirroring the Windows new-admin logic in TDL-004. Hosts and groups are listed for context.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Persistence | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account |
| Privilege Escalation / Defense Evasion | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Abuse Elevation Control Mechanism: Sudo and Sudo Caching |

NIST CSF: DE.CM-3

## Data source

- **Source:** Linux auth.log (sshd, sudo, useradd, usermod)
- **Macros:** `linux_auth`
- **Fields used:** `target_user`, `group`, `host`, `process`

## Search (SPL)

```spl
`linux_auth` (process=useradd OR process=usermod) 
| eval target_user=coalesce(new_user, mod_user) 
| stats count(eval(process="useradd")) as created, count(eval(in(group, "sudo", "wheel", "admin"))) as added_to_sudo, values(group) as groups, values(host) as hosts, min(_time) as first_seen by target_user 
| where created>0 AND added_to_sudo>0 
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S") 
| table first_seen, hosts, target_user, groups
```

## Tuning and false positives

- Configuration management (Ansible, Puppet, cloud-init) creates admin users on new hosts legitimately. Those runs happen at build time; correlate with host age or the automation account in the preceding `sudo` line and exclude.
- Container and CI hosts that create ephemeral users constantly should use a dedicated macro scope.
- The regexes in props.conf match the Debian/Ubuntu syslog format; RHEL logs `usermod` group changes slightly differently and may need an extra `EXTRACT-`.

## Response steps

1. Find the `sudo` line immediately before the `useradd` to learn which existing user performed the action and from which TTY/session.
2. Verify against change-control; if unplanned, lock the new account (`usermod -L`) and remove it from the group.
3. Check whether `target_user` has logged in yet (`Accepted` for that user) and from where.
4. Review the acting user's session for other persistence (cron, systemd units, SSH keys) and for how they obtained root.
5. Rotate credentials for the acting account if it is shared or a service account.

## Validation

Planted scenario `linux_sudo_user` in `scripts/generate_logs.py`: useradd followed by usermod into the sudo group.

Result from `python -m harness.run_detections --only TDL-022` on `data/sample/` (1 row):

```json
{
  "first_seen": "2026-10-14 06:03:01",
  "hosts": "srv-app-01",
  "target_user": "svcmon",
  "groups": "sudo"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-022]` and `::test_detection_is_quiet_on_benign_data[TDL-022]`.
