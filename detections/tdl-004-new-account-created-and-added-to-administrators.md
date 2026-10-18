# TDL-004 New Account Created And Added To Administrators

**Severity:** critical (`alert.severity = 5`)  
**Schedule:** `*/15 * * * *` over `-24h` to `now`  
**Suppression:** `target_user` for 24h  
**ES label:** New Admin Account

## Description

An account is created (4720) and the same account is added to Administrators, Domain Admins or Enterprise Admins (4732) within the search window. Backdoor admin accounts are a classic persistence step after initial compromise.

Collects account creation (4720) and additions to Administrators, Domain Admins or Enterprise Admins (4732) in one search, normalises the subject of both into `target_user`, and alerts when the same account was both created and added within the window. Group membership changes to non-privileged groups are ignored.

## MITRE ATT&CK

| Tactic | Technique | Name |
|---|---|---|
| Persistence | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account |
| Persistence | [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation |

NIST CSF: DE.CM-3

## Data source

- **Source:** Windows Security event log
- **Macros:** `wineventlog_security`
- **Fields used:** `target_user`, `actor (Subject_Account_Name)`, `Group_Name`, `dest`

## Search (SPL)

```spl
`wineventlog_security` (EventCode=4720 OR (EventCode=4732 Group_Name IN ("Administrators", "Domain Admins", "Enterprise Admins"))) 
| eval target_user=coalesce(Target_Account_Name, Member_Name) 
| stats count(eval(EventCode=4720)) as created, count(eval(EventCode=4732)) as added_to_admin_group, values(Group_Name) as groups, values(Subject_Account_Name) as actor, min(_time) as first_seen, max(_time) as last_seen by target_user, dest 
| where created>0 AND added_to_admin_group>0 
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S") 
| table first_seen, last_seen, dest, actor, target_user, groups
```

## Tuning and false positives

- Legitimate onboarding of a new administrator will trigger this once. Treat it as a change-control check: the alert should match a ticket, and the `actor` should be a known IAM operator or provisioning service account.
- Identity-management platforms that create and group accounts in one transaction produce this constantly. Exclude the provisioning service account via a lookup rather than the group names.
- Lab-built domain controllers and test forests are noisy; scope the macro to production domain controllers.

## Response steps

1. Validate the change against change-control; if there is no ticket, disable `target_user` immediately and remove the group membership.
2. Investigate the `actor` account: how did it authenticate to `dest` before the change (4624 with `logon_type` and `src_ip`)?
3. Look for the same actor performing other persistence steps: scheduled tasks (TDL-008), services, GPO edits.
4. Check whether `target_user` has already logged on anywhere (4624 by `user`) and from where.
5. Rotate the actor's credentials if it is a service account; audit who holds rights to create accounts on `dest`.

## Validation

Planted scenario `new_admin` in `scripts/generate_logs.py`: account created and added to Administrators within a minute.

Result from `python -m harness.run_detections --only TDL-004` on `data/sample/` (1 row):

```json
{
  "first_seen": "2026-10-14 11:32:00",
  "last_seen": "2026-10-14 11:32:41",
  "dest": "DC-01",
  "actor": "svc_backup",
  "target_user": "backupadm",
  "groups": "Administrators"
}
```

Tests: `tests/test_detections.py::test_detection_fires_on_planted_scenario[TDL-004]` and `::test_detection_is_quiet_on_benign_data[TDL-004]`.
