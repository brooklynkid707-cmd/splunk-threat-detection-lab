# Detection catalogue

One page per scheduled search in `TA-threat-detection/default/savedsearches.conf`. Pages are kept in sync with the conf
file: the SPL, ATT&CK IDs, severity and schedule quoted here are read from it. See `docs/ATTACK-COVERAGE.md` for the matrix
and `docs/TUNING.md` for the threshold philosophy.

| ID | Detection | Severity | ATT&CK | Data source | Planted scenario |
|---|---|---|---|---|---|
| [TDL-001](tdl-001-windows-brute-force-many-failures-from-one-source.md) | Windows Brute Force - Many Failures From One Source | high | T1110.001 | Windows Security event log | 60 failed logons against one account from one external IP in three minutes |
| [TDL-002](tdl-002-windows-password-spraying-one-source-many-accounts.md) | Windows Password Spraying - One Source, Many Accounts | high | T1110.003 | Windows Security event log | one failed logon each against 30 accounts from one IP in eight minutes |
| [TDL-003](tdl-003-impossible-travel-same-user-two-countries-within-one-hour.md) | Impossible Travel - Same User, Two Countries Within One Hour | high | T1078, T1078.004 | Windows Security event log | VPN logons for the same user from the US and Brazil 15 minutes apart |
| [TDL-004](tdl-004-new-account-created-and-added-to-administrators.md) | New Account Created And Added To Administrators | critical | T1136.001, T1098 | Windows Security event log | account created and added to Administrators within a minute |
| [TDL-005](tdl-005-lateral-movement-rdp-to-multiple-hosts-by-one-user.md) | Lateral Movement - RDP To Multiple Hosts By One User | high | T1021.001 | Windows Security event log | one user RDPs to six servers in 25 minutes |
| [TDL-006](tdl-006-lateral-movement-smb-fan-out-from-one-host.md) | Lateral Movement - SMB Fan-Out From One Host | high | T1021.002 | Sysmon operational log | one workstation opens SMB to 12 peers in four minutes |
| [TDL-007](tdl-007-powershell-encoded-command.md) | PowerShell Encoded Command | high | T1059.001, T1027.010 | Windows 4688 + Sysmon 1 process creation | Word launches PowerShell with an -Enc Base64 payload |
| [TDL-008](tdl-008-scheduled-task-created-by-interactive-user.md) | Scheduled Task Created By Interactive User | medium | T1053.005 | Sysmon operational log; Windows Security event log | interactive user creates a scheduled task outside the Microsoft tree |
| [TDL-009](tdl-009-dns-tunneling-abnormally-long-query-names.md) | DNS Tunneling - Abnormally Long Query Names | high | T1071.004, T1048.003 | Resolver DNS query log | 40 very long TXT queries to one base domain |
| [TDL-010](tdl-010-dns-excessive-unique-subdomains-for-one-base-domain.md) | DNS - Excessive Unique Subdomains For One Base Domain | high | T1048.003, T1071.004 | Resolver DNS query log | 150 distinct subdomains of one zone in eight minutes |
| [TDL-011](tdl-011-beaconing-regular-interval-outbound-connections.md) | Beaconing - Regular Interval Outbound Connections | high | T1071.001, T1571 | Edge firewall connection log | 40 outbound connections on a 60-second timer to a listed C2 address |
| [TDL-012](tdl-012-office-application-spawning-shell-or-script-host.md) | Office Application Spawning Shell Or Script Host | critical | T1566.001, T1204.002 | Sysmon operational log | Excel spawns cmd.exe and a script host |
| [TDL-013](tdl-013-rare-parent-child-process-pair.md) | Rare Parent-Child Process Pair | low | T1059, T1218 | Sysmon operational log | mshta.exe spawns rundll32.exe |
| [TDL-014](tdl-014-lsass-memory-access-by-non-allowlisted-process.md) | LSASS Memory Access By Non-Allowlisted Process | critical | T1003.001 | Sysmon operational log | unknown binary opens lsass.exe with dump-capable access masks |
| [TDL-015](tdl-015-windows-event-log-cleared.md) | Windows Event Log Cleared | critical | T1070.001 | Sysmon operational log; Windows Security event log | wevtutil clears the Security log (1102 follows) |
| [TDL-016](tdl-016-outbound-connection-on-rare-destination-port.md) | Outbound Connection On Rare Destination Port | medium | T1571, T1095 | Edge firewall connection log | outbound connections on TCP 4444 |
| [TDL-017](tdl-017-connection-to-known-bad-ip-threat-intel-match.md) | Connection To Known-Bad IP (Threat Intel Match) | critical | T1071, T1105 | Edge firewall connection log | traffic to an address on the known-bad feed |
| [TDL-018](tdl-018-data-exfiltration-outbound-volume-spike-per-host.md) | Data Exfiltration - Outbound Volume Spike Per Host | high | T1048, T1041 | Edge firewall connection log | one host uploads ~520 MB in one hour |
| [TDL-019](tdl-019-privilege-escalation-attempt-via-runas-to-admin-account.md) | Privilege Escalation Attempt Via runas To Admin Account | medium | T1078.002, T1548 | Sysmon operational log | runas /user:CORP\administrator from a workstation |
| [TDL-020](tdl-020-linux-ssh-brute-force.md) | Linux SSH Brute Force | medium | T1110.001 | Linux auth.log (sshd, sudo, useradd, usermod) | 40 SSH failures from one IP against the bastion |
| [TDL-021](tdl-021-linux-ssh-success-after-repeated-failures.md) | Linux SSH Success After Repeated Failures | critical | T1110.001, T1078 | Linux auth.log (sshd, sudo, useradd, usermod) | eight SSH failures followed by a password success |
| [TDL-022](tdl-022-linux-new-user-added-to-sudo-wheel-group.md) | Linux New User Added To sudo/wheel Group | high | T1136.001, T1548.003 | Linux auth.log (sshd, sudo, useradd, usermod) | useradd followed by usermod into the sudo group |
| [TDL-023](tdl-023-unsigned-dll-loaded-from-user-writable-path.md) | Unsigned DLL Loaded From User-Writable Path | medium | T1574.002, T1574.001 | Sysmon operational log | unsigned DLL loaded from a Temp directory |
| [TDL-024](tdl-024-file-dropped-in-startup-folder.md) | File Dropped In Startup Folder | medium | T1547.001 | Sysmon operational log | PowerShell writes a .lnk into the Startup folder |
| [TDL-025](tdl-025-dns-query-from-scripting-or-lolbin-process.md) | DNS Query From Scripting Or LOLBin Process | medium | T1071.004, T1218 | Sysmon operational log | powershell.exe issues DNS queries for staging domains |
