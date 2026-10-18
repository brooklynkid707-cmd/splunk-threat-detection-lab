#!/usr/bin/env python3
"""Generate synthetic Windows Security, Sysmon, Linux auth, firewall and DNS
logs with planted attack scenarios.

Every line is written in the exact format that the sourcetype stanzas in
``TA-threat-detection/default/props.conf`` parse, so the same files can be
ingested by Splunk or evaluated by the Python harness.

All names, addresses and domains are synthetic: RFC 5737 ranges
(203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24) for "internet" addresses,
10.0.0.0/8 internally, and example.com / example.net / example.org domains.

Usage::

    python scripts/generate_logs.py --out data/sample            # benign + every scenario
    python scripts/generate_logs.py --out /tmp/benign --scenarios none
    python scripts/generate_logs.py --out /tmp/x --scenarios win_brute_force,beacon
    python scripts/generate_logs.py --list-scenarios
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import random
import string
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# Inventory (all synthetic)
# ---------------------------------------------------------------------------
FIRST = ["alex", "jordan", "maria", "chen", "priya", "liam", "noah", "emma", "olivia", "ava", "sofia", "mateo",
         "lucas", "mia", "ethan", "zoe", "ravi", "nina", "omar", "leila", "sam", "kai", "ivy", "theo", "ruby",
         "finn", "hana", "ezra", "lena", "milo"]
LAST = ["smith", "garcia", "chen", "patel", "kim", "nguyen", "brown", "wilson", "lopez", "martin", "lee", "walker",
        "hall", "young", "king", "wright", "scott", "green", "baker", "adams", "nelson", "hill", "cruz", "reed",
        "cook", "bell", "ward", "cox", "diaz", "gray"]
DEPARTMENTS = [("FIN", 1), ("OPS", 2), ("HR", 3), ("ENG", 4)]
SERVERS = {
    "DC-01": "10.10.0.10", "DC-02": "10.10.0.11", "FS-01": "10.10.0.20", "FS-02": "10.10.0.21",
    "SRV-WEB-01": "10.10.0.30", "SRV-APP-01": "10.10.0.31", "SRV-DB-01": "10.10.0.32",
    "SRV-JUMP-01": "10.10.0.40", "SRV-VPN-01": "10.10.0.41", "SRV-PRINT-01": "10.10.0.42",
    "SRV-SCCM-01": "10.10.0.43", "SRV-BACKUP-01": "10.10.0.44",
}
LINUX_HOSTS = ["srv-web-01", "srv-app-01", "srv-db-01", "srv-bastion-01"]
ADMIN_USERS = ["mchen", "rpatel", "akim", "jwalker"]
DOMAIN = "CORP"
RESOLVER = "10.10.0.53"

BENIGN_DOMAINS = [
    "www.example.com", "mail.example.com", "login.example.com", "cdn.example.com", "api.example.com",
    "update.example.com", "telemetry.example.com", "sso.example.com", "files.example.com", "teams.example.com",
    "static.example-cdn.com", "img.example-cdn.com", "js.example-cdn.com", "fonts.example-cdn.com",
    "dl.example-update.com", "sync.example-update.com", "ntp.example.net", "time.example.net",
    "crl.example.net", "ocsp.example.net", "wiki.example.org", "docs.example.org", "status.example.org",
    "intranet.corp.example.com", "sharepoint.corp.example.com", "jira.corp.example.com", "git.corp.example.com",
]
COMMON_PORTS = [443] * 60 + [80] * 20 + [53] * 6 + [22] * 3 + [123] * 3 + [993] * 3 + [8080] * 2 + [25] * 2 + [8443]

SYSTEM32 = "C:\\Windows\\System32"
PS_EXE = f"{SYSTEM32}\\WindowsPowerShell\\v1.0\\powershell.exe"
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16"
CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
EXPLORER = "C:\\Windows\\explorer.exe"
SIGNED_DLLS = ["kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll", "ws2_32.dll", "crypt32.dll", "bcrypt.dll",
               "shell32.dll", "ole32.dll", "combase.dll"]

# (parent image, child image, command line template, weight)
BENIGN_PROCESS_PAIRS = [
    (EXPLORER, CHROME, '"{child}" --profile-directory=Default', 18),
    (EXPLORER, f"{OFFICE}\\OUTLOOK.EXE", '"{child}"', 12),
    (EXPLORER, f"{OFFICE}\\WINWORD.EXE", '"{child}" /n "C:\\Users\\{user}\\Documents\\report.docx"', 10),
    (EXPLORER, f"{OFFICE}\\EXCEL.EXE", '"{child}" /e "C:\\Users\\{user}\\Documents\\budget.xlsx"', 8),
    (EXPLORER, "C:\\Program Files\\Teams\\Teams.exe", '"{child}" --background', 8),
    (EXPLORER, f"{SYSTEM32}\\notepad.exe", '"{child}" C:\\Users\\{user}\\notes.txt', 6),
    (EXPLORER, f"{SYSTEM32}\\cmd.exe", '"{child}"', 6),
    (EXPLORER, PS_EXE, '"{child}" -NoProfile -File C:\\Scripts\\inventory.ps1', 4),
    (f"{SYSTEM32}\\cmd.exe", PS_EXE, 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\collect.ps1', 4),
    (f"{SYSTEM32}\\cmd.exe", f"{SYSTEM32}\\ipconfig.exe", 'ipconfig /all', 4),
    (f"{SYSTEM32}\\services.exe", f"{SYSTEM32}\\svchost.exe", 'C:\\Windows\\System32\\svchost.exe -k netsvcs -p', 14),
    (f"{SYSTEM32}\\svchost.exe", f"{SYSTEM32}\\taskhostw.exe", 'taskhostw.exe {{222A245B-E637-4AE9-A93F-A59CA119A75E}}', 8),
    (f"{SYSTEM32}\\svchost.exe", f"{SYSTEM32}\\backgroundTaskHost.exe", '"{child}" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca', 6),
    (f"{SYSTEM32}\\svchost.exe", f"{SYSTEM32}\\schtasks.exe", 'schtasks.exe /query /tn "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan"', 4),
    (CHROME, CHROME, '"{child}" --type=renderer --lang=en-US', 16),
    (f"{SYSTEM32}\\userinit.exe", EXPLORER, 'C:\\Windows\\explorer.exe', 5),
    (f"{SYSTEM32}\\msiexec.exe", f"{SYSTEM32}\\msiexec.exe", 'C:\\Windows\\System32\\MsiExec.exe -Embedding 9F1C0E2B', 4),
    (f"{SYSTEM32}\\svchost.exe", f"{SYSTEM32}\\wbem\\WmiPrvSE.exe", 'C:\\Windows\\System32\\wbem\\WmiPrvSE.exe', 6),
]


@dataclass(order=True)
class Record:
    """One log line destined for one sourcetype file."""

    ts: float
    sourcetype: str
    line: str


# ---------------------------------------------------------------------------
# Formatting helpers (these define the on-disk formats props.conf parses)
# ---------------------------------------------------------------------------
def iso_z(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_offset(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def bind_ts(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%d-%b-%Y %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def kv(**fields: object) -> str:
    """Render key=value pairs, quoting values that contain spaces."""
    parts = []
    for key, value in fields.items():
        if value is None:
            continue
        text = str(value)
        if text == "" or any(ch.isspace() for ch in text) or '"' in text or ";" in text:
            text = '"' + text.replace('"', '\\"') + '"'
        parts.append(f"{key}={text}")
    return " ".join(parts)


class LogGenerator:
    """Deterministic synthetic log generator with pluggable attack scenarios."""

    def __init__(self, seed: int = 42, start: str = "2026-10-14T00:00:00Z", hours: int = 24) -> None:
        self.rng = random.Random(seed)
        self.start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.hours = hours
        self.start_ts = self.start.timestamp()
        self.end_ts = self.start_ts + hours * 3600
        self._pid = 1000
        self.workstations: dict[str, str] = {}
        self.users: list[str] = []
        self.user_host: dict[str, str] = {}
        dept_rng = random.Random(seed + 1)
        used: set[str] = set()
        for dept, octet in DEPARTMENTS:
            for n in range(1, 16):
                host = f"WS-{dept}-{n:02d}"
                self.workstations[host] = f"10.20.{octet}.{48 + n}"
                while True:
                    user = dept_rng.choice(FIRST)[0] + dept_rng.choice(LAST)
                    if user not in used:
                        used.add(user)
                        break
                self.users.append(user)
                self.user_host[user] = host
        for admin in ADMIN_USERS:
            if admin not in self.user_host:
                self.users.append(admin)
                self.user_host[admin] = "WS-OPS-01"
        self.external_pool = [f"203.0.113.{i}" for i in range(10, 40)] + [f"198.51.100.{i}" for i in range(10, 40)]
        self.vpn_pool = [f"203.0.113.{i}" for i in range(100, 121)]
        self.favorites = {host: self.rng.sample(self.external_pool, 4) for host in self.workstations}

    # -- small helpers --------------------------------------------------
    def pid(self) -> int:
        self._pid += self.rng.randint(1, 40)
        return self._pid

    def at(self, hour: float, minute: float = 0, second: float = 0) -> float:
        return self.start_ts + hour * 3600 + minute * 60 + second

    def rand_in_hour(self, hour: int) -> float:
        return self.start_ts + hour * 3600 + self.rng.random() * 3600

    def guid(self) -> str:
        return "{" + "".join(self.rng.choice("0123456789ABCDEF") for _ in range(32)) + "}"

    def sha256(self) -> str:
        return "SHA256=" + "".join(self.rng.choice("0123456789ABCDEF") for _ in range(64))

    def ws_ip(self, host: str) -> str:
        return self.workstations.get(host) or SERVERS[host]

    # -- event builders ----------------------------------------------
    def win_logon(self, ts: float, host: str, user: str, logon_type: int, src_ip: str, success: bool,
                  workstation: str | None = None, status: str = "0xC000006A") -> Record:
        fields = dict(
            host=host, EventCode=4624 if success else 4625, Account_Name=user, Account_Domain=DOMAIN,
            Logon_Type=logon_type, Source_Network_Address=src_ip, Workstation_Name=workstation or host,
            Logon_Process="NtLmSsp" if logon_type in (3, 10) else "User32", Authentication_Package="NTLM" if logon_type == 3 else "Negotiate",
        )
        if success:
            fields.update(Logon_ID=f"0x{self.rng.randint(0x10000, 0xFFFFFF):X}")
        else:
            fields.update(Status=status, Sub_Status="0xC000006A" if status == "0xC000006D" else "0x0",
                          Failure_Reason="Unknown user name or bad password.")
        return Record(ts, "lab:windows:security", f"{iso_z(ts)} {kv(**fields)}")

    def win_process(self, ts: float, host: str, user: str, process: str, cmdline: str, parent: str) -> Record:
        fields = dict(host=host, EventCode=4688, Account_Name=user, Account_Domain=DOMAIN, New_Process_Name=process,
                      New_Process_ID=f"0x{self.pid():x}", Creator_Process_Name=parent, Token_Elevation_Type="%%1938",
                      Process_Command_Line=cmdline)
        return Record(ts, "lab:windows:security", f"{iso_z(ts)} {kv(**fields)}")

    def win_user_created(self, ts: float, host: str, subject: str, target: str) -> Record:
        fields = dict(host=host, EventCode=4720, Subject_Account_Name=subject, Subject_Domain=DOMAIN,
                      Target_Account_Name=target, Target_Domain=DOMAIN, SAM_Account_Name=target, Display_Name=target)
        return Record(ts, "lab:windows:security", f"{iso_z(ts)} {kv(**fields)}")

    def win_group_member_added(self, ts: float, host: str, subject: str, member: str, group: str) -> Record:
        fields = dict(host=host, EventCode=4732, Subject_Account_Name=subject, Subject_Domain=DOMAIN,
                      Member_Name=member, Group_Name=group, Group_Domain="Builtin")
        return Record(ts, "lab:windows:security", f"{iso_z(ts)} {kv(**fields)}")

    def win_log_cleared(self, ts: float, host: str, subject: str) -> Record:
        fields = dict(host=host, EventCode=1102, Account_Name=subject, Account_Domain=DOMAIN,
                      Logon_ID=f"0x{self.rng.randint(0x10000, 0xFFFFFF):X}", Message="The audit log was cleared.")
        return Record(ts, "lab:windows:security", f"{iso_z(ts)} {kv(**fields)}")

    def win_task_created(self, ts: float, host: str, subject: str, task: str, command: str) -> Record:
        fields = dict(host=host, EventCode=4698, Account_Name=subject, Account_Domain=DOMAIN, Task_Name=task,
                      Task_Command=command)
        return Record(ts, "lab:windows:security", f"{iso_z(ts)} {kv(**fields)}")

    def sysmon_process(self, ts: float, host: str, user: str, image: str, cmdline: str, parent: str,
                       parent_cmdline: str | None = None) -> Record:
        fields = dict(host=host, EventCode=1, UtcTime=iso_z(ts), ProcessGuid=self.guid(), ProcessId=self.pid(),
                      Image=image, CommandLine=cmdline, CurrentDirectory=f"C:\\Users\\{user.split(chr(92))[-1]}\\",
                      User=user, IntegrityLevel="Medium", Hashes=self.sha256(), ParentProcessId=self.pid(),
                      ParentImage=parent, ParentCommandLine=parent_cmdline or parent)
        return Record(ts, "lab:sysmon", f"{iso_z(ts)} {kv(**fields)}")

    def sysmon_network(self, ts: float, host: str, user: str, image: str, dest_ip: str, dest_port: int,
                       dest_host: str = "-", protocol: str = "tcp") -> Record:
        fields = dict(host=host, EventCode=3, UtcTime=iso_z(ts), ProcessGuid=self.guid(), ProcessId=self.pid(),
                      Image=image, User=user, Protocol=protocol, Initiated="true", SourceIp=self.ws_ip(host),
                      SourcePort=self.rng.randint(49152, 65535), DestinationIp=dest_ip, DestinationPort=dest_port,
                      DestinationHostname=dest_host)
        return Record(ts, "lab:sysmon", f"{iso_z(ts)} {kv(**fields)}")

    def sysmon_imageload(self, ts: float, host: str, user: str, image: str, loaded: str, signed: bool,
                         signature: str = "Microsoft Windows") -> Record:
        fields = dict(host=host, EventCode=7, UtcTime=iso_z(ts), ProcessGuid=self.guid(), ProcessId=self.pid(),
                      Image=image, ImageLoaded=loaded, Hashes=self.sha256(), Signed="true" if signed else "false",
                      Signature=signature if signed else "-", SignatureStatus="Valid" if signed else "Unavailable", User=user)
        return Record(ts, "lab:sysmon", f"{iso_z(ts)} {kv(**fields)}")

    def sysmon_process_access(self, ts: float, host: str, user: str, source: str, target: str, access: str,
                              call_trace: str) -> Record:
        fields = dict(host=host, EventCode=10, UtcTime=iso_z(ts), SourceProcessGUID=self.guid(), SourceProcessId=self.pid(),
                      SourceThreadId=self.pid(), SourceImage=source, TargetProcessGUID=self.guid(), TargetProcessId=712,
                      TargetImage=target, GrantedAccess=access, CallTrace=call_trace, User=user)
        return Record(ts, "lab:sysmon", f"{iso_z(ts)} {kv(**fields)}")

    def sysmon_file_create(self, ts: float, host: str, user: str, image: str, target: str) -> Record:
        fields = dict(host=host, EventCode=11, UtcTime=iso_z(ts), ProcessGuid=self.guid(), ProcessId=self.pid(),
                      Image=image, TargetFilename=target, CreationUtcTime=iso_z(ts), User=user)
        return Record(ts, "lab:sysmon", f"{iso_z(ts)} {kv(**fields)}")

    def sysmon_dns(self, ts: float, host: str, user: str, image: str, query: str, result: str = "::ffff:203.0.113.20") -> Record:
        fields = dict(host=host, EventCode=22, UtcTime=iso_z(ts), ProcessGuid=self.guid(), ProcessId=self.pid(),
                      QueryName=query, QueryStatus=0, QueryResults=result + ";", Image=image, User=user)
        return Record(ts, "lab:sysmon", f"{iso_z(ts)} {kv(**fields)}")

    def linux_line(self, ts: float, host: str, process: str, pid: int | None, message: str) -> Record:
        proc = f"{process}[{pid}]" if pid is not None else process
        return Record(ts, "lab:linux:auth", f"{iso_offset(ts)} {host} {proc}: {message}")

    def linux_ssh(self, ts: float, host: str, accepted: bool, user: str, src_ip: str, method: str = "password",
                  invalid: bool = False) -> Record:
        word = "Accepted" if accepted else "Failed"
        inval = "invalid user " if invalid and not accepted else ""
        port = self.rng.randint(1024, 65535)
        return self.linux_line(ts, host, "sshd", self.pid(), f"{word} {method} for {inval}{user} from {src_ip} port {port} ssh2")

    def linux_sudo(self, ts: float, host: str, user: str, command: str, run_as: str = "root") -> Record:
        return self.linux_line(ts, host, "sudo", None, f"    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER={run_as} ; COMMAND={command}")

    def firewall(self, ts: float, action: str, direction: str, src_ip: str, dest_ip: str, dest_port: int,
                 bytes_in: int, bytes_out: int, protocol: str = "tcp") -> Record:
        src_port = self.rng.randint(1024, 65535)
        line = "|".join(str(x) for x in [iso_z(ts), "FW-EDGE-01", action, direction, src_ip, src_port, dest_ip,
                                           dest_port, protocol, bytes_in, bytes_out])
        return Record(ts, "lab:firewall", line)

    def dns(self, ts: float, client_ip: str, query: str, record_type: str = "A") -> Record:
        port = self.rng.randint(1024, 65535)
        return Record(ts, "lab:dns", f"{bind_ts(ts)} client {client_ip}#{port}: query: {query} IN {record_type} + ({RESOLVER})")

    # -- benign background ------------------------------------------------
    def _activity_weight(self, hour: int) -> float:
        hour_of_day = (self.start.hour + hour) % 24
        return 1.0 if 7 <= hour_of_day <= 19 else 0.35

    def benign(self) -> list[Record]:
        """Generate a day of normal activity for every data source."""
        records: list[Record] = []
        rng = self.rng
        ws_names = list(self.workstations)
        for hour in range(self.hours):
            weight = self._activity_weight(hour)

            # Windows logons -------------------------------------------------
            for _ in range(int(30 * weight)):
                user = rng.choice(self.users)
                host = self.user_host[user]
                roll = rng.random()
                if roll < 0.45:
                    records.append(self.win_logon(self.rand_in_hour(hour), host, user, 2, "127.0.0.1", True))
                elif roll < 0.85:
                    server = rng.choice(["FS-01", "FS-02", "DC-01", "SRV-PRINT-01"])
                    records.append(self.win_logon(self.rand_in_hour(hour), server, user, 3, self.ws_ip(host), True, host))
                else:
                    records.append(self.win_logon(self.rand_in_hour(hour), "SRV-VPN-01", user, 3, rng.choice(self.vpn_pool), True, host))
            for _ in range(rng.randint(0, 2)):
                admin = rng.choice(ADMIN_USERS)
                server = rng.choice(["SRV-JUMP-01", "SRV-APP-01"])
                records.append(self.win_logon(self.rand_in_hour(hour), server, admin, 10, self.ws_ip(self.user_host[admin]), True, self.user_host[admin]))
            for _ in range(rng.randint(1, 4)):
                user = rng.choice(self.users)
                host = self.user_host[user]
                records.append(self.win_logon(self.rand_in_hour(hour), rng.choice([host, "FS-01", "DC-01"]), user,
                                              rng.choice([2, 3]), self.ws_ip(host), False, host))

            # Process creation (Sysmon 1 + 4688) ------------------------------
            for _ in range(int(40 * weight)):
                ts = self.rand_in_hour(hour)
                user = rng.choice(self.users)
                host = self.user_host[user]
                parent, child, template, _w = rng.choices(BENIGN_PROCESS_PAIRS, weights=[p[3] for p in BENIGN_PROCESS_PAIRS])[0]
                cmdline = template.format(child=child, user=user)
                sys_user = "NT AUTHORITY\\SYSTEM" if "services.exe" in parent or "svchost" in parent else f"{DOMAIN}\\{user}"
                records.append(self.sysmon_process(ts, host, sys_user, child, cmdline, parent))
                if rng.random() < 0.5:
                    records.append(self.win_process(ts + 0.2, host, user if sys_user.endswith(user) else f"{host}$", child, cmdline, parent))

            # Sysmon network connections -----------------------------------
            for _ in range(int(40 * weight)):
                ts = self.rand_in_hour(hour)
                user = rng.choice(self.users)
                host = self.user_host[user]
                roll = rng.random()
                if roll < 0.35:
                    srv = rng.choice(["FS-01", "FS-02"])
                    records.append(self.sysmon_network(ts, host, f"{DOMAIN}\\{user}", EXPLORER, SERVERS[srv], 445, srv))
                elif roll < 0.55:
                    srv = rng.choice(["DC-01", "DC-02"])
                    port = rng.choice([445, 389, 88, 135])
                    records.append(self.sysmon_network(ts, host, "NT AUTHORITY\\SYSTEM", f"{SYSTEM32}\\lsass.exe", SERVERS[srv], port, srv))
                elif roll < 0.7:
                    records.append(self.sysmon_network(ts, host, f"{DOMAIN}\\{user}", CHROME, SERVERS["SRV-WEB-01"], 443, "SRV-WEB-01"))
                else:
                    records.append(self.sysmon_network(ts, host, f"{DOMAIN}\\{user}", CHROME, rng.choice(self.favorites[host]), 443))

            # Sysmon image loads ---------------------------------------------
            for _ in range(int(15 * weight)):
                user = rng.choice(self.users)
                image = rng.choice([CHROME, f"{OFFICE}\\OUTLOOK.EXE", f"{SYSTEM32}\\svchost.exe", f"{OFFICE}\\WINWORD.EXE"])
                records.append(self.sysmon_imageload(self.rand_in_hour(hour), self.user_host[user], f"{DOMAIN}\\{user}", image,
                                                     f"{SYSTEM32}\\{rng.choice(SIGNED_DLLS)}", True))

            # Sysmon process access (AV + OS internals touching lsass) ---------
            for _ in range(int(5 * weight)):
                host = rng.choice(ws_names)
                source, access = rng.choice([
                    ("C:\\Program Files\\Windows Defender\\MsMpEng.exe", "0x1FFFFF"),
                    (f"{SYSTEM32}\\csrss.exe", "0x1000"), (f"{SYSTEM32}\\svchost.exe", "0x1000"),
                    (f"{SYSTEM32}\\wininit.exe", "0x1000"),
                ])
                records.append(self.sysmon_process_access(self.rand_in_hour(hour), host, "NT AUTHORITY\\SYSTEM", source,
                                                          f"{SYSTEM32}\\lsass.exe", access,
                                                          "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4a4|C:\\Windows\\System32\\KERNELBASE.dll+2c3fe"))

            # Sysmon file creates -------------------------------------------
            for _ in range(int(10 * weight)):
                user = rng.choice(self.users)
                host = self.user_host[user]
                image, target = rng.choice([
                    (CHROME, f"C:\\Users\\{user}\\Downloads\\invoice-{rng.randint(1000, 9999)}.pdf"),
                    (f"{OFFICE}\\WINWORD.EXE", f"C:\\Users\\{user}\\Documents\\~$draft-{rng.randint(1, 99)}.docx"),
                    (f"{SYSTEM32}\\msiexec.exe", f"C:\\Windows\\Temp\\MSI{rng.randint(1000, 9999)}.tmp"),
                    (f"{OFFICE}\\OUTLOOK.EXE", f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Outlook\\{user}.ost"),
                ])
                records.append(self.sysmon_file_create(self.rand_in_hour(hour), host, f"{DOMAIN}\\{user}", image, target))

            # Sysmon DNS ---------------------------------------------------------
            for _ in range(int(30 * weight)):
                user = rng.choice(self.users)
                host = self.user_host[user]
                image, query = rng.choice([
                    (CHROME, rng.choice(BENIGN_DOMAINS)), (f"{OFFICE}\\OUTLOOK.EXE", "mail.example.com"),
                    (f"{SYSTEM32}\\svchost.exe", "update.example.com"), ("C:\\Program Files\\Teams\\Teams.exe", "teams.example.com"),
                ])
                records.append(self.sysmon_dns(self.rand_in_hour(hour), host, f"{DOMAIN}\\{user}", image, query))

            # Resolver DNS log -------------------------------------------------
            for _ in range(int(200 * weight)):
                host = rng.choice(ws_names)
                domain = rng.choice(BENIGN_DOMAINS)
                if rng.random() < 0.2:
                    domain = f"{rng.choice(['a', 'b', 'c', 'edge', 'img', 'v2'])}{rng.randint(1, 9)}.{domain}"
                records.append(self.dns(self.rand_in_hour(hour), self.ws_ip(host), domain, rng.choice(["A", "A", "A", "AAAA"])))

            # Firewall --------------------------------------------------------
            for host in ws_names:
                for _ in range(rng.randint(1, 4) if rng.random() < weight else 0):
                    dest = rng.choice(self.favorites[host]) if rng.random() < 0.7 else rng.choice(self.external_pool)
                    port = rng.choice(COMMON_PORTS)
                    bytes_out = int(rng.lognormvariate(10.0, 1.2))
                    bytes_in = int(bytes_out * rng.uniform(2, 12))
                    records.append(self.firewall(self.rand_in_hour(hour), "allow", "outbound", self.ws_ip(host), dest, port, bytes_in, bytes_out))
            for _ in range(rng.randint(5, 15)):
                scanner = f"192.0.2.{rng.randint(10, 99)}"
                records.append(self.firewall(self.rand_in_hour(hour), "deny", "inbound", scanner, "203.0.113.5",
                                             rng.choice([22, 23, 445, 3389, 8080, 1433, 5900]), 0, 0))

            # Linux auth ------------------------------------------------------
            for _ in range(int(6 * weight)):
                admin = rng.choice(ADMIN_USERS)
                host = rng.choice(LINUX_HOSTS)
                src = self.ws_ip(self.user_host[admin])
                ts = self.rand_in_hour(hour)
                if rng.random() < 0.05:
                    records.append(self.linux_ssh(ts - 8, host, False, admin, src))
                records.append(self.linux_ssh(ts, host, True, admin, src, "publickey"))
                records.append(self.linux_line(ts + 0.5, host, "sshd", self.pid(), f"pam_unix(sshd:session): session opened for user {admin} by (uid=0)"))
                if rng.random() < 0.6:
                    records.append(self.linux_sudo(ts + rng.randint(5, 300), host, admin,
                                                   rng.choice(["/usr/bin/systemctl status nginx", "/usr/bin/apt update", "/usr/bin/tail -n 100 /var/log/syslog",
                                                               "/usr/bin/journalctl -u app", "/usr/bin/docker ps"])))
            for _ in range(rng.randint(1, 3)):
                scanner = rng.choice([f"203.0.113.{rng.randint(200, 250)}", f"192.0.2.{rng.randint(100, 199)}"])
                host = rng.choice(["srv-web-01", "srv-bastion-01"])
                ts = self.rand_in_hour(hour)
                for i in range(rng.randint(1, 2)):
                    records.append(self.linux_ssh(ts + i * 3, host, False, rng.choice(["admin", "test", "ubuntu", "oracle"]), scanner, invalid=True))
            records.append(self.linux_line(self.at(hour, 17), rng.choice(LINUX_HOSTS), "CRON", self.pid(),
                                           "pam_unix(cron:session): session opened for user root by (uid=0)"))

        # Daily account administration (benign) ------------------------------------
        for n in range(2):
            ts = self.at(9 + n * 4, 12)
            new_user = f"newhire.{rng.choice(LAST)}{rng.randint(1, 9)}"
            records.append(self.win_user_created(ts, "DC-01", "rpatel", new_user))
            records.append(self.win_group_member_added(ts + 30, "DC-01", "rpatel", new_user, rng.choice(["Remote Desktop Users", "Domain Users"])))
        for n in range(3):
            host = rng.choice(ws_names)
            records.append(self.win_task_created(self.at(3 + n * 6, 5), host, f"{host}$",
                                                 "\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot",
                                                 "%systemroot%\\system32\\MusNotification.exe"))
        return records

    # -- attack scenarios ------------------------------------------------
    def scenario_win_brute_force(self) -> list[Record]:
        """TDL-001: 60 failures from 203.0.113.45 against svc_backup on DC-01 in 3 minutes."""
        base = self.at(2, 11)
        return [self.win_logon(base + i * 3, "DC-01", "svc_backup", 3, "203.0.113.45", False, "KALI", "0xC000006D")
                for i in range(60)]

    def scenario_password_spray(self) -> list[Record]:
        """TDL-002: one failure each against 30 accounts from 198.51.100.23 in 8 minutes."""
        base = self.at(3, 1)
        return [self.win_logon(base + i * 16, "DC-01", user, 3, "198.51.100.23", False, "WORKSTATION", "0xC000006A")
                for i, user in enumerate(self.users[:30])]

    def scenario_impossible_travel(self) -> list[Record]:
        """TDL-003: mchen logs on via VPN from the US then from Brazil 15 minutes later."""
        return [
            self.win_logon(self.at(10, 10), "SRV-VPN-01", "mchen", 3, "203.0.113.77", True, "WS-OPS-01"),
            self.win_logon(self.at(10, 25), "SRV-VPN-01", "mchen", 3, "192.0.2.55", True, "DESKTOP-9Q2L"),
        ]

    def scenario_new_admin(self) -> list[Record]:
        """TDL-004: svc_backup creates backupadm and adds it to Administrators on DC-01."""
        ts = self.at(11, 32)
        return [
            self.win_user_created(ts, "DC-01", "svc_backup", "backupadm"),
            self.win_group_member_added(ts + 41, "DC-01", "svc_backup", "backupadm", "Administrators"),
        ]

    def scenario_rdp_lateral(self) -> list[Record]:
        """TDL-005: mchen RDPs to six servers in 25 minutes from WS-FIN-07."""
        src = self.ws_ip("WS-FIN-07")
        targets = ["SRV-APP-01", "SRV-DB-01", "FS-01", "SRV-SCCM-01", "SRV-BACKUP-01", "DC-02"]
        return [self.win_logon(self.at(11, 2 + i * 4), host, "mchen", 10, src, True, "WS-FIN-07") for i, host in enumerate(targets)]

    def scenario_smb_lateral(self) -> list[Record]:
        """TDL-006: WS-FIN-07 opens SMB to 12 peers in 4 minutes (share enumeration)."""
        base = self.at(10, 31)
        user = f"{DOMAIN}\\{self.victim}"
        peers = [h for h in self.workstations if h.startswith("WS-OPS")][:10] + ["FS-02", "SRV-APP-01"]
        return [self.sysmon_network(base + i * 18, "WS-FIN-07", user, f"{SYSTEM32}\\net.exe", self.ws_ip(peer), 445, peer)
                for i, peer in enumerate(peers)]

    def scenario_ps_encoded(self) -> list[Record]:
        """TDL-007: Word macro launches powershell -enc <base64> (also seen as 4688)."""
        ts = self.at(9, 47)
        host, user = "WS-HR-03", self.users[32]
        # The payload is a Base64 encoding of a harmless placeholder string.
        payload = base64.b64encode("lab-placeholder-encoded-command-text-for-detection-testing".encode("utf-16-le")).decode()
        cmdline = f"powershell.exe -NoP -NonI -W Hidden -Enc {payload}"
        parent = f"{OFFICE}\\WINWORD.EXE"
        return [
            self.sysmon_process(ts, host, f"{DOMAIN}\\{user}", PS_EXE, cmdline, parent, f'"{parent}" /n "C:\\Users\\{user}\\Downloads\\invoice.docm"'),
            self.win_process(ts + 0.3, host, user, PS_EXE, cmdline, parent),
        ]

    def scenario_schtask(self) -> list[Record]:
        """TDL-008: interactive user creates a task outside \\Microsoft\\Windows\\ via schtasks and 4698."""
        ts = self.at(12, 14)
        host, user = "WS-FIN-07", self.victim
        cmdline = 'schtasks.exe /create /sc minute /mo 15 /tn "OneDriveSync" /tr "C:\\Users\\Public\\sync.exe" /f'
        return [
            self.sysmon_process(ts, host, f"{DOMAIN}\\{user}", f"{SYSTEM32}\\schtasks.exe", cmdline, f"{SYSTEM32}\\cmd.exe"),
            self.win_task_created(ts + 1, host, user, "\\OneDriveSync", "C:\\Users\\Public\\sync.exe"),
        ]

    def scenario_dns_tunnel(self) -> list[Record]:
        """TDL-009: 40 queries of 60+ character labels to tun.example.net from WS-ENG-05."""
        base = self.at(14, 3)
        client = self.ws_ip("WS-ENG-05")
        alphabet = string.ascii_lowercase + string.digits
        records = []
        for i in range(40):
            label = "".join(self.rng.choice(alphabet) for _ in range(52))
            records.append(self.dns(base + i * 7, client, f"{label}.tun.example.net", "TXT"))
        return records

    def scenario_dns_subdomains(self) -> list[Record]:
        """TDL-010: 150 distinct short subdomains of example.org from WS-ENG-09 in eight minutes."""
        base = self.at(15, 20)
        client = self.ws_ip("WS-ENG-09")
        return [self.dns(base + i * 3.2, client, f"{self.rng.randrange(16**8):08x}.example.org") for i in range(150)]

    def scenario_beacon(self) -> list[Record]:
        """TDL-011: WS-OPS-04 connects to 203.0.113.66:443 every 60s (+/-2s) for 40 minutes."""
        base = self.at(1, 5)
        src = self.ws_ip("WS-OPS-04")
        records = []
        ts = base
        for _ in range(40):
            ts += 60 + self.rng.uniform(-2, 2)
            records.append(self.firewall(ts, "allow", "outbound", src, "203.0.113.66", 443, self.rng.randint(300, 900), self.rng.randint(200, 400)))
        return records

    def scenario_office_shell(self) -> list[Record]:
        """TDL-012: Excel spawns cmd.exe which runs a script host."""
        ts = self.at(13, 41)
        host, user = "WS-FIN-02", self.users[1]
        excel = f"{OFFICE}\\EXCEL.EXE"
        return [
            self.sysmon_process(ts, host, f"{DOMAIN}\\{user}", f"{SYSTEM32}\\cmd.exe", 'cmd.exe /c "C:\\Users\\Public\\run.bat"', excel,
                                f'"{excel}" /e "C:\\Users\\{user}\\Downloads\\Q3-forecast.xlsm"'),
            self.sysmon_process(ts + 1, host, f"{DOMAIN}\\{user}", f"{SYSTEM32}\\wscript.exe", 'wscript.exe //B C:\\Users\\Public\\stage.vbs', f"{SYSTEM32}\\cmd.exe"),
        ]

    def scenario_rare_parent_child(self) -> list[Record]:
        """TDL-013: mshta.exe spawns rundll32.exe twice on WS-HR-11."""
        ts = self.at(16, 22)
        host, user = "WS-HR-11", self.users[40]
        return [self.sysmon_process(ts + i * 90, host, f"{DOMAIN}\\{user}", f"{SYSTEM32}\\rundll32.exe",
                                    'rundll32.exe C:\\Users\\Public\\helper.dll,Start', f"{SYSTEM32}\\mshta.exe",
                                    'mshta.exe C:\\Users\\Public\\page.hta') for i in range(2)]

    def scenario_lsass_access(self) -> list[Record]:
        """TDL-014: an unknown binary in Windows\\Temp opens lsass with dump-capable access masks."""
        ts = self.at(17, 8)
        host, user = "WS-FIN-07", self.victim
        source = "C:\\Windows\\Temp\\pd.exe"
        trace = "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4a4|C:\\Windows\\System32\\KERNELBASE.dll+2c3fe|C:\\Windows\\Temp\\pd.exe+1a2b"
        return [self.sysmon_process_access(ts + i * 2, host, f"{DOMAIN}\\{user}", source, f"{SYSTEM32}\\lsass.exe", access, trace)
                for i, access in enumerate(["0x1FFFFF", "0x1010", "0x1438"])]

    def scenario_log_cleared(self) -> list[Record]:
        """TDL-015: wevtutil clears the Security log and Windows records 1102."""
        ts = self.at(18, 55)
        host, user = "WS-FIN-07", self.victim
        return [
            self.sysmon_process(ts, host, f"{DOMAIN}\\{user}", f"{SYSTEM32}\\wevtutil.exe", "wevtutil.exe cl Security", f"{SYSTEM32}\\cmd.exe"),
            self.win_log_cleared(ts + 1, host, user),
        ]

    def scenario_rare_port(self) -> list[Record]:
        """TDL-016: three outbound connections from WS-ENG-02 to 203.0.113.88 on TCP 4444."""
        base = self.at(19, 12)
        src = self.ws_ip("WS-ENG-02")
        return [self.firewall(base + i * 45, "allow", "outbound", src, "203.0.113.88", 4444, 1200, 3400) for i in range(3)]

    def scenario_threat_intel_ip(self) -> list[Record]:
        """TDL-017: WS-HR-08 talks to 198.51.100.251 (exfil drop host on the lab feed)."""
        base = self.at(20, 31)
        src = self.ws_ip("WS-HR-08")
        records = [self.firewall(base + i * 20, "allow", "outbound", src, "198.51.100.251", 443, 900, 48000) for i in range(4)]
        records.append(self.firewall(base + 100, "deny", "outbound", src, "198.51.100.251", 8443, 0, 0))
        return records

    def scenario_exfil_volume(self) -> list[Record]:
        """TDL-018: WS-OPS-09 pushes ~520 MB to 203.0.113.37 inside one hour."""
        base = self.at(21, 4)
        src = self.ws_ip("WS-OPS-09")
        return [self.firewall(base + i * 300, "allow", "outbound", src, "203.0.113.37", 443, 12000, 65_000_000 + self.rng.randint(0, 2_000_000))
                for i in range(8)]

    def scenario_runas_admin(self) -> list[Record]:
        """TDL-019: runas /user:CORP\\administrator launched from a workstation."""
        ts = self.at(12, 48)
        host, user = "WS-FIN-07", self.victim
        return [self.sysmon_process(ts, host, f"{DOMAIN}\\{user}", f"{SYSTEM32}\\runas.exe",
                                    f'runas.exe /user:{DOMAIN}\\administrator "cmd.exe /k whoami"', f"{SYSTEM32}\\cmd.exe")]

    def scenario_ssh_brute(self) -> list[Record]:
        """TDL-020: 40 SSH failures from 192.0.2.77 against srv-bastion-01 in six minutes."""
        base = self.at(4, 20)
        return [self.linux_ssh(base + i * 9, "srv-bastion-01", False, self.rng.choice(["root", "admin", "deploy", "ubuntu"]), "192.0.2.77", invalid=i % 3 == 0)
                for i in range(40)]

    def scenario_ssh_success_after_failures(self) -> list[Record]:
        """TDL-021: eight failures then a password success for deploy from 203.0.113.90 on srv-web-01."""
        base = self.at(5, 42)
        records = [self.linux_ssh(base + i * 25, "srv-web-01", False, "deploy", "203.0.113.90") for i in range(8)]
        records.append(self.linux_ssh(base + 8 * 25, "srv-web-01", True, "deploy", "203.0.113.90"))
        records.append(self.linux_line(base + 8 * 25 + 0.5, "srv-web-01", "sshd", self.pid(), "pam_unix(sshd:session): session opened for user deploy by (uid=0)"))
        return records

    def scenario_linux_sudo_user(self) -> list[Record]:
        """TDL-022: useradd creates svcmon and usermod adds it to sudo on srv-app-01."""
        ts = self.at(6, 3)
        host = "srv-app-01"
        return [
            self.linux_sudo(ts, host, "deploy", "/usr/sbin/useradd -m svcmon"),
            self.linux_line(ts + 1, host, "useradd", self.pid(), "new user: name=svcmon, UID=1007, GID=1007, home=/home/svcmon, shell=/bin/bash"),
            self.linux_sudo(ts + 20, host, "deploy", "/usr/sbin/usermod -aG sudo svcmon"),
            self.linux_line(ts + 21, host, "usermod", self.pid(), "add 'svcmon' to group 'sudo'"),
        ]

    def scenario_unsigned_dll(self) -> list[Record]:
        """TDL-023: an unsigned version.dll is loaded from a user's Temp directory."""
        ts = self.at(13, 59)
        host, user = "WS-FIN-07", self.victim
        loaded = f"C:\\Users\\{user}\\AppData\\Local\\Temp\\version.dll"
        return [self.sysmon_imageload(ts + i * 30, host, f"{DOMAIN}\\{user}", f"C:\\Users\\{user}\\AppData\\Local\\Temp\\setup.exe", loaded, False)
                for i in range(2)]

    def scenario_startup_folder(self) -> list[Record]:
        """TDL-024: PowerShell drops a shortcut into the user's Startup folder."""
        ts = self.at(14, 36)
        host, user = "WS-ENG-05", self.users[49]
        target = f"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk"
        return [self.sysmon_file_create(ts, host, f"{DOMAIN}\\{user}", PS_EXE, target)]

    def scenario_lolbin_dns(self) -> list[Record]:
        """TDL-025: powershell.exe resolves three staging domains on WS-HR-03."""
        ts = self.at(9, 48)
        host, user = "WS-HR-03", self.users[32]
        return [self.sysmon_dns(ts + i * 4, host, f"{DOMAIN}\\{user}", PS_EXE, domain, "::ffff:203.0.113.151")
                for i, domain in enumerate(["cdn-stage.example.net", "files.example-mirror.net", "api.example-mirror.net"])]

    # -- orchestration ----------------------------------------------------
    @property
    def victim(self) -> str:
        """The user whose workstation (WS-FIN-07) is the pivot point of the planted intrusion."""
        return self.users[6]

    def generate(self, scenarios: Iterable[str] | None = None) -> list[Record]:
        """Return benign background plus the requested planted scenarios, sorted by time.

        ``scenarios`` accepts detection IDs (``TDL-007``) or scenario slugs
        (``ps_encoded``). ``None`` or ``["all"]`` plants every scenario;
        ``["none"]`` returns benign data only.
        """
        records = self.benign()
        for detection_id in resolve_scenarios(scenarios):
            method: Callable[[], list[Record]] = getattr(self, f"scenario_{SCENARIOS[detection_id].slug}")
            records.extend(method())
        records.sort()
        return records


@dataclass(frozen=True)
class Scenario:
    """A planted attack scenario and the detection it exists to trigger."""

    detection_id: str
    slug: str
    summary: str


SCENARIOS: dict[str, Scenario] = {s.detection_id: s for s in [
    Scenario("TDL-001", "win_brute_force", "60 failed logons against one account from one external IP in three minutes"),
    Scenario("TDL-002", "password_spray", "one failed logon each against 30 accounts from one IP in eight minutes"),
    Scenario("TDL-003", "impossible_travel", "VPN logons for the same user from the US and Brazil 15 minutes apart"),
    Scenario("TDL-004", "new_admin", "account created and added to Administrators within a minute"),
    Scenario("TDL-005", "rdp_lateral", "one user RDPs to six servers in 25 minutes"),
    Scenario("TDL-006", "smb_lateral", "one workstation opens SMB to 12 peers in four minutes"),
    Scenario("TDL-007", "ps_encoded", "Word launches PowerShell with an -Enc Base64 payload"),
    Scenario("TDL-008", "schtask", "interactive user creates a scheduled task outside the Microsoft tree"),
    Scenario("TDL-009", "dns_tunnel", "40 very long TXT queries to one base domain"),
    Scenario("TDL-010", "dns_subdomains", "150 distinct subdomains of one zone in eight minutes"),
    Scenario("TDL-011", "beacon", "40 outbound connections on a 60-second timer to a listed C2 address"),
    Scenario("TDL-012", "office_shell", "Excel spawns cmd.exe and a script host"),
    Scenario("TDL-013", "rare_parent_child", "mshta.exe spawns rundll32.exe"),
    Scenario("TDL-014", "lsass_access", "unknown binary opens lsass.exe with dump-capable access masks"),
    Scenario("TDL-015", "log_cleared", "wevtutil clears the Security log (1102 follows)"),
    Scenario("TDL-016", "rare_port", "outbound connections on TCP 4444"),
    Scenario("TDL-017", "threat_intel_ip", "traffic to an address on the known-bad feed"),
    Scenario("TDL-018", "exfil_volume", "one host uploads ~520 MB in one hour"),
    Scenario("TDL-019", "runas_admin", "runas /user:CORP\\administrator from a workstation"),
    Scenario("TDL-020", "ssh_brute", "40 SSH failures from one IP against the bastion"),
    Scenario("TDL-021", "ssh_success_after_failures", "eight SSH failures followed by a password success"),
    Scenario("TDL-022", "linux_sudo_user", "useradd followed by usermod into the sudo group"),
    Scenario("TDL-023", "unsigned_dll", "unsigned DLL loaded from a Temp directory"),
    Scenario("TDL-024", "startup_folder", "PowerShell writes a .lnk into the Startup folder"),
    Scenario("TDL-025", "lolbin_dns", "powershell.exe issues DNS queries for staging domains"),
]}
SLUG_TO_ID = {s.slug: s.detection_id for s in SCENARIOS.values()}


def resolve_scenarios(selection: Iterable[str] | None) -> list[str]:
    """Normalise a scenario selection to an ordered list of detection IDs."""
    if selection is None:
        return list(SCENARIOS)
    items = [s.strip().lower() for s in selection if s and s.strip()]
    if items == ["all"]:
        return list(SCENARIOS)
    if not items or items == ["none"]:
        return []
    chosen: list[str] = []
    for item in items:
        detection_id = SLUG_TO_ID.get(item, item.upper())
        if detection_id not in SCENARIOS:
            raise ValueError(f"Unknown scenario {item!r}; use --list-scenarios")
        if detection_id not in chosen:
            chosen.append(detection_id)
    return chosen


OUTPUT_FILES = {
    "lab:windows:security": "windows_security.log",
    "lab:sysmon": "sysmon.log",
    "lab:linux:auth": "linux_auth.log",
    "lab:firewall": "firewall.log",
    "lab:dns": "dns.log",
}


def write_records(records: Iterable[Record], out_dir: Path | str, planted: Iterable[str] = ()) -> dict[str, int]:
    """Write records to one file per sourcetype plus ``scenarios.json``; return line counts."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    buckets: dict[str, list[str]] = {st: [] for st in OUTPUT_FILES}
    for record in sorted(records):
        buckets[record.sourcetype].append(record.line)
    counts: dict[str, int] = {}
    for sourcetype, filename in OUTPUT_FILES.items():
        lines = buckets[sourcetype]
        (out / filename).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        counts[filename] = len(lines)
    manifest = {
        "planted": [{"detection_id": i, "scenario": SCENARIOS[i].slug, "summary": SCENARIOS[i].summary} for i in planted],
        "files": counts,
    }
    (out / "scenarios.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return counts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic lab logs with planted attack scenarios.")
    parser.add_argument("--out", default="data/sample", help="output directory (default: data/sample)")
    parser.add_argument("--seed", type=int, default=42, help="random seed (default: 42)")
    parser.add_argument("--hours", type=int, default=24, help="hours of benign background to generate (default: 24)")
    parser.add_argument("--start", default="2026-10-14T00:00:00Z", help="UTC start timestamp of the dataset")
    parser.add_argument("--scenarios", default="all",
                        help="comma separated detection IDs or slugs, 'all' or 'none' (default: all)")
    parser.add_argument("--list-scenarios", action="store_true", help="print the scenario catalogue and exit")
    args = parser.parse_args(argv)

    if args.list_scenarios:
        for scenario in SCENARIOS.values():
            print(f"{scenario.detection_id}  {scenario.slug:<28} {scenario.summary}")
        return 0
    try:
        planted = resolve_scenarios(args.scenarios.split(","))
    except ValueError as exc:
        parser.error(str(exc))
    generator = LogGenerator(seed=args.seed, start=args.start, hours=args.hours)
    records = generator.generate(planted)
    counts = write_records(records, args.out, planted)
    total = sum(counts.values())
    print(f"wrote {total} lines to {args.out}/ (seed={args.seed}, {args.hours}h, {len(planted)} scenarios)")
    for filename, count in counts.items():
        print(f"  {filename:<22} {count:>6} lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
