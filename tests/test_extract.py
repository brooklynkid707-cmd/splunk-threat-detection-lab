"""Search-time field extraction per sourcetype (props.conf + transforms.conf)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from harness.loader import SOURCE_MAP, EventLoader

EPOCH = datetime(2026, 10, 14, 2, 11, 5, tzinfo=timezone.utc).timestamp()


def test_windows_security_logon_failure(loader: EventLoader) -> None:
    raw = ("2026-10-14T02:11:05Z host=DC-01 EventCode=4625 Account_Name=svc_backup Account_Domain=CORP Logon_Type=3 "
           "Source_Network_Address=203.0.113.45 Workstation_Name=KALI Status=0xC000006D Sub_Status=0xC000006A "
           'Failure_Reason="Unknown user name or bad password."')
    ev = loader.parse_lines([raw], "lab:windows:security")[0]
    assert ev["_time"] == EPOCH
    assert ev["index"] == "lab_windows"
    assert ev["EventCode"] == "4625"
    # CIM style aliases
    assert ev["user"] == "svc_backup"
    assert ev["src_ip"] == "203.0.113.45"
    assert ev["dest"] == "DC-01"
    assert ev["logon_type"] == "3"
    # quoted value with spaces survives KV_MODE=auto
    assert ev["Failure_Reason"] == "Unknown user name or bad password."
    # calculated fields
    assert ev["action"] == "failure"
    assert ev["signature"] == "An account failed to log on"


def test_windows_process_creation_aliases(loader: EventLoader) -> None:
    raw = ('2026-10-14T09:47:00Z host=WS-HR-03 EventCode=4688 Account_Name=onelson New_Process_Name="C:\\Windows\\System32\\cmd.exe" '
           'Creator_Process_Name=C:\\Windows\\explorer.exe Process_Command_Line="cmd.exe /c whoami"')
    ev = loader.parse_lines([raw], "lab:windows:security")[0]
    assert ev["process"] == "C:\\Windows\\System32\\cmd.exe"
    assert ev["parent_process"] == "C:\\Windows\\explorer.exe"
    assert ev["process_cmdline"] == "cmd.exe /c whoami"
    assert ev["signature"] == "A new process has been created"


def test_sysmon_process_fields(loader: EventLoader) -> None:
    raw = ('2026-10-14T09:47:00Z host=WS-HR-03 EventCode=1 Image="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" '
           'CommandLine="\\"WINWORD.EXE\\" /n report.docx" User=CORP\\onelson ParentImage=C:\\Windows\\explorer.exe')
    ev = loader.parse_lines([raw], "lab:sysmon")[0]
    assert ev["index"] == "lab_sysmon"
    assert ev["process"].endswith("WINWORD.EXE")
    assert ev["process_cmdline"] == '"WINWORD.EXE" /n report.docx'
    assert ev["user"] == "CORP\\onelson"
    assert ev["parent_process"] == "C:\\Windows\\explorer.exe"
    assert ev["process_name"] == "winword.exe"
    assert ev["parent_process_name"] == "explorer.exe"


def test_sysmon_network_and_dns_aliases(loader: EventLoader) -> None:
    net = ("2026-10-14T10:31:00Z host=WS-FIN-07 EventCode=3 Image=C:\\Windows\\System32\\net.exe Protocol=tcp Initiated=true "
           "SourceIp=10.20.1.55 SourcePort=50001 DestinationIp=10.10.0.21 DestinationPort=445 DestinationHostname=FS-02")
    dns = "2026-10-14T10:31:00Z host=WS-HR-03 EventCode=22 QueryName=cdn-stage.example.net QueryStatus=0 Image=C:\\x\\powershell.exe"
    net_ev, dns_ev = loader.parse_lines([net, dns], "lab:sysmon")
    assert (net_ev["src_ip"], net_ev["dest_ip"], net_ev["dest_port"], net_ev["dest"]) == ("10.20.1.55", "10.10.0.21", "445", "FS-02")
    assert dns_ev["query"] == "cdn-stage.example.net"


@pytest.mark.parametrize("raw,expected", [
    ("2026-10-14T02:11:05+00:00 srv-web-01 sshd[2211]: Failed password for root from 203.0.113.9 port 51234 ssh2",
     {"host": "srv-web-01", "process": "sshd", "pid": "2211", "action": "Failed", "auth_method": "password",
      "user": "root", "src_ip": "203.0.113.9", "src_port": "51234", "dest": "srv-web-01"}),
    ("2026-10-14T02:11:05+00:00 srv-web-01 sshd[2212]: Failed password for invalid user oracle from 192.0.2.7 port 4000 ssh2",
     {"action": "Failed", "user": "oracle", "invalid_user": "invalid user"}),
    ("2026-10-14T02:11:05+00:00 srv-web-01 sshd[2213]: Accepted publickey for mchen from 10.20.2.49 port 4001 ssh2",
     {"action": "Accepted", "auth_method": "publickey", "user": "mchen"}),
    ("2026-10-14T02:11:05+00:00 srv-app-01 sudo:     deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/sbin/useradd -m svcmon",
     {"process": "sudo", "user": "deploy", "run_as": "root", "command": "/usr/sbin/useradd -m svcmon"}),
    ("2026-10-14T02:11:05+00:00 srv-app-01 useradd[4101]: new user: name=svcmon, UID=1007, GID=1007, home=/home/svcmon, shell=/bin/bash",
     {"process": "useradd", "new_user": "svcmon", "uid": "1007", "shell": "/bin/bash"}),
    ("2026-10-14T02:11:05+00:00 srv-app-01 usermod[4102]: add 'svcmon' to group 'sudo'",
     {"process": "usermod", "mod_user": "svcmon", "group": "sudo"}),
])
def test_linux_auth_extractions(loader: EventLoader, raw: str, expected: dict[str, str]) -> None:
    ev = loader.parse_lines([raw], "lab:linux:auth")[0]
    assert ev["_time"] == EPOCH
    for key, value in expected.items():
        assert ev.get(key) == value, key


def test_firewall_pipe_delimited(loader: EventLoader) -> None:
    raw = "2026-10-14T02:11:05Z|FW-EDGE-01|allow|outbound|10.20.1.55|52344|203.0.113.50|443|tcp|1532|84211"
    ev = loader.parse_lines([raw], "lab:firewall")[0]
    assert ev["_time"] == EPOCH
    assert ev["index"] == "lab_network"
    assert (ev["host"], ev["action"], ev["direction"]) == ("FW-EDGE-01", "allow", "outbound")
    assert (ev["src_ip"], ev["dest_ip"], ev["dest_port"], ev["protocol"]) == ("10.20.1.55", "203.0.113.50", "443", "tcp")
    assert ev["bytes"] == 1532 + 84211
    assert ev["dest"] == "203.0.113.50" and ev["src"] == "10.20.1.55"


def test_dns_bind_query_log(loader: EventLoader) -> None:
    raw = "14-Oct-2026 02:11:05.117 client 10.20.1.55#51234: query: www.example.com IN A + (10.10.0.53)"
    ev = loader.parse_lines([raw], "lab:dns")[0]
    assert ev["_time"] == pytest.approx(EPOCH + 0.117)  # %3N milliseconds are kept
    assert ev["host"] == "DNS-01"
    assert (ev["src_ip"], ev["src_port"], ev["query"], ev["record_type"]) == ("10.20.1.55", "51234", "www.example.com", "A")
    assert ev["dest_ip"] == "10.10.0.53"
    assert ev["query_length"] == len("www.example.com")


def test_unknown_timestamp_is_rejected(loader: EventLoader) -> None:
    with pytest.raises(ValueError):
        loader.parse_lines(["garbage line with no timestamp"], "lab:firewall")


def test_sample_dataset_loads_every_sourcetype(loader: EventLoader) -> None:
    from harness import DEFAULT_DATA_DIR
    events = loader.load_dir(DEFAULT_DATA_DIR)
    assert len(events) > 5000
    assert {e["sourcetype"] for e in events} == {v[1] for v in SOURCE_MAP.values()}
    assert all("_time" in e and "host" in e for e in events)
    assert events == sorted(events, key=lambda e: e["_time"])
