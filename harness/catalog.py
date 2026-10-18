"""Detection catalogue: every stanza in savedsearches.conf as a typed object.

The catalogue is the single source of truth that ``run_detections.py``, the
tests, ``scripts/attack_coverage.py`` and the per-detection docs all read, so
adding a detection means adding one stanza to savedsearches.conf and one
planted scenario to ``scripts/generate_logs.py`` - nothing else.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import APP_DIR
from .conf import SplunkConf, is_true

SEVERITY_NAMES = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}

# Which data-source macro a search uses -> human readable data source.
DATA_SOURCE_MACROS = {
    "wineventlog_security": "Windows Security event log",
    "sysmon": "Sysmon operational log",
    "process_creation": "Windows 4688 + Sysmon 1 process creation",
    "linux_auth": "Linux auth.log (sshd, sudo, useradd, usermod)",
    "firewall": "Edge firewall connection log",
    "dns": "Resolver DNS query log",
}

# Tactic per technique prefix. Sub-techniques inherit their parent's tactic.
TECHNIQUE_TACTICS: dict[str, str] = {
    "T1110": "Credential Access", "T1003": "Credential Access",
    "T1078": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
    "T1136": "Persistence", "T1098": "Persistence", "T1053": "Execution / Persistence / Privilege Escalation",
    "T1547": "Persistence / Privilege Escalation", "T1574": "Persistence / Privilege Escalation / Defense Evasion",
    "T1548": "Privilege Escalation / Defense Evasion", "T1021": "Lateral Movement",
    "T1059": "Execution", "T1204": "Execution", "T1566": "Initial Access",
    "T1027": "Defense Evasion", "T1218": "Defense Evasion", "T1070": "Defense Evasion",
    "T1071": "Command and Control", "T1571": "Command and Control", "T1095": "Command and Control",
    "T1105": "Command and Control", "T1048": "Exfiltration", "T1041": "Exfiltration",
}

TECHNIQUE_NAMES: dict[str, str] = {
    "T1110": "Brute Force", "T1110.001": "Brute Force: Password Guessing", "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts", "T1078.002": "Valid Accounts: Domain Accounts", "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1136.001": "Create Account: Local Account", "T1098": "Account Manipulation",
    "T1053.005": "Scheduled Task/Job: Scheduled Task", "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1574.001": "Hijack Execution Flow: DLL Search Order Hijacking", "T1574.002": "Hijack Execution Flow: DLL Side-Loading",
    "T1548": "Abuse Elevation Control Mechanism", "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1021.001": "Remote Services: Remote Desktop Protocol", "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1059": "Command and Scripting Interpreter", "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1027.010": "Obfuscated Files or Information: Command Obfuscation", "T1566.001": "Phishing: Spearphishing Attachment",
    "T1204.002": "User Execution: Malicious File", "T1218": "System Binary Proxy Execution",
    "T1003.001": "OS Credential Dumping: LSASS Memory", "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1071": "Application Layer Protocol", "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS", "T1048": "Exfiltration Over Alternative Protocol",
    "T1048.003": "Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol", "T1041": "Exfiltration Over C2 Channel",
    "T1571": "Non-Standard Port", "T1095": "Non-Application Layer Protocol", "T1105": "Ingress Tool Transfer",
}

_STANZA_RE = re.compile(r"^(?P<id>TDL-\d{3})\s+(?P<name>.+)$")
_MACRO_RE = re.compile(r"`(\w+)")


@dataclass
class Detection:
    """One scheduled detection from savedsearches.conf."""

    id: str
    name: str
    description: str
    spl: str
    severity: int
    cron_schedule: str
    earliest: str
    latest: str
    enabled: bool
    mitre_attack: list[str] = field(default_factory=list)
    nist: list[str] = field(default_factory=list)
    label: str = ""
    suppress_fields: list[str] = field(default_factory=list)
    suppress_period: str = ""
    macros: list[str] = field(default_factory=list)

    @property
    def severity_name(self) -> str:
        return SEVERITY_NAMES.get(self.severity, str(self.severity))

    @property
    def stanza(self) -> str:
        """The exact ``[stanza]`` name in savedsearches.conf."""
        return f"{self.id} {self.name}"

    @property
    def slug(self) -> str:
        """``tdl-001-windows-brute-force`` style file name component."""
        text = re.sub(r"[^a-z0-9]+", "-", self.name.lower()).strip("-")
        return f"{self.id.lower()}-{text}"

    @property
    def data_sources(self) -> list[str]:
        return [DATA_SOURCE_MACROS[m] for m in self.macros if m in DATA_SOURCE_MACROS]

    @property
    def tactics(self) -> list[str]:
        seen: list[str] = []
        for technique in self.mitre_attack:
            tactic = TECHNIQUE_TACTICS.get(technique.split(".")[0], "Unknown")
            if tactic not in seen:
                seen.append(tactic)
        return seen

    def technique_name(self, technique: str) -> str:
        return TECHNIQUE_NAMES.get(technique, technique)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "severity": self.severity, "severity_name": self.severity_name,
            "mitre_attack": self.mitre_attack, "nist": self.nist, "tactics": self.tactics,
            "data_sources": self.data_sources, "cron_schedule": self.cron_schedule, "enabled": self.enabled,
        }


def _parse_annotations(text: str | None) -> dict[str, list[str]]:
    if not text:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Bad correlationsearch annotations JSON: {text}") from exc
    return {k: list(v) for k, v in data.items()}


def load_catalog(app_dir: Path | str = APP_DIR) -> list[Detection]:
    """Parse ``default/savedsearches.conf`` into :class:`Detection` objects, sorted by ID."""
    conf = SplunkConf.load(Path(app_dir) / "default" / "savedsearches.conf")
    detections: list[Detection] = []
    for stanza, settings in conf.items():
        match = _STANZA_RE.match(stanza)
        if not match or "search" not in settings:
            continue
        annotations = _parse_annotations(settings.get("action.correlationsearch.annotations"))
        spl = settings["search"]
        detections.append(Detection(
            id=match.group("id"),
            name=match.group("name").strip(),
            description=settings.get("description", "").strip(),
            spl=spl,
            severity=int(settings.get("alert.severity", "3")),
            cron_schedule=settings.get("cron_schedule", ""),
            earliest=settings.get("dispatch.earliest_time", ""),
            latest=settings.get("dispatch.latest_time", "now"),
            enabled=is_true(settings.get("enableSched"), default=False) and not is_true(settings.get("disabled")),
            mitre_attack=annotations.get("mitre_attack", []),
            nist=annotations.get("nist", []),
            label=settings.get("action.correlationsearch.label", ""),
            suppress_fields=[f.strip() for f in settings.get("alert.suppress.fields", "").split(",") if f.strip()],
            suppress_period=settings.get("alert.suppress.period", ""),
            macros=sorted(set(_MACRO_RE.findall(spl))),
        ))
    detections.sort(key=lambda d: d.id)
    return detections


def catalog_by_id(app_dir: Path | str = APP_DIR) -> dict[str, Detection]:
    """``{"TDL-001": Detection, ...}``."""
    return {d.id: d for d in load_catalog(app_dir)}
