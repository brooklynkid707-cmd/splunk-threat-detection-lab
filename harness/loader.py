"""Turn synthetic log files into Splunk-style events.

The file name -> (index, sourcetype, host) mapping mirrors the monitor
stanzas in ``TA-threat-detection/default/inputs.conf``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from . import APP_DIR
from .extract import Extractor

Event = dict[str, Any]

# basename -> (index, sourcetype, default host)
SOURCE_MAP: dict[str, tuple[str, str, str | None]] = {
    "windows_security.log": ("lab_windows", "lab:windows:security", None),
    "sysmon.log": ("lab_sysmon", "lab:sysmon", None),
    "linux_auth.log": ("lab_linux", "lab:linux:auth", None),
    "firewall.log": ("lab_network", "lab:firewall", "FW-EDGE-01"),
    "dns.log": ("lab_network", "lab:dns", "DNS-01"),
}

SOURCETYPE_TO_FILE = {v[1]: k for k, v in SOURCE_MAP.items()}


class EventLoader:
    """Parse raw lines into events using the app's extraction rules."""

    def __init__(self, app_dir: Path | str = APP_DIR) -> None:
        self.app_dir = Path(app_dir)
        self.extractor = Extractor.from_app(self.app_dir)

    def parse_lines(self, lines: Iterable[str], sourcetype: str, index: str | None = None,
                    source: str | None = None, host: str | None = None) -> list[Event]:
        """Parse ``lines`` of ``sourcetype`` into fully extracted events."""
        if index is None:
            basename = SOURCETYPE_TO_FILE.get(sourcetype, "")
            index = SOURCE_MAP.get(basename, ("main", sourcetype, None))[0]
            host = host or SOURCE_MAP.get(basename, ("", "", None))[2]
        events: list[Event] = []
        for line in lines:
            raw = line.rstrip("\r\n")
            if not raw.strip():
                continue
            event = self.extractor.extract(raw, sourcetype)
            event["index"] = index
            event["source"] = source or SOURCETYPE_TO_FILE.get(sourcetype, sourcetype)
            if "host" not in event and host:
                event["host"] = host
            if "_time" not in event:
                raise ValueError(f"No timestamp recognised for {sourcetype}: {raw[:80]!r}")
            events.append(event)
        return events

    def load_file(self, path: Path | str) -> list[Event]:
        """Load one log file whose basename is in :data:`SOURCE_MAP`."""
        path = Path(path)
        if path.name not in SOURCE_MAP:
            raise ValueError(f"Unknown log file {path.name}; expected one of {sorted(SOURCE_MAP)}")
        index, sourcetype, host = SOURCE_MAP[path.name]
        with path.open(encoding="utf-8") as handle:
            return self.parse_lines(handle, sourcetype, index, path.name, host)

    def load_dir(self, data_dir: Path | str) -> list[Event]:
        """Load every known log file in ``data_dir`` and sort by ``_time``."""
        data_dir = Path(data_dir)
        events: list[Event] = []
        for name in SOURCE_MAP:
            path = data_dir / name
            if path.exists():
                events.extend(self.load_file(path))
        events.sort(key=lambda e: e["_time"])
        return events
