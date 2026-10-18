"""CSV lookup tables as defined in transforms.conf.

Supports the lookup features the detections rely on: case-insensitive exact
matching (Splunk's default), ``match_type = CIDR(field)`` for IP ranges and
``match_type = WILDCARD(field)`` for glob patterns.
"""

from __future__ import annotations

import csv
import ipaddress
import re
from pathlib import Path

from .conf import SplunkConf, is_true

Row = dict[str, str]


class LookupTable:
    """One CSV lookup plus its matching rules."""

    def __init__(self, name: str, rows: list[Row], fieldnames: list[str],
                 cidr_fields: set[str] | None = None, wildcard_fields: set[str] | None = None,
                 case_sensitive: bool = False) -> None:
        self.name = name
        self.rows = rows
        self.fieldnames = fieldnames
        self.cidr_fields = cidr_fields or set()
        self.wildcard_fields = wildcard_fields or set()
        self.case_sensitive = case_sensitive
        self._networks: dict[tuple[str, str], ipaddress.IPv4Network | ipaddress.IPv6Network | None] = {}

    def _network(self, field: str, text: str):
        key = (field, text)
        if key not in self._networks:
            try:
                self._networks[key] = ipaddress.ip_network(text, strict=False)
            except ValueError:
                self._networks[key] = None
        return self._networks[key]

    def _field_matches(self, field: str, table_value: str, event_value: str) -> bool:
        if field in self.cidr_fields:
            network = self._network(field, table_value)
            if network is None:
                return False
            try:
                return ipaddress.ip_address(event_value) in network
            except ValueError:
                return False
        if field in self.wildcard_fields:
            regex = "^" + ".*".join(re.escape(part) for part in table_value.split("*")) + "$"
            return re.match(regex, event_value, 0 if self.case_sensitive else re.IGNORECASE) is not None
        if self.case_sensitive:
            return table_value == event_value
        return table_value.lower() == event_value.lower()

    def match(self, criteria: dict[str, str]) -> Row | None:
        """Return the first row where every ``criteria`` field matches."""
        best: Row | None = None
        best_prefix = -1
        for row in self.rows:
            if all(self._field_matches(f, row.get(f, ""), v) for f, v in criteria.items()):
                # For CIDR lookups prefer the most specific network (longest prefix).
                prefix = 0
                for field in criteria:
                    if field in self.cidr_fields:
                        network = self._network(field, row.get(field, ""))
                        prefix = max(prefix, network.prefixlen if network else 0)
                if prefix > best_prefix:
                    best, best_prefix = row, prefix
                if not self.cidr_fields:
                    return row
        return best


_MATCH_TYPE_RE = re.compile(r"(CIDR|WILDCARD)\(([^)]+)\)", re.IGNORECASE)


def load_lookups(transforms: SplunkConf, lookups_dir: Path) -> dict[str, LookupTable]:
    """Build every lookup declared with ``filename`` in transforms.conf."""
    tables: dict[str, LookupTable] = {}
    for name, settings in transforms.items():
        filename = settings.get("filename")
        if not filename:
            continue
        path = lookups_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Lookup {name} references missing file {path}")
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            fieldnames = list(reader.fieldnames or [])
            rows = [dict(r) for r in reader]
        cidr: set[str] = set()
        wildcard: set[str] = set()
        for kind, fields in _MATCH_TYPE_RE.findall(settings.get("match_type", "")):
            target = cidr if kind.upper() == "CIDR" else wildcard
            target.update(f.strip() for f in fields.split(","))
        tables[name] = LookupTable(name, rows, fieldnames, cidr, wildcard,
                                   is_true(settings.get("case_sensitive_match"), default=False))
    return tables
