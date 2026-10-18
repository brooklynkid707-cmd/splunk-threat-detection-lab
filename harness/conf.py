"""Parser for Splunk ``.conf`` files.

Splunk conf files are INI-like with three quirks that matter here:

* a line ending in a backslash continues on the next line (used heavily for
  multi-line ``search =`` values in savedsearches.conf);
* backslashes are otherwise literal, so regexes and Windows paths are stored
  exactly as written;
* a stanza may be the empty string ``[]`` (metadata files).
"""

from __future__ import annotations

from pathlib import Path


class SplunkConf:
    """An ordered mapping of stanza name -> {key: value}."""

    def __init__(self) -> None:
        self.stanzas: dict[str, dict[str, str]] = {}

    @classmethod
    def load(cls, path: Path | str) -> "SplunkConf":
        """Parse ``path`` and return a :class:`SplunkConf`."""
        conf = cls()
        conf.parse(Path(path).read_text(encoding="utf-8"))
        return conf

    def parse(self, text: str) -> None:
        """Parse conf text into :attr:`stanzas` (appending to existing ones)."""
        current: dict[str, str] | None = None
        logical_lines: list[str] = []
        buffer = ""
        continuing = False
        for raw_line in text.splitlines():
            line = raw_line.rstrip("\r")
            if continuing:
                buffer += line
            else:
                buffer = line
            if buffer.endswith("\\") and not buffer.endswith("\\\\"):
                buffer = buffer[:-1]
                continuing = True
                continue
            continuing = False
            logical_lines.append(buffer)
        if continuing:
            logical_lines.append(buffer)

        for line in logical_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                name = stripped[1:-1]
                current = self.stanzas.setdefault(name, {})
                continue
            if "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            if current is None:
                current = self.stanzas.setdefault("default", {})
            current[key.strip()] = value.strip()

    def get(self, stanza: str, key: str, default: str | None = None) -> str | None:
        """Return ``stanza/key`` or ``default``."""
        return self.stanzas.get(stanza, {}).get(key, default)

    def __contains__(self, stanza: str) -> bool:
        return stanza in self.stanzas

    def __getitem__(self, stanza: str) -> dict[str, str]:
        return self.stanzas[stanza]

    def items(self):
        """Iterate ``(stanza, settings)`` pairs in file order."""
        return self.stanzas.items()


def is_true(value: str | None, default: bool = False) -> bool:
    """Interpret Splunk boolean spellings (1/0, true/false, t/f, yes/no)."""
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "t", "yes", "y", "on"}
