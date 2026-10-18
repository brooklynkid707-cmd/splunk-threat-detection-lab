"""Search-time field extraction driven by props.conf and transforms.conf.

For each sourcetype stanza the extractor applies, in Splunk's order:

1. timestamp recognition (``TIME_PREFIX``, ``TIME_FORMAT``,
   ``MAX_TIMESTAMP_LOOKAHEAD``, ``TZ``) -> ``_time`` (epoch seconds, UTC)
2. ``EXTRACT-*`` inline regexes (named capture groups; ``in <field>`` suffix)
3. ``REPORT-*`` transforms: ``REGEX`` + ``FORMAT`` or ``DELIMS`` + ``FIELDS``
4. ``KV_MODE = auto`` key=value pairs (quoted values allowed)
5. ``FIELDALIAS-*`` (``old AS new`` pairs)
6. ``EVAL-<field>`` calculated fields (same expression engine as ``eval``)

Only the ``[sourcetype]`` style of stanza is used by this app; ``source::``
and ``host::`` stanzas are ignored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .conf import SplunkConf
from .expr import Compiled, compile_expr, is_null

Event = dict[str, Any]

_KV_RE = re.compile(r'(?P<key>[A-Za-z_][\w.\-]*)=(?:"(?P<quoted>(?:[^"\\]|\\.)*)"|(?P<bare>\S+))')

_STRPTIME_PATTERNS = {
    "Y": r"\d{4}", "y": r"\d{2}", "m": r"\d{1,2}", "d": r"\d{1,2}", "e": r"\s?\d{1,2}",
    "H": r"\d{1,2}", "M": r"\d{2}", "S": r"\d{2}", "I": r"\d{1,2}", "p": r"[AaPp][Mm]",
    "b": r"[A-Za-z]{3}", "B": r"[A-Za-z]+", "a": r"[A-Za-z]{3}", "A": r"[A-Za-z]+",
    "j": r"\d{3}", "f": r"\d{1,6}", "z": r"(?:Z|[+-]\d{2}:?\d{2})", "Z": r"[A-Z]{1,5}",
    "s": r"\d{9,10}", "%": "%",
}


def _python_named_groups(pattern: str) -> str:
    """Convert PCRE ``(?<name>`` groups to Python ``(?P<name>``."""
    return re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", pattern)


@dataclass
class TimeSpec:
    """Compiled timestamp recognition settings."""

    prefix: re.Pattern[str]
    regex: re.Pattern[str]
    strptime_format: str
    lookahead: int
    tz: timezone

    @classmethod
    def build(cls, settings: dict[str, str]) -> "TimeSpec | None":
        fmt = settings.get("TIME_FORMAT")
        if not fmt:
            return None
        fmt = re.sub(r"%(\d)N", lambda m: "%f", fmt)
        regex_parts: list[str] = []
        i = 0
        while i < len(fmt):
            ch = fmt[i]
            if ch == "%" and i + 1 < len(fmt):
                directive = fmt[i + 1]
                regex_parts.append(_STRPTIME_PATTERNS.get(directive, r"\S+"))
                i += 2
            else:
                regex_parts.append(re.escape(ch))
                i += 1
        prefix = settings.get("TIME_PREFIX", "^")
        tz_name = settings.get("TZ", "UTC").upper()
        return cls(
            prefix=re.compile(prefix),
            regex=re.compile("".join(regex_parts)),
            strptime_format=fmt,
            lookahead=int(settings.get("MAX_TIMESTAMP_LOOKAHEAD", "128")),
            tz=timezone.utc if tz_name in {"UTC", "GMT", "Z"} else timezone.utc,
        )

    def parse(self, raw: str, default_year: int | None = None) -> float | None:
        """Return the epoch timestamp found in ``raw`` or ``None``."""
        start = self.prefix.search(raw)
        if not start:
            return None
        window = raw[start.end(): start.end() + self.lookahead]
        found = self.regex.search(window)
        if not found:
            return None
        text = found.group(0)
        fmt = self.strptime_format
        if "%Y" not in fmt and "%y" not in fmt:
            year = default_year or datetime.now(tz=timezone.utc).year
            text = f"{year} {text}"
            fmt = f"%Y {fmt}"
        try:
            dt = datetime.strptime(text, fmt)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=self.tz)
        return dt.timestamp()


@dataclass
class Transform:
    """A transforms.conf field extraction stanza."""

    name: str
    regex: re.Pattern[str] | None = None
    format_pairs: list[tuple[str, str]] = field(default_factory=list)
    delims: str | None = None
    fields: list[str] = field(default_factory=list)

    @classmethod
    def build(cls, name: str, settings: dict[str, str]) -> "Transform":
        transform = cls(name)
        if "REGEX" in settings:
            transform.regex = re.compile(_python_named_groups(settings["REGEX"]))
            fmt = settings.get("FORMAT", "")
            for token in fmt.split():
                if "::" in token:
                    key, _, value = token.partition("::")
                    transform.format_pairs.append((key, value))
        if "DELIMS" in settings:
            delims = settings["DELIMS"].strip()
            transform.delims = delims.strip('"')
            transform.fields = [f.strip().strip('"') for f in settings.get("FIELDS", "").split(",") if f.strip()]
        return transform

    def apply(self, raw: str, out: Event) -> None:
        """Extract fields from ``raw`` into ``out``."""
        if self.regex is not None:
            match = self.regex.search(raw)
            if not match:
                return
            if self.format_pairs:
                for key, template in self.format_pairs:
                    key_value = re.sub(r"\$(\d+)", lambda m: match.group(int(m.group(1))) or "", key)
                    value = re.sub(r"\$(\d+)", lambda m: match.group(int(m.group(1))) or "", template)
                    _set(out, key_value, value)
            else:
                for key, value in match.groupdict().items():
                    if value is not None:
                        _set(out, key, value)
        elif self.delims is not None:
            parts = raw.split(self.delims)
            for key, value in zip(self.fields, parts):
                _set(out, key, value)


def _set(out: Event, key: str, value: str) -> None:
    """Assign a field; a repeated key becomes a multivalue list."""
    if value == "":
        return
    if key in out and out[key] != value:
        existing = out[key]
        if isinstance(existing, list):
            if value not in existing:
                existing.append(value)
        else:
            out[key] = [existing, value]
    else:
        out[key] = value


@dataclass
class SourcetypeConfig:
    """Everything needed to extract fields for one sourcetype."""

    name: str
    time_spec: TimeSpec | None
    extracts: list[tuple[re.Pattern[str], str]]
    reports: list[Transform]
    kv_mode: str
    aliases: list[tuple[str, str]]
    evals: list[tuple[str, Compiled]]


class Extractor:
    """Build field extraction rules from an app's props.conf/transforms.conf."""

    def __init__(self, props: SplunkConf, transforms: SplunkConf) -> None:
        self.transforms = {name: Transform.build(name, s) for name, s in transforms.items()
                           if "REGEX" in s or "DELIMS" in s}
        self.sourcetypes: dict[str, SourcetypeConfig] = {}
        for stanza, settings in props.items():
            if "::" in stanza or stanza == "default":
                continue
            self.sourcetypes[stanza] = self._build(stanza, settings)

    @classmethod
    def from_app(cls, app_dir: Path | str) -> "Extractor":
        """Load ``default/props.conf`` and ``default/transforms.conf``."""
        app = Path(app_dir)
        return cls(SplunkConf.load(app / "default" / "props.conf"),
                   SplunkConf.load(app / "default" / "transforms.conf"))

    def _build(self, name: str, settings: dict[str, str]) -> SourcetypeConfig:
        extracts: list[tuple[re.Pattern[str], str]] = []
        reports: list[Transform] = []
        aliases: list[tuple[str, str]] = []
        evals: list[tuple[str, Compiled]] = []
        for key, value in settings.items():
            if key.startswith("EXTRACT-"):
                source_field = "_raw"
                pattern = value
                in_match = re.search(r"\s+in\s+([\w.]+)\s*$", value)
                if in_match:
                    source_field = in_match.group(1)
                    pattern = value[: in_match.start()]
                extracts.append((re.compile(_python_named_groups(pattern)), source_field))
            elif key.startswith("REPORT-"):
                for transform_name in value.split(","):
                    transform_name = transform_name.strip()
                    if transform_name not in self.transforms:
                        raise KeyError(f"props.conf {name}/{key} references unknown transform {transform_name}")
                    reports.append(self.transforms[transform_name])
            elif key.startswith("FIELDALIAS-"):
                for old, new in re.findall(r"([\w.]+)\s+AS\s+([\w.]+)", value, re.IGNORECASE):
                    aliases.append((old, new))
            elif key.startswith("EVAL-"):
                evals.append((key[len("EVAL-"):], compile_expr(value)))
        return SourcetypeConfig(
            name=name,
            time_spec=TimeSpec.build(settings),
            extracts=extracts,
            reports=reports,
            kv_mode=settings.get("KV_MODE", "auto").lower(),
            aliases=aliases,
            evals=evals,
        )

    def extract(self, raw: str, sourcetype: str, default_year: int | None = None) -> Event:
        """Return the fields Splunk would expose for ``raw`` of ``sourcetype``."""
        config = self.sourcetypes.get(sourcetype)
        event: Event = {"_raw": raw, "sourcetype": sourcetype}
        if config is None:
            return event
        if config.time_spec is not None:
            ts = config.time_spec.parse(raw, default_year)
            if ts is not None:
                event["_time"] = ts
        for regex, source_field in config.extracts:
            subject = event.get(source_field)
            if subject is None:
                continue
            match = regex.search(str(subject))
            if match:
                for key, value in match.groupdict().items():
                    if value is not None:
                        _set(event, key, value)
        for transform in config.reports:
            transform.apply(raw, event)
        if config.kv_mode == "auto":
            for match in _KV_RE.finditer(raw):
                value = match.group("quoted")
                if value is not None:
                    value = value.replace('\\"', '"')
                else:
                    value = match.group("bare")
                _set(event, match.group("key"), value)
        for old, new in config.aliases:
            if old in event and new not in event:
                event[new] = event[old]
        for name, fn in config.evals:
            value = fn(event)
            if not is_null(value):
                event[name] = value
        return event
