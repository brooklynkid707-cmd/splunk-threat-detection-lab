#!/usr/bin/env python3
"""Run every detection in savedsearches.conf over a directory of lab logs.

Example::

    python -m harness.run_detections                       # data/sample, expect scenarios.json
    python -m harness.run_detections --data /tmp/benign --expect none
    python -m harness.run_detections --json results.json --only TDL-007,TDL-012

Exit status is 1 when a detection that was expected to fire produced no
rows, or when a search fails to execute; 0 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import APP_DIR, DEFAULT_DATA_DIR
from .catalog import Detection, load_catalog
from .loader import EventLoader
from .spl import Pipeline, SPLEnvironment, SPLError

# Result columns that identify "who/what" an alert is about, in display priority.
ENTITY_FIELDS = ["user", "target_user", "src_ip", "host", "dest", "dest_ip", "dest_port", "base_domain",
                 "SourceImage", "ImageLoaded", "process", "parent_name", "child_name", "TargetFilename", "task"]


@dataclass
class DetectionResult:
    """Outcome of running one detection."""

    detection: Detection
    rows: list[dict[str, Any]]
    seconds: float
    expected: bool
    error: str | None = None
    entities: list[str] = field(default_factory=list)

    @property
    def fired(self) -> bool:
        return bool(self.rows)

    @property
    def status(self) -> str:
        if self.error:
            return "ERROR"
        if self.fired and self.expected:
            return "PASS"
        if self.fired:
            return "FIRED"
        if self.expected:
            return "MISSED"
        return "quiet"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.detection.id, "name": self.detection.name, "severity": self.detection.severity_name,
            "mitre_attack": self.detection.mitre_attack, "expected": self.expected, "fired": self.fired,
            "status": self.status, "result_count": len(self.rows), "entities": self.entities,
            "seconds": round(self.seconds, 3), "error": self.error, "results": self.rows,
        }


def _text(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(v) for v in value[:3]) + ("..." if len(value) > 3 else "")
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def summarise_entities(rows: list[dict[str, Any]], limit: int = 3) -> list[str]:
    """Build short ``field=value`` descriptions of the entities in result rows."""
    out: list[str] = []
    for row in rows[:limit]:
        parts = [f"{f}={_text(row[f])}" for f in ENTITY_FIELDS if f in row][:3]
        if parts:
            out.append(" ".join(parts))
    if len(rows) > limit:
        out.append(f"(+{len(rows) - limit} more)")
    return out


def load_expected(data_dir: Path, expect: str | None) -> set[str]:
    """Resolve which detections must fire: ``--expect`` wins, else ``scenarios.json``, else none."""
    if expect:
        if expect.lower() == "all":
            return {"*"}
        if expect.lower() == "none":
            return set()
        return {e.strip().upper() for e in expect.split(",") if e.strip()}
    manifest = data_dir / "scenarios.json"
    if manifest.exists():
        data = json.loads(manifest.read_text(encoding="utf-8"))
        return {entry["detection_id"] for entry in data.get("planted", [])}
    return set()


def run_all(data_dir: Path, expected: set[str], only: set[str] | None = None,
            app_dir: Path = APP_DIR) -> tuple[list[DetectionResult], int]:
    """Run every (selected) detection and return results plus the event count."""
    events = EventLoader(app_dir).load_dir(data_dir)
    pipeline = Pipeline(SPLEnvironment.from_app(app_dir))
    results: list[DetectionResult] = []
    for detection in load_catalog(app_dir):
        if only and detection.id not in only:
            continue
        is_expected = "*" in expected or detection.id in expected
        started = time.perf_counter()
        try:
            rows = pipeline.run(detection.spl, events)
            result = DetectionResult(detection, rows, time.perf_counter() - started, is_expected)
            result.entities = summarise_entities(rows)
        except SPLError as exc:
            result = DetectionResult(detection, [], time.perf_counter() - started, is_expected, error=str(exc))
        results.append(result)
    return results, len(events)


def render_table(results: list[DetectionResult], event_count: int, data_dir: Path) -> str:
    """Plain-text report."""
    lines = [f"Detections over {event_count} events from {data_dir}", ""]
    header = f"{'ID':<8} {'Status':<7} {'Sev':<9} {'Rows':>4}  {'Detection':<58} Entities"
    lines.append(header)
    lines.append("-" * len(header))
    for r in results:
        name = r.detection.name if len(r.detection.name) <= 58 else r.detection.name[:55] + "..."
        first = r.entities[0] if r.entities else (r.error or "-")
        lines.append(f"{r.detection.id:<8} {r.status:<7} {r.detection.severity_name:<9} {len(r.rows):>4}  {name:<58} {first}")
        for extra in r.entities[1:]:
            lines.append(f"{'':<8} {'':<7} {'':<9} {'':>4}  {'':<58} {extra}")
    fired = sum(1 for r in results if r.fired)
    missed = [r.detection.id for r in results if r.status == "MISSED"]
    errors = [r.detection.id for r in results if r.error]
    unexpected = [r.detection.id for r in results if r.status == "FIRED"]
    total = sum(r.seconds for r in results)
    lines.append("")
    lines.append(f"{fired}/{len(results)} detections fired, {sum(len(r.rows) for r in results)} result rows, {total:.1f}s search time")
    if unexpected:
        lines.append(f"Fired without being expected: {', '.join(unexpected)}")
    if missed:
        lines.append(f"MISSED (expected but produced no rows): {', '.join(missed)}")
    if errors:
        lines.append(f"ERRORS: {', '.join(errors)}")
    if not missed and not errors:
        lines.append("All expected detections fired.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data", default=str(DEFAULT_DATA_DIR), help="directory holding the five *.log files")
    parser.add_argument("--app", default=str(APP_DIR), help="path to the TA-threat-detection app")
    parser.add_argument("--expect", help="comma separated detection IDs that must fire, 'all' or 'none' "
                                         "(default: the planted list in <data>/scenarios.json)")
    parser.add_argument("--only", help="comma separated detection IDs to run (default: all)")
    parser.add_argument("--json", metavar="FILE", help="also write full results (including rows) as JSON; '-' for stdout")
    parser.add_argument("--quiet", action="store_true", help="suppress the text table")
    args = parser.parse_args(argv)

    data_dir = Path(args.data)
    app_dir = Path(args.app)
    expected = load_expected(data_dir, args.expect)
    only = {o.strip().upper() for o in args.only.split(",") if o.strip()} if args.only else None
    results, event_count = run_all(data_dir, expected, only, app_dir)

    if not args.quiet and args.json != "-":
        print(render_table(results, event_count, data_dir))
    if args.json:
        payload = {"data_dir": str(data_dir), "events": event_count, "detections": [r.to_dict() for r in results]}
        text = json.dumps(payload, indent=2, default=str)
        if args.json == "-":
            print(text)
        else:
            Path(args.json).write_text(text + "\n", encoding="utf-8")
            if not args.quiet:
                print(f"JSON written to {args.json}")
    failed = any(r.status in {"MISSED", "ERROR"} for r in results)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
