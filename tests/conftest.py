"""Shared fixtures: the app, the evaluator and in-memory synthetic datasets."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from harness import APP_DIR  # noqa: E402
from harness.catalog import Detection, load_catalog  # noqa: E402
from harness.loader import EventLoader  # noqa: E402
from harness.spl import Pipeline, SPLEnvironment  # noqa: E402
from generate_logs import OUTPUT_FILES, LogGenerator, Record  # noqa: E402

Event = dict[str, Any]
SEED = 42


def records_to_events(loader: EventLoader, records: list[Record]) -> list[Event]:
    """Parse generator records with the app's extraction rules, like Splunk would."""
    events: list[Event] = []
    for sourcetype in OUTPUT_FILES:
        lines = [r.line for r in records if r.sourcetype == sourcetype]
        events.extend(loader.parse_lines(lines, sourcetype))
    events.sort(key=lambda e: e["_time"])
    return events


@pytest.fixture(scope="session")
def loader() -> EventLoader:
    return EventLoader(APP_DIR)


@pytest.fixture(scope="session")
def pipeline() -> Pipeline:
    return Pipeline(SPLEnvironment.from_app(APP_DIR))


@pytest.fixture(scope="session")
def catalog() -> list[Detection]:
    return load_catalog(APP_DIR)


@pytest.fixture(scope="session")
def catalog_by_id(catalog: list[Detection]) -> dict[str, Detection]:
    return {d.id: d for d in catalog}


@pytest.fixture(scope="session")
def benign_events(loader: EventLoader) -> list[Event]:
    """A full day of benign background with no scenarios planted."""
    return records_to_events(loader, LogGenerator(seed=SEED).generate([]))


def scenario_events(loader: EventLoader, detection_id: str) -> list[Event]:
    """Only the planted records for one detection (no background)."""
    from generate_logs import SCENARIOS
    generator = LogGenerator(seed=SEED)
    method = getattr(generator, f"scenario_{SCENARIOS[detection_id].slug}")
    return records_to_events(loader, method())
