"""Every detection fires on its planted scenario and stays quiet on benign data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import scenario_events
from harness import DEFAULT_DATA_DIR
from harness.catalog import Detection
from harness.loader import EventLoader
from harness.run_detections import load_expected, main, run_all, summarise_entities
from harness.spl import Pipeline
from generate_logs import SCENARIOS

DETECTION_IDS = [f"TDL-{n:03d}" for n in range(1, 26)]

# Entity values that the planted scenario in scripts/generate_logs.py must surface.
EXPECTED_ENTITY: dict[str, tuple[str, str]] = {
    "TDL-001": ("src_ip", "203.0.113.45"), "TDL-002": ("src_ip", "198.51.100.23"), "TDL-003": ("user", "mchen"),
    "TDL-004": ("target_user", "backupadm"), "TDL-005": ("user", "mchen"), "TDL-006": ("host", "WS-FIN-07"),
    "TDL-007": ("host", "WS-HR-03"), "TDL-008": ("host", "WS-FIN-07"), "TDL-009": ("base_domain", "example.net"),
    "TDL-010": ("base_domain", "example.org"), "TDL-011": ("dest_ip", "203.0.113.66"), "TDL-012": ("host", "WS-FIN-02"),
    "TDL-013": ("parent_name", "mshta.exe"), "TDL-014": ("SourceImage", "C:\\Windows\\Temp\\pd.exe"),
    "TDL-015": ("host", "WS-FIN-07"), "TDL-016": ("dest_port", "4444"), "TDL-017": ("dest_ip", "198.51.100.251"),
    "TDL-018": ("dest_ips", "203.0.113.37"), "TDL-019": ("target_account", "CORP\\administrator"),
    "TDL-020": ("src_ip", "192.0.2.77"), "TDL-021": ("src_ip", "203.0.113.90"), "TDL-022": ("target_user", "svcmon"),
    "TDL-023": ("ImageLoaded", "C:\\Users\\lwright\\AppData\\Local\\Temp\\version.dll"),
    "TDL-024": ("host", "WS-ENG-05"), "TDL-025": ("host", "WS-HR-03"),
}


def test_one_scenario_per_detection() -> None:
    assert list(SCENARIOS) == DETECTION_IDS


@pytest.mark.parametrize("detection_id", DETECTION_IDS)
def test_detection_fires_on_planted_scenario(detection_id: str, catalog_by_id: dict[str, Detection],
                                             pipeline: Pipeline, loader: EventLoader, benign_events: list[dict]) -> None:
    detection = catalog_by_id[detection_id]
    events = sorted(benign_events + scenario_events(loader, detection_id), key=lambda e: e["_time"])
    rows = pipeline.run(detection.spl, events)
    assert rows, f"{detection_id} produced no rows on benign + its scenario"
    field_name, value = EXPECTED_ENTITY[detection_id]
    found = {str(v) for row in rows for v in (row.get(field_name) if isinstance(row.get(field_name), list) else [row.get(field_name)])}
    assert value in found, f"{detection_id}: expected {field_name}={value!r} in {found}"


@pytest.mark.parametrize("detection_id", DETECTION_IDS)
def test_detection_is_quiet_on_benign_data(detection_id: str, catalog_by_id: dict[str, Detection],
                                           pipeline: Pipeline, benign_events: list[dict]) -> None:
    rows = pipeline.run(catalog_by_id[detection_id].spl, benign_events)
    assert rows == [], f"{detection_id} fired on benign-only data: {rows[:2]}"


def test_scenario_alone_is_enough(catalog_by_id: dict[str, Detection], pipeline: Pipeline, loader: EventLoader) -> None:
    """Thresholds are met by the planted events themselves, not by background noise.

    TDL-018 is deliberately absent: it compares an hour against the host's own
    baseline, so it needs the benign background to have anything to baseline.
    """
    for detection_id in ("TDL-001", "TDL-009", "TDL-011", "TDL-020"):
        assert pipeline.run(catalog_by_id[detection_id].spl, scenario_events(loader, detection_id)), detection_id


def test_run_all_on_committed_sample() -> None:
    expected = load_expected(DEFAULT_DATA_DIR, None)
    assert expected == set(DETECTION_IDS)
    results, count = run_all(DEFAULT_DATA_DIR, expected)
    assert count > 5000
    assert [r.status for r in results] == ["PASS"] * 25
    assert all(r.entities for r in results)


def test_cli_exit_codes_and_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "results.json"
    assert main(["--data", str(DEFAULT_DATA_DIR), "--only", "TDL-001,TDL-017", "--json", str(out)]) == 0
    payload = json.loads(out.read_text())
    assert [d["id"] for d in payload["detections"]] == ["TDL-001", "TDL-017"]
    assert payload["detections"][0]["results"][0]["src_ip"] == "203.0.113.45"
    assert "PASS" in capsys.readouterr().out
    # expecting a detection on benign-only data must be reported as MISSED with exit status 1
    from generate_logs import main as generate
    benign = tmp_path / "benign"
    generate(["--out", str(benign), "--hours", "2", "--scenarios", "none"])
    assert load_expected(benign, None) == set()
    assert main(["--data", str(benign), "--only", "TDL-001", "--expect", "TDL-001", "--quiet"]) == 1
    assert main(["--data", str(benign), "--only", "TDL-001", "--quiet"]) == 0


def test_load_expected_variants(tmp_path: Path) -> None:
    assert load_expected(tmp_path, "all") == {"*"}
    assert load_expected(tmp_path, "none") == set()
    assert load_expected(tmp_path, "tdl-001, TDL-002") == {"TDL-001", "TDL-002"}
    assert load_expected(tmp_path, None) == set()


def test_summarise_entities() -> None:
    rows = [{"user": "a", "src_ip": "1.1.1.1", "x": 1}, {"host": "h"}, {"host": "i"}, {"host": "j"}]
    assert summarise_entities(rows) == ["user=a src_ip=1.1.1.1", "host=h", "host=i", "(+1 more)"]
