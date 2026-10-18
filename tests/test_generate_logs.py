"""The synthetic log generator is deterministic, selectable and writes the expected files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from generate_logs import OUTPUT_FILES, SCENARIOS, LogGenerator, main, resolve_scenarios, write_records


def test_deterministic_for_a_seed() -> None:
    a = LogGenerator(seed=7, hours=2).generate(["TDL-001"])
    b = LogGenerator(seed=7, hours=2).generate(["TDL-001"])
    assert [r.line for r in a] == [r.line for r in b]
    assert a == sorted(a)


def test_resolve_scenarios_accepts_ids_and_slugs() -> None:
    assert resolve_scenarios(None) == list(SCENARIOS)
    assert resolve_scenarios(["all"]) == list(SCENARIOS)
    assert resolve_scenarios(["none"]) == []
    assert resolve_scenarios([]) == []
    assert resolve_scenarios(["beacon", "tdl-001", "TDL-001"]) == ["TDL-011", "TDL-001"]
    with pytest.raises(ValueError):
        resolve_scenarios(["not-a-scenario"])


def test_every_scenario_method_returns_records() -> None:
    generator = LogGenerator(seed=1, hours=1)
    for scenario in SCENARIOS.values():
        records = getattr(generator, f"scenario_{scenario.slug}")()
        assert records, scenario.detection_id
        assert {r.sourcetype for r in records} <= set(OUTPUT_FILES)


def test_only_documentation_and_private_addresses() -> None:
    import re
    allowed = ("203.0.113.", "198.51.100.", "192.0.2.", "10.", "127.0.0.1", "::ffff:203.0.113.")
    text = "\n".join(r.line for r in LogGenerator(seed=3, hours=3).generate(None))
    for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)):
        assert ip.startswith(allowed), ip
    assert "example" in text and ".com" in text


def test_write_records_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "logs"
    assert main(["--out", str(out), "--hours", "2", "--scenarios", "TDL-007,TDL-020"]) == 0
    assert sorted(p.name for p in out.iterdir()) == sorted([*OUTPUT_FILES.values(), "scenarios.json"])
    manifest = json.loads((out / "scenarios.json").read_text())
    assert [p["detection_id"] for p in manifest["planted"]] == ["TDL-007", "TDL-020"]
    assert "wrote" in capsys.readouterr().out
    assert main(["--list-scenarios"]) == 0
    assert "TDL-025" in capsys.readouterr().out


def test_write_records_counts(tmp_path: Path) -> None:
    records = LogGenerator(seed=2, hours=1).generate([])
    counts = write_records(records, tmp_path, [])
    assert sum(counts.values()) == len(records)
    for name, count in counts.items():
        assert len((tmp_path / name).read_text().splitlines()) == count
