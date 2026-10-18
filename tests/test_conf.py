"""Splunk .conf parsing and the detection catalogue."""

from __future__ import annotations

import json
import re

import pytest

from harness import APP_DIR
from harness.conf import SplunkConf, is_true
from harness.catalog import TECHNIQUE_NAMES, TECHNIQUE_TACTICS, load_catalog


def test_parse_continuation_lines_and_comments() -> None:
    conf = SplunkConf()
    conf.parse("""
# a comment
[alpha]
search = index=a \\
| stats count \\
| where count>1
path = C:\\\\Windows\\\\System32
; another comment style

[beta]
disabled = 0
""")
    assert conf["alpha"]["search"] == "index=a | stats count | where count>1"
    assert conf["alpha"]["path"] == "C:\\\\Windows\\\\System32"
    assert conf["beta"]["disabled"] == "0"
    assert conf.get("beta", "missing", "dflt") == "dflt"
    assert "gamma" not in conf


def test_empty_stanza_name_in_metadata() -> None:
    meta = SplunkConf.load(APP_DIR / "metadata" / "default.meta")
    assert "" in meta
    assert meta[""]["export"] == "system"


@pytest.mark.parametrize("value,expected", [("1", True), ("true", True), ("f", False), ("0", False), (None, False)])
def test_is_true(value: str | None, expected: bool) -> None:
    assert is_true(value) is expected


def test_catalog_has_25_sequential_detections() -> None:
    catalog = load_catalog(APP_DIR)
    assert [d.id for d in catalog] == [f"TDL-{n:03d}" for n in range(1, 26)]


def test_every_detection_is_complete() -> None:
    for detection in load_catalog(APP_DIR):
        assert detection.name, detection.id
        assert detection.description, detection.id
        assert detection.spl.startswith(("`", "(")), f"{detection.id} must reach data through a macro"
        assert detection.severity in {2, 3, 4, 5}, detection.id
        assert re.match(r"^(\S+\s+){4}\S+$", detection.cron_schedule), f"{detection.id} cron"
        assert detection.enabled, detection.id
        assert detection.mitre_attack, f"{detection.id} has no ATT&CK mapping"
        assert all(re.match(r"^T\d{4}(\.\d{3})?$", t) for t in detection.mitre_attack), detection.id
        assert detection.nist, detection.id
        assert detection.label, detection.id
        assert detection.data_sources, f"{detection.id} uses no known data-source macro"
        assert detection.tactics and "Unknown" not in detection.tactics, detection.id


def test_annotations_are_valid_es_json() -> None:
    conf = SplunkConf.load(APP_DIR / "default" / "savedsearches.conf")
    for stanza, settings in conf.items():
        if not stanza.startswith("TDL-"):
            continue
        data = json.loads(settings["action.correlationsearch.annotations"])
        assert set(data) >= {"mitre_attack", "nist"}, stanza
        assert settings.get("action.correlationsearch.enabled") == "1", stanza


def test_technique_metadata_covers_every_annotation() -> None:
    for detection in load_catalog(APP_DIR):
        for technique in detection.mitre_attack:
            assert technique in TECHNIQUE_NAMES, f"{detection.id}: no name for {technique}"
            assert technique.split(".")[0] in TECHNIQUE_TACTICS, f"{detection.id}: no tactic for {technique}"


def test_slug_and_stanza_round_trip() -> None:
    detection = load_catalog(APP_DIR)[0]
    assert detection.slug == "tdl-001-windows-brute-force-many-failures-from-one-source"
    assert detection.stanza == "TDL-001 Windows Brute Force - Many Failures From One Source"
    assert detection.to_dict()["severity_name"] == "high"


def test_attack_coverage_doc_is_current() -> None:
    """docs/ATTACK-COVERAGE.md is generated; it must match the annotations in the conf."""
    import sys
    from harness import REPO_ROOT
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from attack_coverage import render
    assert (REPO_ROOT / "docs" / "ATTACK-COVERAGE.md").read_text(encoding="utf-8") == render(load_catalog(APP_DIR))


def test_every_detection_has_a_doc_page() -> None:
    from harness import REPO_ROOT
    for detection in load_catalog(APP_DIR):
        page = REPO_ROOT / "detections" / f"{detection.slug}.md"
        assert page.exists(), page
        text = page.read_text(encoding="utf-8")
        assert detection.spl.split(" | ")[0] in text.replace(" \n| ", " | "), detection.id
        for technique in detection.mitre_attack:
            assert technique in text, f"{detection.id} page missing {technique}"
