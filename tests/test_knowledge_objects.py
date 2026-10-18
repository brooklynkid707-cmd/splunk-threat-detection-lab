"""Macros, eventtypes, lookups, inputs and tags resolve consistently."""

from __future__ import annotations

import re

import pytest

from harness import APP_DIR
from harness.catalog import Detection
from harness.conf import SplunkConf
from harness.loader import SOURCE_MAP
from harness.spl import Pipeline, SPLEnvironment, SPLError, expand_macros, run_search


@pytest.fixture(scope="module")
def env() -> SPLEnvironment:
    return SPLEnvironment.from_app(APP_DIR)


def test_all_macros_load(env: SPLEnvironment) -> None:
    assert {"wineventlog_security", "sysmon", "linux_auth", "firewall", "dns", "process_creation", "common_ports",
            "lsass_access_allowlist", "rare_parent_child_allowlist", "dns_subdomain_allowlist", "bytes_to_mb(1)"} <= set(env.macros)


def test_macro_with_argument_substitutes() -> None:
    env = SPLEnvironment.from_app(APP_DIR)
    assert expand_macros("| eval mb=`bytes_to_mb(bytes_out)`", env.macros) == "| eval mb=round(bytes_out/1048576, 2)"
    with pytest.raises(SPLError):
        expand_macros("`no_such_macro`", env.macros)


def test_every_detection_expands_without_unknown_objects(env: SPLEnvironment, catalog: list[Detection]) -> None:
    pipeline = Pipeline(env)
    for detection in catalog:
        expanded = pipeline.expand(detection.spl)
        assert "`" not in expanded, detection.id
        assert "index=" in expanded and "sourcetype=" in expanded, detection.id


def test_data_source_macros_match_inputs_conf(env: SPLEnvironment) -> None:
    inputs = SplunkConf.load(APP_DIR / "default" / "inputs.conf")
    pairs = {(s["index"], s["sourcetype"]) for s in inputs.stanzas.values() if "sourcetype" in s}
    assert pairs == {v[:2] for v in SOURCE_MAP.values()}
    for name in ("wineventlog_security", "sysmon", "linux_auth", "firewall", "dns"):
        match = re.match(r"index=(\S+) sourcetype=(\S+)", env.macros[name].definition)
        assert match and (match.group(1), match.group(2)) in pairs, name


def test_indexes_conf_defines_every_index() -> None:
    indexes = SplunkConf.load(APP_DIR / "default" / "indexes.conf")
    assert {v[0] for v in SOURCE_MAP.values()} <= set(indexes.stanzas)


def test_eventtypes_resolve_and_tags_reference_them(env: SPLEnvironment) -> None:
    pipeline = Pipeline(env)
    for name, search in env.eventtypes.items():
        assert "`" not in pipeline.expand(search), name
        assert "`" not in pipeline.expand(f"eventtype={name}")
    tags = SplunkConf.load(APP_DIR / "default" / "tags.conf")
    for stanza in tags.stanzas:
        assert stanza.startswith("eventtype=") and stanza[len("eventtype="):] in env.eventtypes, stanza


def test_eventtype_filters_events(env: SPLEnvironment) -> None:
    events = [
        {"index": "lab_windows", "sourcetype": "lab:windows:security", "EventCode": "4625", "_raw": "x"},
        {"index": "lab_windows", "sourcetype": "lab:windows:security", "EventCode": "4624", "_raw": "y"},
    ]
    assert len(run_search("eventtype=windows_failed_logon", events, env)) == 1


def test_lookups_load_with_match_types(env: SPLEnvironment) -> None:
    assert set(env.lookups) == {"known_bad_ips", "known_bad_ports", "ip_geo"}
    assert env.lookups["ip_geo"].cidr_fields == {"ip"}
    assert env.lookups["known_bad_ips"].match({"ip": "203.0.113.66"})["threat_category"] == "c2"
    assert env.lookups["known_bad_ips"].match({"ip": "203.0.113.67"}) is None
    assert env.lookups["known_bad_ports"].match({"port": "4444"})["description"].startswith("Metasploit")


@pytest.mark.parametrize("ip,country", [("10.20.1.55", "internal"), ("203.0.113.77", "US"), ("198.51.100.23", "DE"),
                                        ("192.0.2.55", "BR"), ("8.8.8.8", None)])
def test_cidr_geo_lookup(env: SPLEnvironment, ip: str, country: str | None) -> None:
    hit = env.lookups["ip_geo"].match({"ip": ip})
    assert (hit["country"] if hit else None) == country


def test_lookup_command_enriches_rows(env: SPLEnvironment) -> None:
    rows = [{"dest_ip": "198.51.100.251", "_raw": ""}, {"dest_ip": "203.0.113.1", "_raw": ""}]
    out = run_search("| lookup known_bad_ips ip AS dest_ip OUTPUT threat_category | where isnotnull(threat_category)", rows, env)
    assert [r["threat_category"] for r in out] == ["exfil"]


def test_lookup_files_have_no_real_world_addresses(env: SPLEnvironment) -> None:
    documentation_ranges = ("203.0.113.", "198.51.100.", "192.0.2.", "10.", "172.16.", "192.168.")
    for row in env.lookups["known_bad_ips"].rows:
        assert row["ip"].startswith(documentation_ranges), row["ip"]


def test_unsupported_syntax_raises(env: SPLEnvironment) -> None:
    with pytest.raises(SPLError):
        run_search("index=x [search index=y | fields a]", [], env)
    with pytest.raises(SPLError):
        run_search("index=x | transaction host", [{"index": "x", "_raw": ""}], env)
