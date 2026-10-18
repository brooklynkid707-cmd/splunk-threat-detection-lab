"""Pure-Python validation harness for the TA-threat-detection Splunk app.

Modules
-------
conf      Parse Splunk .conf files (stanzas, key = value, line continuation).
extract   Apply props.conf / transforms.conf search-time field extraction.
spl       A subset-of-SPL evaluator (search, where, eval, stats, eventstats,
          streamstats, rare, top, bin, sort, lookup, rex, dedup, table ...).
loader    Load synthetic log files into events using the extraction engine.
catalog   savedsearches.conf parsed into Detection objects (id, name, SPL,
          severity, schedule, ATT&CK and NIST annotations).
run_detections
          CLI that runs every detection over a data directory, prints a
          table, optionally writes JSON and exits non-zero on a miss.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "TA-threat-detection"
DEFAULT_DATA_DIR = REPO_ROOT / "data" / "sample"
