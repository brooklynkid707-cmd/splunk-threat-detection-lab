# Tuning guide

Every detection in this app is a trade-off between catching the technique and the number of alerts an
analyst has to close. This document explains where each knob lives, the order to enable searches in a
new environment, and how to measure whether a change helped. Per-detection false-positive notes are in
`detections/<id>-<slug>.md`.

## Where the knobs are

| Knob | Lives in | Why there |
|---|---|---|
| Index and sourcetype names | `macros.conf` data-source macros | Change five lines, not 25 searches |
| Allowlists | `macros.conf` (`lsass_access_allowlist`, `rare_parent_child_allowlist`, `dns_subdomain_allowlist`, `common_ports`) | Searchable, versioned, and the harness tests them |
| Threat intel and geolocation | `lookups/*.csv` via `transforms.conf` | Swappable for real feeds without touching SPL |
| Thresholds and windows | inline in each `search =` | They are part of the detection logic and are documented beside it |
| Schedules and look-back | `cron_schedule`, `dispatch.earliest_time` | Look-back must cover the `bin` span plus one scheduling interval |
| Alert fatigue controls | `alert.suppress.*` per stanza | Suppress on the entity (`src_ip`, `user`) for the time it takes to triage |

Make every change in `local/` (`local/macros.conf`, `local/savedsearches.conf`), never in `default/`.

## Detection classes and their failure modes

### Threshold detections (TDL-001, 002, 005, 006, 009, 010, 020)

Count something per entity inside a time bucket and compare with a number.

- The number was chosen for a lab of 60 workstations and 12 servers. The right production value is
  the one that keeps the daily alert count below what the SOC can triage; find it by running the
  search for a week with `| where` removed and plotting the distribution of the counted field.
- `bin _time span=` creates hard bucket edges: 9 failures at 02:04 and 9 at 02:06 in two different
  five-minute buckets will not fire. If the attack you care about is slow, widen the span or
  switch to `streamstats time_window=` as TDL-021 does.
- Aggregating by the right entity matters more than the number. TDL-020 groups by `src_ip, host`
  so a scan across 50 hosts does not become 50 alerts; TDL-002 groups only by `src_ip` because the
  point is one source touching many accounts.

### Pattern detections (TDL-007, 008, 012, 014, 015, 019, 023, 024, 025)

A single event is enough: the parent/child pair, the command-line switch, the path or the access mask
is the indicator.

- These produce the fewest alerts and the highest confidence. Enable them first.
- Tune by adding specific exclusions (full path, signature, exact command line) rather than
  broadening the match. The lab's `lsass_access_allowlist` is the model: full paths of the few
  binaries that may touch LSASS, nothing else.
- Resist allowlisting on `user`; attackers run as the user they compromised.

### Correlation detections (TDL-003, 004, 021, 022)

Two different events about the same entity inside a window.

- The order of events and the window are the logic. TDL-021 uses `streamstats time_window=30m` so
  "five failures then a success" is evaluated in event order; TDL-004 and TDL-022 use a single
  `stats` over the window because order does not matter (created and added, in either order).
- Correlation searches are sensitive to field normalisation: TDL-004 joins 4720's
  `Target_Account_Name` with 4732's `Member_Name` through `coalesce`. Check your own sourcetype
  produces both before enabling.

### Baseline and statistical detections (TDL-011, 016, 018)

Compare an entity against the population or against itself.

- They need enough data to baseline. TDL-018 cannot fire on a host with one hourly bucket; TDL-016
  flags everything as rare on a quiet night. Run them over at least a day and prefer a summary
  index (`collect`) with 30 days of history for production.
- Expect a steady stream of new-but-benign results (new SaaS, new agent). Treat the first two weeks
  as allowlist building, with the alert routed to a dashboard, not the queue.
- The constants (`jitter_ratio<0.2`, `connections_on_port<=5`, `3*baseline_stdev`) are starting
  points. Loosen the beacon jitter only after the periodic-service allowlist exists, or you will
  trade a few real beacons for hundreds of NTP alerts.

### Hunting detections (TDL-013)

`rare` over the whole population produces a review list, never an alert. Severity is low and the
expected workflow is a daily look, promotion of confirmed-bad pairs into their own pattern detection,
and weekly additions to `rare_parent_child_allowlist`.

## Rollout order for a new environment

1. Confirm field names with `| fieldsummary` on each data-source macro. The detections need
   `user`, `src_ip`, `dest`, `logon_type`, `process`, `process_cmdline`, `parent_process`,
   `dest_ip`, `dest_port`, `bytes_out`, `query`, `action`, `direction`.
2. Enable pattern detections (TDL-007, 012, 014, 015, 019, 023, 024, 025) and the two account
   correlations (TDL-004, 022). Review for three days.
3. Enable the threshold detections with the look-back temporarily set to `-7d` and the final
   `| where` removed to see the distributions, then set thresholds and enable for real.
4. Enable TDL-003 after replacing `ip_geo.csv` with a real geolocation table and adding your
   egress ranges.
5. Enable TDL-017 after replacing `known_bad_ips.csv` with a feed that has `first_seen` dates; age
   out entries older than 90 days.
6. Enable the baseline detections last, routed to a dashboard for two weeks before they alert.
7. Leave TDL-013 on a hunting dashboard permanently.

## Measuring a change

Record, per detection and per week:

- alerts fired, alerts closed as true positive, alerts closed as benign;
- for benign closes, the reason category (new software, admin activity, misconfiguration, stale
  indicator) so the fix goes to the right knob;
- median time to close.

A tuning change is good when benign closes fall and true positives do not. If a detection has had zero
true positives in six months and a non-trivial benign rate, either its threshold is wrong or the
technique is not relevant to the environment; review it rather than letting it run.

## Testing a change before shipping it

The Python harness runs the exact SPL from `savedsearches.conf`, so a threshold or allowlist edit
can be validated without a Splunk instance:

```bash
# does every planted scenario still fire, and is benign data still quiet?
python -m pytest -q tests/test_detections.py

# generate benign-only data with a different seed and check nothing fires
python scripts/generate_logs.py --out /tmp/benign --seed 7 --scenarios none
python -m harness.run_detections --data /tmp/benign --expect none
```

If you add a detection, add a stanza, add a `scenario_<slug>` method and a `Scenario` entry in
`scripts/generate_logs.py`, add the entity you expect to `EXPECTED_ENTITY` in
`tests/test_detections.py`, then run `make coverage` to regenerate `docs/ATTACK-COVERAGE.md`.
