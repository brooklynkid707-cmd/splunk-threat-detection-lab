# Installing TA-threat-detection in Splunk

The app is a standard Splunk add-on directory. Nothing in it is specific to the lab except the
sample data and the `lab_*` index names, both of which are easy to swap.

## 1. Prerequisites

- Splunk Enterprise 9.x (single instance or a search head; the app has no modular inputs, so it also
  works on Splunk Cloud via the private app upload).
- Permission to create indexes, or an admin who will create `lab_windows`, `lab_sysmon`, `lab_linux`
  and `lab_network` for you (see `default/indexes.conf`).
- Optional: Splunk Enterprise Security. The searches carry `action.correlationsearch.*` settings so
  they appear in Content Management as correlation searches with ATT&CK annotations.

## 2. Copy the app

```bash
cp -r TA-threat-detection "$SPLUNK_HOME/etc/apps/"
"$SPLUNK_HOME/bin/splunk" restart
```

Or package it first and upload through **Apps > Manage Apps > Install app from file**:

```bash
tar -C . -czf TA-threat-detection.tgz TA-threat-detection
```

After the restart confirm the knowledge objects loaded:

```
| rest /servicesNS/-/TA-threat-detection/saved/searches | search title="TDL-*" | stats count
```

The count should be 25.

## 3. Indexes

`default/indexes.conf` creates the four lab indexes with default retention. If your environment
already has indexes for these sources, delete `indexes.conf` and edit the five data-source macros in
`default/macros.conf` instead:

| Macro | Default definition | Change to |
|---|---|---|
| `wineventlog_security` | `index=lab_windows sourcetype=lab:windows:security` | your WinEventLog:Security index/sourcetype |
| `sysmon` | `index=lab_sysmon sourcetype=lab:sysmon` | your Sysmon index/sourcetype |
| `linux_auth` | `index=lab_linux sourcetype=lab:linux:auth` | your `linux_secure` / auth.log sourcetype |
| `firewall` | `index=lab_network sourcetype=lab:firewall` | your firewall sourcetype |
| `dns` | `index=lab_network sourcetype=lab:dns` | your resolver query-log sourcetype |

Every detection reaches data only through these macros, so this table is the whole integration
surface. Field names are CIM-style (`user`, `src_ip`, `dest`, `process`, `process_cmdline`,
`parent_process`, `dest_ip`, `dest_port`, `query`, `bytes_out`); if your sourcetypes use the Splunk
add-ons for Windows, Sysmon and the CIM, those fields already exist and no further mapping is needed.

## 4. Sourcetypes and the sample data

`default/props.conf` defines five sourcetypes in the exact format `scripts/generate_logs.py` writes:

| Sourcetype | Format | Timestamp | Extraction |
|---|---|---|---|
| `lab:windows:security` | one `key=value` line per event | `%Y-%m-%dT%H:%M:%SZ` | `KV_MODE=auto` + `FIELDALIAS` to CIM names + `EVAL-action` |
| `lab:sysmon` | one `key=value` line per event | `%Y-%m-%dT%H:%M:%SZ` | `KV_MODE=auto` + `FIELDALIAS` + `EVAL-process_name` |
| `lab:linux:auth` | rsyslog line with RFC 3339 time | `%Y-%m-%dT%H:%M:%S%z` | `EXTRACT-` regexes for sshd, sudo, useradd, usermod |
| `lab:firewall` | pipe-delimited | `%Y-%m-%dT%H:%M:%SZ` | `REPORT-firewall_fields` (`DELIMS`) |
| `lab:dns` | BIND query log | `%d-%b-%Y %H:%M:%S.%3N` | `REPORT-dns_fields` (`REGEX`/`FORMAT`) |

To load the committed sample set:

```bash
mkdir -p "$SPLUNK_HOME/etc/apps/TA-threat-detection/samples"
cp data/sample/*.log "$SPLUNK_HOME/etc/apps/TA-threat-detection/samples/"
```

Then either enable the monitor stanzas in `default/inputs.conf` (set `disabled = 0`, or better,
copy them to `local/inputs.conf`) and restart, or add each file once with the CLI:

```bash
"$SPLUNK_HOME/bin/splunk" add oneshot data/sample/windows_security.log -index lab_windows -sourcetype lab:windows:security
"$SPLUNK_HOME/bin/splunk" add oneshot data/sample/sysmon.log          -index lab_sysmon   -sourcetype lab:sysmon
"$SPLUNK_HOME/bin/splunk" add oneshot data/sample/linux_auth.log      -index lab_linux    -sourcetype lab:linux:auth
"$SPLUNK_HOME/bin/splunk" add oneshot data/sample/firewall.log        -index lab_network  -sourcetype lab:firewall -host FW-EDGE-01
"$SPLUNK_HOME/bin/splunk" add oneshot data/sample/dns.log             -index lab_network  -sourcetype lab:dns      -host DNS-01
```

The sample data is dated 2026-10-14 00:00 to 23:59 UTC. When searching it manually, set the time
picker to that day; the scheduled searches use short look-back windows (`-15m` to `-24h`) and will not
see data that old. To exercise them live, regenerate with a current `--start`:

```bash
python scripts/generate_logs.py --out /tmp/live --start "$(date -u +%Y-%m-%dT00:00:00Z)"
```

## 5. Lookups

Three CSV lookups ship in `lookups/` and are declared in `default/transforms.conf`:

| Lookup | Match | Used by |
|---|---|---|
| `known_bad_ips` | exact, case-insensitive on `ip` | TDL-011 (enrichment), TDL-017 (match required) |
| `known_bad_ports` | exact on `port` | TDL-016 (enrichment) |
| `ip_geo` | `CIDR(ip)` | TDL-003 |

Replace their contents with your threat feed and a real geolocation table; keep the column names.
The lab feed contains only RFC 5737 documentation addresses.

## 6. Enabling the searches

All 25 searches ship with `enableSched = 1` and `alert.track = 1`, so they will start running and
creating triggered alerts as soon as the app loads. For a staged rollout:

1. Disable them all: **Settings > Searches, reports, and alerts**, filter on app
   `TA-threat-detection`, select all, **Disable**. Or in `local/savedsearches.conf` add
   `disabled = 1` under each stanza.
2. Enable one at a time, starting with the high-fidelity ones (TDL-004, TDL-012, TDL-014, TDL-015,
   TDL-017, TDL-021) and ending with the baseline and hunting searches (TDL-011, TDL-013, TDL-016,
   TDL-018). `docs/TUNING.md` explains the order.
3. Put every threshold or allowlist change in `local/`, never in `default/`, so the app can be
   upgraded.

Severity is encoded in `alert.severity` (2 low, 3 medium, 4 high, 5 critical) and the ES
`action.correlationsearch.annotations` JSON carries the ATT&CK and NIST CSF IDs. In Enterprise
Security the searches appear under **Configure > Content > Content Management** and can be enabled
there; the `notable` adaptive response is not pre-wired, so add it per search if you want notables
rather than triggered alerts.

## 7. Dashboard

`default/data/ui/views/soc_overview.xml` is a Simple XML dashboard that uses the eventtypes in
`default/eventtypes.conf`. It appears in the app navigation as **SOC Overview**.

## 8. Verifying without Splunk

The Python harness runs the same SPL strings over the same files:

```bash
python -m harness.run_detections --data data/sample
```

If a search fires in the harness and not in Splunk, the usual causes are the time picker (section 4)
or the macros pointing at the wrong index (section 3).
