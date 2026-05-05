# py-scan-blu
It's have 2 version gui and scritp.
# Python Bluetooth / BLE Scanner

`scan-blu.py` is a single-file Python 3.9+ command-line tool for scanning,
enumerating, monitoring, and auditing Bluetooth (BR/EDR) and Bluetooth Low
Energy (BLE) devices on Linux.

It wraps **`bleak`** (BLE), **`pybluez`** (classic BR/EDR), and a local
**SQLite** database behind a `click`-based CLI with a colorful `colorama`
front-end and a clean `--headless` mode for logs/CI.

---

## Features

- **BLE & BR/EDR scanning** — async BLE discovery (with retries) + classic SDP scan
- **GATT enumeration** — list services and characteristics for any BLE device
- **Security scan** — flags exposed services and unauthenticated writable characteristics (LOW / MEDIUM / HIGH)
- **Continuous monitor** — repeated BLE passes with first/last seen tracking and a memory cap
- **RSSI trend** — track signal strength of one device over a window
- **Proximity report** — aggregate stats from stored history (avg / min / max RSSI, in-range count)
- **JSON device report** — combines services + security scan + history + vendor into one file
- **CSV / JSON export** of scan results
- **SQLite history** — every sighting is recorded; `device_history` + `device_profiles` tables (WAL mode)
- **Vendor OUI lookup** — built-in table for common manufacturers
- **Advertisement parsing** — decodes BLE AD structures (flags, names, TX power, mfg data, …)
- **Filter helper** — `filter_devices_by_criteria(...)` (name / vendor / type / min_rssi / mac_prefix)
- **Interactive TUI** — scan, pick a device, enumerate
- **Headless mode** — `--headless` strips ANSI colors

---

## Install

### Arch Linux

```bash
sudo pacman -S python-bleak python-colorama python-click
pip install pybluez   # optional — only needed for BR/EDR (Classic) scanning
```

`pybluez` is optional. Without it, the BLE-only commands still work; BR/EDR
commands will print a clear error pointing you at the install line.

### Other distros

```bash
pip install bleak colorama click
pip install pybluez   # optional
```

Python **3.9+** is required (the script enforces this on startup).

---

## Run

```bash
sudo ./scan-blu.py --help
```

`sudo` is needed for raw BLE / HCI access on Linux. On most setups
`CAP_NET_ADMIN` + `CAP_NET_RAW` on the Python interpreter is enough as a
non-root alternative.

---

## Commands

```
Usage: scan-blu.py [--headless] COMMAND [ARGS]...
```

| Command       | Arguments                                             | Description                                                |
|---------------|-------------------------------------------------------|------------------------------------------------------------|
| `list`        | `[-w SECS]`                                           | Quick BLE device list (btscanner-compatible alias)         |
| `scan`        | `[-b] [-t SECS]`                                      | Scan for BR/EDR (default) or BLE (`-b`)                    |
| `enum`        | `<MAC> [-b]`                                          | Enumerate SDP / GATT services                              |
| `interactive` | `[-b]`                                                | Scan, pick a device, then enumerate                        |
| `export`      | `[-b] [-t SECS] [-f csv\|json] [-o FILE]`             | Scan and dump to CSV / JSON                                |
| `monitor`     | `[-d SECS] [-i SECS] [-e csv\|json]`                  | Continuous BLE monitor with optional auto-export           |
| `security`    | `<MAC>`                                               | BLE security scan (LOW / MEDIUM / HIGH risk report)        |
| `report`      | `<MAC> [-o FILE]`                                     | Full JSON report (services + security + history + vendor)  |
| `trend`       | `<MAC> [-d SECS] [-i SECS]`                           | RSSI trend over a time window                              |
| `history`     | `<MAC> [-n LIMIT]`                                    | Stored sightings for a MAC                                 |
| `devices`     | `<MAC> [-t RSSI]`                                     | Per-device statistics (counts, avg/min/max RSSI, recent)   |
| `proximity`   | `<MAC>`                                               | Proximity report (in-range count, RSSI stats, scan cadence)|
| `vendors`     |                                                       | List known OUI prefixes                                    |

### Global options

- `--headless` — disable ANSI colors (good for logs / pipes)
- `-h`, `--help` — show help (works on every subcommand)

### Examples

```bash
# Quick BLE list
sudo ./scan-blu.py list -w 8

# Classic BR/EDR scan
sudo ./scan-blu.py scan

# BLE scan with a 10-second window
sudo ./scan-blu.py scan --ble -t 10

# Enumerate GATT on a device
sudo ./scan-blu.py enum AA:BB:CC:DD:EE:FF --ble

# 5-minute monitor, 10s passes, auto-export to JSON at the end
sudo ./scan-blu.py monitor -d 300 -i 10 -e json

# Security audit
sudo ./scan-blu.py security AA:BB:CC:DD:EE:FF

# Full JSON report
sudo ./scan-blu.py report AA:BB:CC:DD:EE:FF -o phone.json

# Track RSSI for 60s
sudo ./scan-blu.py trend AA:BB:CC:DD:EE:FF -d 60 -i 5

# Show last 100 sightings
sudo ./scan-blu.py history AA:BB:CC:DD:EE:FF -n 100

# Proximity stats
sudo ./scan-blu.py proximity AA:BB:CC:DD:EE:FF

# Pipe-friendly logging
sudo ./scan-blu.py --headless scan --ble | tee scan.log
```

---

## Database

A local SQLite database `ble_devices.db` is created in the working directory
on first call to a function that records sightings. Schema:

- `device_history` — one row per sighting (MAC, name, RSSI, vendor, type, `seen_at` ISO timestamp)
- `device_profiles` — deduped per MAC (first seen / last seen / times seen)
- Index `idx_history_mac` on `device_history(mac_address)`

WAL journaling and a 5-second busy timeout are enabled so concurrent reads
(e.g. via `sqlite3` CLI) don't block writes.

---

## Library use

Every CLI command is also a top-level Python function and can be imported:

```python
from scan_blu import (
    ble_scan, bredr_scan,
    ble_enum_services, bredr_enum_services,
    perform_security_scan, generate_device_report,
    get_signal_strength_trend, get_proximity_report,
    monitor_continuous_scan, batch_enumerate,
    export_scan_results, filter_devices_by_criteria,
    parse_advertisement_data, get_service_characteristics,
    create_device_database, get_device_history,
    lookup_vendor, validate_mac,
)

devices = ble_scan(timeout=8.0)
near    = filter_devices_by_criteria(devices, {"min_rssi": -70, "vendor": "apple"})
export_scan_results(near, format_type="json", filepath="apple_nearby.json")
```

(Module name will match whatever you rename the file to —
`scan-blu.py` isn't directly importable due to the dash; copy or symlink to
`scan_blu.py` if you want to `import` it.)

---

## Notes

- BLE scanning uses **`bleak`**, which talks to BlueZ over D-Bus and supports
  proper async cleanup; the wrapper here adds retry and a hard timeout guard.
- BR/EDR support is optional. If `pybluez` isn't installed, only the BLE
  paths are available — the code degrades gracefully.
- The vendor OUI table (`VENDORS_OUI`) is intentionally small; extend it in
  the source to add more prefixes.
- All MAC inputs are validated against `XX:XX:XX:XX:XX:XX` (case-insensitive)
  before any radio/socket call.
- `_run_async()` handles being called from inside an existing event loop
  (e.g. Jupyter) by delegating to a worker thread.

---

## Related

- `scan_blu.c` — pure C / BlueZ port of the same scanner (CLI only)
- `gui-blu.c` — GTK3 desktop GUI version

All three share the same on-disk database schema and OUI table, so you can
mix and match (e.g. log with the C scanner, query with `scan-blu.py history`).

---

## License

MIT License

Copyright (c) 2026 Acheron-HSR

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

