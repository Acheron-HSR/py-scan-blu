#!/usr/bin/env python3
"""
Requirements (Arch):
    sudo pacman -S python-bleak python-colorama python-click
    pip install pybluez  # optional, for BR/EDR classic scanning
"""

import sys
import asyncio
import platform
import csv
import json
import sqlite3
import time
import datetime
import click
from colorama import Fore, init as colorama_init
from collections import defaultdict

# Initialise colorama early so BANNER constant renders correctly
colorama_init(autoreset=True)

# --- Optional imports ---

try:
    import bluetooth
    PYBLUEZ_AVAILABLE = True
except ImportError:
    PYBLUEZ_AVAILABLE = False

try:
    from bleak import BleakScanner, BleakClient
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


# ============================================================================
# CONSTANTS
# ============================================================================

VENDORS_OUI: dict[str, str] = {
    "acer":      "C0:98:79",
    "apple":     "FC:FC:48",
    "asus":      "FC:C2:33",
    "dell":      "D8:D0:90",
    "google":    "F8:8F:CA",
    "hp":        "B0:5C:DA",
    "htc":       "98:0D:2E",
    "intel":     "FC:F8:AE",
    "lenovo":    "A4:8C:DB",
    "lg":        "F8:A9:D0",
    "microsoft": "C4:9D:ED",
    "motorola":  "F8:F1:B6",
    "samsung":   "FC:F1:36",
    "sony":      "D4:38:9C",
    "toshiba":   "EC:21:E5",
    "xiaomi":    "FC:64:BA",
}


# ============================================================================
# SYSTEM UTILITIES
# ============================================================================

def is_linux() -> bool:
    return platform.system() == "Linux"

def is_windows() -> bool:
    return platform.system() == "Windows"

def validate_mac(mac: str) -> bool:
    """Return True if mac matches XX:XX:XX:XX:XX:XX format (case-insensitive)."""
    import re
    return bool(re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", mac))

def lookup_vendor(mac: str) -> str:
    """Return vendor name from OUI prefix, or empty string if unknown."""
    prefix = mac[:8].upper()
    for vendor, oui in VENDORS_OUI.items():
        if oui.upper() == prefix:
            return vendor.capitalize()
    return ""

def check_ble_available() -> None:
    if not BLEAK_AVAILABLE:
        log_err("BLE support requires 'bleak'. Install with: sudo pacman -S python-bleak")
        sys.exit(1)

def check_bredr_available() -> None:
    if not PYBLUEZ_AVAILABLE:
        log_err("BR/EDR support requires 'pybluez'. Install with: pip install pybluez")
        sys.exit(1)


def _run_async(coro):
    """Run a coroutine safely whether or not a loop is already running."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Already inside an event loop (e.g. Jupyter / nested calls)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)


# ============================================================================
# LOGGER
# ============================================================================

class Logger:
    """Centralised logger with colorama colour-tag support."""

    COLOR_MAP: dict[str, str] = {
        "<black>":    Fore.BLACK,    "<blue>":    Fore.BLUE,
        "<cyan>":     Fore.CYAN,     "<green>":   Fore.GREEN,
        "<magenta>":  Fore.MAGENTA,  "<red>":     Fore.RED,
        "<white>":    Fore.WHITE,    "<yellow>":  Fore.YELLOW,
        "<lblack>":   Fore.LIGHTBLACK_EX,  "<lblue>":    Fore.LIGHTBLUE_EX,
        "<lcyan>":    Fore.LIGHTCYAN_EX,   "<lgreen>":   Fore.LIGHTGREEN_EX,
        "<lmagenta>": Fore.LIGHTMAGENTA_EX,"<lred>":     Fore.LIGHTRED_EX,
        "<lwhite>":   Fore.LIGHTWHITE_EX,  "<lyellow>":  Fore.LIGHTYELLOW_EX,
        "<reset>":    Fore.RESET,
    }

    def __init__(self):
        self.headless = False

    def set_headless(self, headless: bool):
        self.headless = headless

    def _format(self, message: str) -> str:
        for tag, color in self.COLOR_MAP.items():
            message = message.replace(tag, "" if self.headless else color)
        return message

    def _print(self, level: str, color: str, message: str):
        if self.headless:
            print(f"{level} {self._format(message)}")
        else:
            prefix = f"{color}{level:<5}{Fore.RESET}"
            print(f"{prefix} {self._format(message)}")

    def info(self, message: str):  self._print("INFO", Fore.CYAN,   message)
    def warn(self, message: str):  self._print("WARN", Fore.YELLOW, message)
    def err(self,  message: str):  self._print("ERR",  Fore.RED,    message)


logger = Logger()

def log_info(msg: str): logger.info(msg)
def log_warn(msg: str): logger.warn(msg)
def log_err(msg: str):  logger.err(msg)


# ============================================================================
# BANNER
# ============================================================================

BANNER = Fore.CYAN + r"""
  ____  _     _____          _ _             
 |  _ \| |   | ____|__ _  __| (_)_ __   __ _ 
 | |_) | |   |  _| / _` |/ _` | | '_ \ / _` |
 |  _ <| |___| |__| (_| | (_| | | | | | (_| |
 |_| \_\_____|_____\__,_|\__,_|_|_| |_|\__, |
                                        |___/ 
       Bluetooth / BLE Scanner & Enumerator
""" + Fore.RESET

BORDERED_WIDTH = 38

def print_bordered(text: str, color: str = Fore.CYAN):
    text_len = len(text)
    if text_len >= BORDERED_WIDTH:
        centered = text[:BORDERED_WIDTH]
    else:
        pad = BORDERED_WIDTH - text_len
        left = pad // 2
        centered = " " * left + text + " " * (pad - left)
    print(f"{color}╔{'═' * (BORDERED_WIDTH + 2)}╗{Fore.RESET}")
    print(f"{color}║ {centered} ║{Fore.RESET}")
    print(f"{color}╚{'═' * (BORDERED_WIDTH + 2)}╝{Fore.RESET}")


# ============================================================================
# SCANNING
# ============================================================================

async def _ble_scan_async(timeout: float, retries: int = 2) -> list[dict]:
    """Async BLE scan using bleak with proper resource cleanup and retry logic."""
    log_info(f"Starting BLE scan ({int(timeout)}s)...")

    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        scanner = BleakScanner()
        found: dict = {}
        try:
            async with scanner:
                try:
                    await asyncio.wait_for(
                        scanner.discover(timeout=timeout, return_adv=True),
                        timeout=timeout + 5.0,
                    )
                    # After discover() the scanner is stopped; retrieve results.
                    found = scanner.discovered_devices_and_advertisement_data
                except asyncio.TimeoutError:
                    log_warn(f"BLE scan timed out (attempt {attempt}) — using partial results.")
                    found = scanner.discovered_devices_and_advertisement_data
        except Exception as exc:
            last_exc = exc
            log_warn(f"BLE scan attempt {attempt} failed: {exc}")
            if attempt < retries:
                await asyncio.sleep(1.0)
            continue
        finally:
            # Explicit stop guard – bleak is safe to call stop() multiple times
            try:
                await scanner.stop()
            except Exception:
                pass

        # Success – build device list
        devices: list[dict] = []
        for address, (device, adv_data) in found.items():
            vendor = lookup_vendor(address)
            name = device.name or (f"[{vendor}]" if vendor else "Unknown")
            devices.append({
                "address": address,
                "name": name,
                "rssi": adv_data.rssi,
                "type": "BLE",
                "vendor": vendor,
            })
        return devices

    log_err(f"BLE scan failed after {retries} attempt(s): {last_exc}")
    return []


def ble_scan(timeout: float = 5.0) -> list[dict]:
    """Scan for BLE devices. Returns a list of device dicts."""
    check_ble_available()
    return _run_async(_ble_scan_async(timeout))


def bredr_scan() -> list[dict]:
    """Scan for BR/EDR (Classic Bluetooth) devices. Returns a list of device dicts."""
    check_bredr_available()
    log_info("Starting BR/EDR scan (may take ~10s)...")
    nearby = []
    try:
        nearby = bluetooth.discover_devices(
            lookup_names=True, duration=10, flush_cache=True, lookup_class=True
        )
    except OSError as exc:
        log_err(f"BR/EDR scan failed (check Bluetooth adapter permissions): {exc}")
        return []
    except Exception as exc:
        log_err(f"BR/EDR scan failed: {exc}")
        return []
    return [
        {
            "address": addr,
            "name": name or (lookup_vendor(addr) and f"[{lookup_vendor(addr)}]") or "Unknown",
            "class": dev_class,
            "type": "BR/EDR",
            "vendor": lookup_vendor(addr),
        }
        for addr, name, dev_class in nearby
    ]


def display_devices(devices: list[dict]):
    """Pretty-print a list of scanned devices."""
    if not devices:
        log_warn("No devices found.")
        return

    print()
    print(f"  {'Address':<20} {'Type':<8} {'RSSI':<8} {'Vendor':<12} Name")
    print(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*12} {'-'*20}")
    for dev in sorted(devices, key=lambda d: d.get("rssi") or 0, reverse=True):
        rssi   = str(dev["rssi"]) if dev.get("rssi") is not None else "N/A"
        dtype  = dev.get("type", "?")
        vendor = dev.get("vendor") or ""
        print(
            f"  {Fore.CYAN}{dev['address']:<20}{Fore.RESET} "
            f"{Fore.YELLOW}{dtype:<8}{Fore.RESET} "
            f"{Fore.LIGHTBLACK_EX}{rssi:<8}{Fore.RESET} "
            f"{Fore.MAGENTA}{vendor:<12}{Fore.RESET} "
            f"{Fore.LIGHTGREEN_EX}{dev['name']}{Fore.RESET}"
        )
    print(f"\n  {Fore.GREEN}[+] {len(devices)} device(s) found.{Fore.RESET}\n")


# ============================================================================
# SERVICE ENUMERATION
# ============================================================================

def bredr_enum_services(device_addr: str) -> list[dict]:
    """Enumerate BR/EDR services on a device."""
    check_bredr_available()
    try:
        raw = bluetooth.find_service(address=device_addr)
    except Exception as exc:
        log_err(f"bredr_enum_services: failed for {device_addr} — {exc}")
        return []
    services = []
    for svc in raw:
        name = svc.get("name", "Unknown")
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="ignore")
        services.append({
            "name":        name or "Unknown",
            "description": svc.get("description") or "N/A",
            "protocol":    svc.get("protocol")    or "N/A",
            "provider":    svc.get("provider")    or "N/A",
            "port":        svc.get("port", 0),
            "uuid":        svc.get("service-id")  or "N/A",
        })
    return services


async def _ble_enum_async(device_addr: str, retries: int = 2) -> list[dict]:
    """Async BLE GATT service enumeration with proper resource cleanup and retry."""
    log_info(f"Connecting to {device_addr}...")
    services: list[dict] = []

    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        client = BleakClient(device_addr, timeout=15.0)
        try:
            await client.connect()
            if not client.is_connected:
                log_err(f"Failed to connect to {device_addr} (attempt {attempt}).")
                if attempt < retries:
                    await asyncio.sleep(1.0)
                continue

            log_info("Connected. Discovering GATT services...")

            for svc in client.services:
                chars = [
                    {
                        "uuid":        c.uuid,
                        "description": c.description or "Unknown",
                        "properties":  list(c.properties),
                    }
                    for c in svc.characteristics
                ]
                services.append({
                    "name":            svc.description or "Unknown",
                    "description":     f"UUID: {svc.uuid}",
                    "protocol":        "GATT",
                    "provider":        "BLE",
                    "port":            0,
                    "uuid":            svc.uuid,
                    "characteristics": chars,
                })
            return services

        except asyncio.TimeoutError:
            last_exc = asyncio.TimeoutError(f"Connection to {device_addr} timed out.")
            log_warn(f"Connection timed out (attempt {attempt}).")
        except Exception as exc:
            last_exc = exc
            log_warn(f"Enumeration attempt {attempt} failed for {device_addr}: {exc}")
        finally:
            # Always disconnect – bleak is safe to call even if not connected
            try:
                if client.is_connected:
                    await client.disconnect()
            except Exception as disc_exc:
                log_warn(f"Disconnect error for {device_addr}: {disc_exc}")

        if attempt < retries:
            await asyncio.sleep(1.0)

    log_err(f"Failed to enumerate services on {device_addr} after {retries} attempt(s): {last_exc}")
    return services


def ble_enum_services(device_addr: str) -> list[dict]:
    """Enumerate BLE GATT services on a device."""
    check_ble_available()
    return _run_async(_ble_enum_async(device_addr))


def display_services(services: list[dict]):
    """Pretty-print a list of enumerated services."""
    if not services:
        log_warn("No services found.")
        return

    print()
    for svc in services:
        print(f"  {Fore.CYAN}▸ {svc['name']}{Fore.RESET}")
        print(f"    {Fore.LIGHTBLACK_EX}Description : {Fore.RESET}{svc['description']}")
        print(f"    {Fore.LIGHTBLACK_EX}Protocol    : {Fore.RESET}{svc['protocol']}")
        print(f"    {Fore.LIGHTBLACK_EX}Provider    : {Fore.RESET}{svc['provider']}")
        if svc.get("port", 0) > 0:
            print(f"    {Fore.LIGHTBLACK_EX}Port        : {Fore.RESET}{svc['port']}")
        print(f"    {Fore.LIGHTBLACK_EX}UUID        : {Fore.RESET}{svc['uuid']}")

        chars = svc.get("characteristics", [])
        if chars:
            print(f"    {Fore.LIGHTBLACK_EX}Characteristics:")
            for c in chars:
                props = ", ".join(c["properties"])
                print(
                    f"      {Fore.LIGHTBLACK_EX}- {Fore.RESET}{c['description']} "
                    f"{Fore.LIGHTBLACK_EX}[{c['uuid']}]{Fore.RESET}"
                )
                print(f"        {Fore.LIGHTBLACK_EX}Properties: {Fore.RESET}{props}")
        print()

    print(f"  {Fore.GREEN}[+] {len(services)} service(s) found.{Fore.RESET}\n")


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

def select_from_menu(items: list[dict], item_type: str = "item") -> dict | None:
    """Display a numbered menu and return the selected item."""
    if not items:
        return None

    print(f"\n{Fore.YELLOW}Available {item_type}s:{Fore.RESET}")
    for idx, item in enumerate(items, 1):
        if item_type == "device":
            print(
                f"  {Fore.LIGHTBLACK_EX}[{idx}]{Fore.RESET} "
                f"{Fore.LIGHTGREEN_EX}{item['address']}{Fore.RESET} — "
                f"{Fore.CYAN}{item['name']}{Fore.RESET}"
            )
        elif item_type == "service":
            print(
                f"  {Fore.LIGHTBLACK_EX}[{idx}]{Fore.RESET} "
                f"{Fore.LIGHTGREEN_EX}{item['name']}{Fore.RESET} | "
                f"Protocol: {Fore.CYAN}{item['protocol']}{Fore.RESET}"
            )
    print(f"  {Fore.LIGHTBLACK_EX}[0]{Fore.RESET} {Fore.RED}Exit{Fore.RESET}")

    while True:
        try:
            raw = input(f"\n{Fore.CYAN}Select {item_type} [0–{len(items)}]: {Fore.RESET}").strip()
            choice = int(raw)
            if choice == 0:
                return None
            if 1 <= choice <= len(items):
                return items[choice - 1]
            print(f"{Fore.RED}Invalid selection.{Fore.RESET}")
        except ValueError:
            print(f"{Fore.RED}Please enter a number.{Fore.RESET}")
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Cancelled.{Fore.RESET}")
            return None


def interactive_mode(use_ble: bool = False):
    """Interactive TUI: scan → pick device → enumerate services."""
    mode = "BLE" if use_ble else "BR/EDR"
    print_bordered(f"Interactive Mode ({mode})")
    print()

    devices = ble_scan() if use_ble else bredr_scan()
    display_devices(devices)
    if not devices:
        return

    device = select_from_menu(devices, "device")
    if not device:
        log_info("Exiting.")
        return

    print(
        f"\n{Fore.GREEN}✓ Selected:{Fore.RESET} "
        f"{Fore.LIGHTGREEN_EX}{device['name']}{Fore.RESET} "
        f"({Fore.CYAN}{device['address']}{Fore.RESET})\n"
    )

    print_bordered("Enumerating services...")
    services = (
        ble_enum_services(device["address"]) if use_ble
        else bredr_enum_services(device["address"])
    )
    display_services(services)
    if not services:
        return

    service = select_from_menu(services, "service")
    if service:
        print(
            f"\n{Fore.GREEN}✓ Service info:{Fore.RESET} "
            f"{Fore.LIGHTGREEN_EX}{service['name']}{Fore.RESET} | "
            f"UUID: {Fore.CYAN}{service['uuid']}{Fore.RESET}\n"
        )


# ============================================================================
# ADVERTISEMENT DATA PARSING
# ============================================================================

# BLE AD type codes → human-readable name
_AD_TYPES: dict[int, str] = {
    0x01: "Flags",
    0x02: "Incomplete 16-bit UUIDs",
    0x03: "Complete 16-bit UUIDs",
    0x04: "Incomplete 32-bit UUIDs",
    0x05: "Complete 32-bit UUIDs",
    0x06: "Incomplete 128-bit UUIDs",
    0x07: "Complete 128-bit UUIDs",
    0x08: "Shortened Local Name",
    0x09: "Complete Local Name",
    0x0A: "TX Power Level",
    0x16: "Service Data (16-bit UUID)",
    0x20: "Service Data (32-bit UUID)",
    0x21: "Service Data (128-bit UUID)",
    0xFF: "Manufacturer Specific",
}

def parse_advertisement_data(data: bytes | dict) -> dict:
    """
    Parse BLE advertisement data into a structured format.

    Accepts either:
      - a raw bytes object (packed AD structures)
      - a bleak AdvertisementData dict / mapping

    Returns a dictionary with human-readable parsed fields.
    """
    result: dict = {}

    # --- dict / bleak AdvertisementData path ---
    if isinstance(data, dict):
        if "local_name" in data and data["local_name"]:
            result["Complete Local Name"] = data["local_name"]
        if "tx_power" in data and data["tx_power"] is not None:
            result["TX Power Level"] = f"{data['tx_power']} dBm"
        if "service_uuids" in data and data["service_uuids"]:
            result["Service UUIDs"] = list(data["service_uuids"])
        if "service_data" in data and data["service_data"]:
            result["Service Data"] = {
                str(uuid): raw.hex() for uuid, raw in data["service_data"].items()
            }
        if "manufacturer_data" in data and data["manufacturer_data"]:
            result["Manufacturer Specific"] = {
                f"0x{cid:04X}": payload.hex()
                for cid, payload in data["manufacturer_data"].items()
            }
        return result

    # --- raw bytes path ---
    if not isinstance(data, (bytes, bytearray)):
        log_warn("parse_advertisement_data: unsupported data type, returning empty dict.")
        return result

    idx = 0
    while idx < len(data):
        if idx + 1 > len(data):
            break
        length = data[idx]
        if length == 0:
            break
        idx += 1
        if idx + length > len(data):
            break
        ad_type = data[idx]
        payload = data[idx + 1: idx + length]
        idx += length

        field_name = _AD_TYPES.get(ad_type, f"Unknown (0x{ad_type:02X})")

        if ad_type == 0x01:          # Flags
            result[field_name] = f"0x{payload[0]:02X}" if payload else "N/A"
        elif ad_type in (0x08, 0x09):  # Local names
            result[field_name] = payload.decode("utf-8", errors="replace")
        elif ad_type == 0x0A:        # TX Power
            result[field_name] = f"{payload[0]:+d} dBm" if payload else "N/A"
        elif ad_type == 0xFF:        # Manufacturer specific
            if len(payload) >= 2:
                company_id = int.from_bytes(payload[:2], "little")
                result[field_name] = {
                    "company_id": f"0x{company_id:04X}",
                    "data": payload[2:].hex(),
                }
            else:
                result[field_name] = payload.hex()
        else:
            result[field_name] = payload.hex()

    return result


# ============================================================================
# SERVICE CHARACTERISTICS
# ============================================================================

# Well-known GATT characteristic UUIDs (abbreviated 16-bit form)
_GATT_CHARACTERISTICS: dict[str, dict] = {
    "2a00": {"name": "Device Name",           "format": "utf-8"},
    "2a01": {"name": "Appearance",            "format": "uint16"},
    "2a04": {"name": "Peripheral Preferred Connection Parameters", "format": "struct"},
    "2a05": {"name": "Service Changed",       "format": "struct"},
    "2a19": {"name": "Battery Level",         "format": "uint8",  "unit": "%"},
    "2a24": {"name": "Model Number String",   "format": "utf-8"},
    "2a25": {"name": "Serial Number String",  "format": "utf-8"},
    "2a26": {"name": "Firmware Revision",     "format": "utf-8"},
    "2a27": {"name": "Hardware Revision",     "format": "utf-8"},
    "2a28": {"name": "Software Revision",     "format": "utf-8"},
    "2a29": {"name": "Manufacturer Name",     "format": "utf-8"},
    "2a2a": {"name": "IEEE 11073-20601 Regulatory Cert.", "format": "struct"},
    "2a37": {"name": "Heart Rate Measurement","format": "struct"},
    "2a38": {"name": "Body Sensor Location",  "format": "uint8"},
    "2a3f": {"name": "Alert Status",          "format": "uint8"},
    "2a46": {"name": "New Alert",             "format": "struct"},
    "2a6d": {"name": "Pressure",              "format": "uint32", "unit": "Pa"},
    "2a6e": {"name": "Temperature",           "format": "sint16", "unit": "°C (×0.01)"},
    "2a6f": {"name": "Humidity",              "format": "uint16", "unit": "% (×0.01)"},
}

def get_service_characteristics(uuid: str) -> dict:
    """
    Return detailed information about a GATT characteristic UUID.

    Accepts full 128-bit UUIDs (xxxxxxxx-0000-1000-8000-00805f9b34fb)
    or short 16-bit hex strings / ints.
    """
    import re

    # Normalise to lowercase string
    if isinstance(uuid, int):
        short = f"{uuid:04x}"
    else:
        uuid_str = uuid.lower().strip()
        # Extract short key from full 128-bit GATT UUID
        m = re.match(r"^0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb$", uuid_str)
        short = m.group(1) if m else uuid_str.replace("-", "").replace("0x", "")[:4]

    info = _GATT_CHARACTERISTICS.get(short)
    if info:
        return {
            "uuid":        uuid,
            "short_uuid":  f"0x{short.upper()}",
            "name":        info["name"],
            "data_format": info.get("format", "unknown"),
            "unit":        info.get("unit", ""),
            "known":       True,
        }

    return {
        "uuid":        uuid,
        "short_uuid":  f"0x{short.upper()}",
        "name":        "Unknown Characteristic",
        "data_format": "unknown",
        "unit":        "",
        "known":       False,
    }


# ============================================================================
# DATA EXPORT
# ============================================================================

def export_scan_results(devices: list[dict], format_type: str = "csv",
                        filepath: str | None = None) -> str:
    """
    Export scan results to CSV or JSON.

    Args:
        devices:     List of device dicts (output of ble_scan / bredr_scan).
        format_type: "csv" or "json".
        filepath:    Optional output path. Auto-generated if not provided.

    Returns the path of the written file.
    """
    if not devices:
        log_warn("export_scan_results: no devices to export.")
        return ""

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fmt = format_type.lower()

    if filepath is None:
        filepath = f"ble_scan_{ts}.{fmt}"

    if fmt == "json":
        try:
            with open(filepath, "w", encoding="utf-8") as fh:
                json.dump(devices, fh, indent=2, default=str)
        except OSError as exc:
            log_err(f"export_scan_results: failed to write JSON — {exc}")
            return ""

    elif fmt == "csv":
        # Collect all possible field names in insertion order
        fieldnames: list[str] = []
        for dev in devices:
            for k in dev:
                if k not in fieldnames:
                    fieldnames.append(k)

        try:
            with open(filepath, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(devices)
        except OSError as exc:
            log_err(f"export_scan_results: failed to write CSV — {exc}")
            return ""

    else:
        log_err(f"export_scan_results: unsupported format '{format_type}'. Use 'csv' or 'json'.")
        return ""

    log_info(f"Exported {len(devices)} device(s) → {filepath}")
    return filepath


# ============================================================================
# CONTINUOUS MONITORING
# ============================================================================

import gc as _gc

def monitor_continuous_scan(duration: int = 300, interval: float = 10.0,
                             callback=None, max_devices: int = 500) -> list[dict]:
    """
    Continuously scan for BLE devices over *duration* seconds.

    Args:
        duration:    Total monitoring time in seconds.
        interval:    Seconds per individual scan pass.
        callback:    Optional callable(devices) invoked after each pass.
        max_devices: Safety cap on the number of unique devices tracked in
                     memory to prevent unbounded growth during long runs.

    Returns aggregated list of unique devices seen during the session.
    """
    check_ble_available()
    seen: dict[str, dict] = {}
    end_time = time.monotonic() + duration
    pass_num = 0

    log_info(f"Continuous monitor started — {duration}s total, {interval}s per pass.")

    try:
        while time.monotonic() < end_time:
            pass_num += 1
            remaining = end_time - time.monotonic()
            scan_time = min(interval, remaining)
            if scan_time <= 0:
                break

            log_info(f"Pass {pass_num} — scanning {scan_time:.0f}s ...")
            try:
                devices = ble_scan(timeout=scan_time)
            except Exception as exc:
                log_warn(f"Pass {pass_num} failed: {exc}")
                devices = []

            for dev in devices:
                addr = dev["address"]
                dev["last_seen"] = datetime.datetime.now().isoformat()
                dev.setdefault("first_seen", dev["last_seen"])
                if addr not in seen:
                    if len(seen) >= max_devices:
                        log_warn(
                            f"Device cap ({max_devices}) reached — "
                            "skipping new device to limit memory use."
                        )
                        continue
                    seen[addr] = dev
                    log_info(f"  NEW  {addr}  {dev['name']}")
                else:
                    seen[addr].update(
                        rssi=dev.get("rssi"),
                        last_seen=dev["last_seen"],
                    )

            if callback:
                try:
                    callback(list(seen.values()))
                except Exception as exc:
                    log_warn(f"Callback error: {exc}")

            # Periodic garbage collection every 10 passes to reclaim memory
            if pass_num % 10 == 0:
                _gc.collect()
                log_info(f"  [GC] collected after pass {pass_num}.")

    except KeyboardInterrupt:
        log_warn("Continuous monitor interrupted by user.")
    finally:
        # Final GC on exit regardless of how the loop ended
        _gc.collect()

    log_info(f"Monitor finished — {len(seen)} unique device(s) observed.")
    return list(seen.values())


# ============================================================================
# SECURITY SCAN
# ============================================================================

# Known-vulnerable or interesting service UUIDs (16-bit, lowercase)
_SUSPICIOUS_UUIDS: dict[str, str] = {
    "1800": "Generic Access — device name / appearance exposed",
    "1801": "Generic Attribute — service change notifications",
    "180a": "Device Information — firmware/model/serial exposed",
    "180f": "Battery Service — battery level readable",
    "1812": "HID over GATT — keyboard/mouse emulation possible",
    "fe59": "Nordic DFU — firmware update possible (check auth)",
}

def perform_security_scan(target: str) -> dict:
    """
    Perform basic BLE security checks on a target device.

    Enumerates GATT services and flags potentially risky ones.

    Returns a report dict with 'findings' and 'risk_level'.
    """
    if not validate_mac(target):
        log_err(f"perform_security_scan: invalid MAC '{target}'")
        return {}

    check_ble_available()
    log_info(f"Security scan → {target}")

    try:
        services = ble_enum_services(target)
    except Exception as exc:
        log_err(f"perform_security_scan: service enumeration failed — {exc}")
        return {}
    findings: list[dict] = []

    for svc in services:
        uuid_short = svc.get("uuid", "").lower().replace("-", "")
        # Check both full and short form
        for short, reason in _SUSPICIOUS_UUIDS.items():
            if short in uuid_short:
                findings.append({
                    "severity": "MEDIUM",
                    "service":  svc["name"],
                    "uuid":     svc["uuid"],
                    "reason":   reason,
                })

        # Open (no-auth) writable characteristics are flagged HIGH
        for char in svc.get("characteristics", []):
            props = [p.lower() for p in char.get("properties", [])]
            if "write" in props or "write-without-response" in props:
                findings.append({
                    "severity": "HIGH",
                    "service":  svc["name"],
                    "char_uuid": char["uuid"],
                    "reason":   "Writable characteristic (no auth confirmed)",
                })

    risk_level = "LOW"
    if any(f["severity"] == "HIGH"   for f in findings): risk_level = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in findings): risk_level = "MEDIUM"

    report = {
        "target":     target,
        "timestamp":  datetime.datetime.now().isoformat(),
        "services":   len(services),
        "risk_level": risk_level,
        "findings":   findings,
    }

    # Pretty-print summary
    color = {"LOW": Fore.GREEN, "MEDIUM": Fore.YELLOW, "HIGH": Fore.RED}.get(risk_level, Fore.WHITE)
    print(f"\n  {Fore.CYAN}Security Scan Report{Fore.RESET}  →  {target}")
    print(f"  Risk level : {color}{risk_level}{Fore.RESET}")
    print(f"  Services   : {len(services)}")
    print(f"  Findings   : {len(findings)}")
    for f in findings:
        sev_color = Fore.RED if f["severity"] == "HIGH" else Fore.YELLOW
        print(f"    {sev_color}[{f['severity']}]{Fore.RESET} {f.get('service', '')} — {f['reason']}")
    print()

    return report


# ============================================================================
# DEVICE HISTORY  (SQLite-backed)
# ============================================================================

_DB_PATH = "ble_devices.db"

def _get_db() -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(_DB_PATH, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Write-Ahead Logging: reduces lock contention during long scans
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT    NOT NULL,
                name        TEXT,
                rssi        INTEGER,
                vendor      TEXT,
                device_type TEXT,
                seen_at     TEXT    NOT NULL
            )
        """)
        conn.commit()
        return conn
    except sqlite3.Error as exc:
        log_err(f"Database error: {exc}")
        raise


def get_device_history(mac_address: str, limit: int = 50) -> list[dict]:
    """
    Retrieve stored scan history for a specific MAC address from the local DB.

    Records are inserted automatically by create_device_database() /
    batch_enumerate(), or you can call _record_device() directly.
    """
    if not validate_mac(mac_address):
        log_err(f"get_device_history: invalid MAC '{mac_address}'")
        return []

    try:
        with _get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM device_history WHERE mac_address = ? ORDER BY seen_at DESC LIMIT ?",
                (mac_address.upper(), limit),
            ).fetchall()
    except sqlite3.Error as exc:
        log_err(f"get_device_history: database error — {exc}")
        return []

    history = [dict(r) for r in rows]
    log_info(f"History for {mac_address}: {len(history)} record(s) found.")
    return history


def _record_device(dev: dict):
    """Insert a single device observation into the local DB."""
    try:
        with _get_db() as conn:
            conn.execute(
                """INSERT INTO device_history
                   (mac_address, name, rssi, vendor, device_type, seen_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    dev.get("address", "").upper(),
                    dev.get("name", ""),
                    dev.get("rssi"),
                    dev.get("vendor", ""),
                    dev.get("type", "BLE"),
                    datetime.datetime.now().isoformat(),
                ),
            )
            conn.commit()
    except sqlite3.Error as exc:
        log_warn(f"_record_device: failed to save record — {exc}")


# ============================================================================
# BATCH ENUMERATION
# ============================================================================

def batch_enumerate(targets: list[str],
                    ble: bool = True,
                    delay: float = 1.0) -> dict[str, list[dict]]:
    """
    Enumerate GATT/SDP services on multiple devices in sequence.

    Args:
        targets: List of Bluetooth MAC addresses.
        ble:     True → BLE/GATT; False → BR/EDR SDP.
        delay:   Pause (seconds) between connections.

    Returns a dict mapping MAC → list of service dicts.
    """
    results: dict[str, list[dict]] = {}

    for idx, mac in enumerate(targets, 1):
        if not validate_mac(mac):
            log_warn(f"batch_enumerate: skipping invalid MAC '{mac}'")
            continue

        log_info(f"[{idx}/{len(targets)}] Enumerating {mac} ...")
        try:
            services = ble_enum_services(mac) if ble else bredr_enum_services(mac)
            results[mac] = services
            log_info(f"  → {len(services)} service(s) found.")
        except Exception as exc:
            log_warn(f"  → Failed: {exc}")
            results[mac] = []

        if idx < len(targets):
            time.sleep(delay)

    return results


# ============================================================================
# DEVICE REPORT
# ============================================================================

def generate_device_report(mac_address: str,
                            output_path: str | None = None) -> dict:
    """
    Generate a comprehensive report for a BLE device.

    Combines live service enumeration, security scan, OUI lookup, and
    stored history, then writes a JSON file.

    Returns the report dict.
    """
    if not validate_mac(mac_address):
        log_err(f"generate_device_report: invalid MAC '{mac_address}'")
        return {}

    check_ble_available()
    mac_upper = mac_address.upper()
    ts = datetime.datetime.now().isoformat()

    log_info(f"Generating report for {mac_upper} ...")

    services      = ble_enum_services(mac_upper)
    security      = perform_security_scan(mac_upper)
    history       = get_device_history(mac_upper)
    vendor        = lookup_vendor(mac_upper)

    report = {
        "generated_at":  ts,
        "mac_address":   mac_upper,
        "vendor":        vendor or "Unknown",
        "services":      services,
        "security_scan": security,
        "history":       history,
        "summary": {
            "service_count":  len(services),
            "risk_level":     security.get("risk_level", "N/A"),
            "history_count":  len(history),
        },
    }

    if output_path is None:
        safe_mac = mac_upper.replace(":", "")
        output_path = f"report_{safe_mac}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    try:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        log_info(f"Report saved → {output_path}")
    except OSError as exc:
        log_err(f"generate_device_report: failed to write report — {exc}")

    return report


# ============================================================================
# DEVICE FILTERING
# ============================================================================

def filter_devices_by_criteria(devices: list[dict], criteria: dict) -> list[dict]:
    """
    Filter a device list by one or more criteria.

    Supported criteria keys:
        name        (str)  — case-insensitive substring match on device name
        vendor      (str)  — case-insensitive substring match on vendor
        type        (str)  — exact match on device type (BLE / BR/EDR)
        min_rssi    (int)  — minimum RSSI value (e.g. -70)
        mac_prefix  (str)  — MAC address prefix (e.g. "FC:F1")

    Example:
        filter_devices_by_criteria(devices, {"min_rssi": -70, "vendor": "apple"})
    """
    filtered = []

    for dev in devices:
        match = True

        if "name" in criteria:
            if criteria["name"].lower() not in (dev.get("name") or "").lower():
                match = False

        if "vendor" in criteria:
            if criteria["vendor"].lower() not in (dev.get("vendor") or "").lower():
                match = False

        if "type" in criteria:
            if dev.get("type", "").upper() != criteria["type"].upper():
                match = False

        if "min_rssi" in criteria:
            rssi = dev.get("rssi")
            if rssi is None or rssi < criteria["min_rssi"]:
                match = False

        if "mac_prefix" in criteria:
            prefix = criteria["mac_prefix"].upper()
            if not dev.get("address", "").upper().startswith(prefix):
                match = False

        if match:
            filtered.append(dev)

    log_info(f"filter_devices_by_criteria: {len(filtered)}/{len(devices)} devices matched.")
    return filtered


# ============================================================================
# DEVICE DATABASE
# ============================================================================

def create_device_database(db_path: str = _DB_PATH) -> sqlite3.Connection:
    """
    Create (or open) the local SQLite device database and return the connection.

    Tables created:
        device_history  — per-observation log (MAC, name, RSSI, vendor, time)
        device_profiles — deduplicated device summary (most-recent data)
    """
    global _DB_PATH
    _DB_PATH = db_path

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS device_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT    NOT NULL,
            name        TEXT,
            rssi        INTEGER,
            vendor      TEXT,
            device_type TEXT,
            seen_at     TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS device_profiles (
            mac_address  TEXT PRIMARY KEY,
            name         TEXT,
            vendor       TEXT,
            device_type  TEXT,
            first_seen   TEXT,
            last_seen    TEXT,
            times_seen   INTEGER DEFAULT 1
        );

        CREATE INDEX IF NOT EXISTS idx_history_mac
            ON device_history (mac_address);
    """)
    conn.commit()
    log_info(f"Device database ready → {db_path}")
    return conn


def upsert_device_profile(dev: dict):
    """Insert or update a device in the device_profiles table."""
    mac = dev.get("address", "").upper()
    if not mac:
        return
    now = datetime.datetime.now().isoformat()

    try:
        with _get_db() as conn:
            existing = conn.execute(
                "SELECT times_seen FROM device_profiles WHERE mac_address = ?", (mac,)
            ).fetchone()

            if existing:
                conn.execute("""
                    UPDATE device_profiles
                    SET name=?, vendor=?, device_type=?, last_seen=?, times_seen=times_seen+1
                    WHERE mac_address=?
                """, (dev.get("name"), dev.get("vendor"), dev.get("type"), now, mac))
            else:
                conn.execute("""
                    INSERT INTO device_profiles
                        (mac_address, name, vendor, device_type, first_seen, last_seen, times_seen)
                    VALUES (?, ?, ?, ?, ?, ?, 1)
                """, (mac, dev.get("name"), dev.get("vendor"), dev.get("type"), now, now))
            conn.commit()
    except sqlite3.Error as exc:
        log_warn(f"upsert_device_profile: database error — {exc}")


# ============================================================================
# SIGNAL STRENGTH TREND
# ============================================================================

def get_signal_strength_trend(mac_address: str,
                               duration: int = 60,
                               interval: float = 5.0) -> list[dict]:
    """
    Track RSSI for a specific device over *duration* seconds.

    Args:
        mac_address: Target MAC address.
        duration:    Total tracking window in seconds.
        interval:    Seconds between scan passes.

    Returns a list of {"timestamp": ISO-str, "rssi": int} dicts (may be empty
    for passes where the device was not visible).
    """
    if not validate_mac(mac_address):
        log_err(f"get_signal_strength_trend: invalid MAC '{mac_address}'")
        return []

    check_ble_available()
    mac_upper = mac_address.upper()
    trend:    list[dict] = []
    end_time = time.monotonic() + duration

    log_info(f"RSSI trend for {mac_upper} — {duration}s window, {interval}s interval.")

    while time.monotonic() < end_time:
        remaining  = end_time - time.monotonic()
        scan_time  = min(interval, remaining)
        if scan_time <= 0:
            break

        try:
            devices = ble_scan(timeout=scan_time)
        except Exception as exc:
            log_warn(f"Scan error: {exc}")
            devices = []

        ts = datetime.datetime.now().isoformat()
        hit = next((d for d in devices if d["address"].upper() == mac_upper), None)

        if hit:
            rssi = hit.get("rssi")
            trend.append({"timestamp": ts, "rssi": rssi})
            log_info(f"  {ts}  RSSI={rssi}")
        else:
            trend.append({"timestamp": ts, "rssi": None})
            log_info(f"  {ts}  device not visible")

    log_info(f"RSSI trend complete — {len(trend)} sample(s) collected.")
    return trend


# ============================================================================
# PROXIMITY HELPERS
# ============================================================================

def count_nearby_devices(target_mac: str, rssi_threshold: int = -70) -> int:
    """Count how many history records for target_mac are above the RSSI threshold."""
    history = get_device_history(target_mac, limit=100)
    if not history:
        return 0
    nearby_count = 0
    for record in history:
        if record.get("rssi") is not None and record["rssi"] > rssi_threshold:
            nearby_count += 1
    return nearby_count


def get_proximity_report(target_mac: str) -> dict | None:
    """Generate a comprehensive proximity report for a device."""
    history = get_device_history(target_mac, limit=100)
    if not history:
        return None

    timestamps = [datetime.datetime.fromisoformat(r["seen_at"]) for r in history]
    time_diffs = [
        (timestamps[i] - timestamps[i - 1]).total_seconds()
        for i in range(1, len(timestamps))
    ]

    in_range_count = len(
        [r for r in history if r.get("rssi") is not None and r["rssi"] > -70]
    )
    avg_time_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 0

    rssi_values = [r["rssi"] for r in history if r["rssi"] is not None]
    return {
        "total_scans": len(history),
        "in_range_count": in_range_count,
        "avg_time_between_scans": avg_time_diff,
        "rssi_stats": {
            "avg": sum(rssi_values) / len(rssi_values) if rssi_values else None,
            "min": min(rssi_values) if rssi_values else None,
            "max": max(rssi_values) if rssi_values else None,
        },
    }


# ============================================================================
# CLI
# ============================================================================

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--headless", is_flag=True, default=False, help="Disable colours and formatting")
def cli(headless: bool):
    """BLEeding — Bluetooth/BLE Scanner and Service Enumerator"""
    logger.set_headless(headless)
    if not headless:
        print(BANNER)


@cli.command("list")
@click.option("--wait-time", "-w", default=5, show_default=True,
              help="Seconds to scan for BLE advertisements")
def list_cmd(wait_time: int):
    """Quick BLE device list (alias for: scan --ble --timeout N).

    Mirrors the btscanner 'list' interface for drop-in compatibility.
    """
    check_ble_available()
    devices = ble_scan(timeout=float(wait_time))
    if not devices:
        log_warn("No devices found.")
        return
    print(f"\n{'Address':<20} {'RSSI':<8} {'Vendor':<12} Name")
    print("-" * 60)
    for dev in sorted(devices, key=lambda d: d.get("rssi") or 0, reverse=True):
        vendor = dev.get("vendor") or ""
        print(f"{dev['address']:<20} {str(dev.get('rssi', 'N/A')):<8} {vendor:<12} {dev['name']}")
    print(f"\n[+] {len(devices)} device(s) found.")


@cli.command("scan")
@click.option("--ble", "-b", is_flag=True, default=False,
              help="Scan for BLE devices (default: BR/EDR)")
@click.option("--timeout", "-t", default=5, show_default=True,
              help="Scan duration in seconds (BLE only)")
def scan_cmd(ble: bool, timeout: int):
    """Scan for nearby Bluetooth devices."""
    if ble:
        check_ble_available()
        devices = ble_scan(timeout=float(timeout))
    else:
        check_bredr_available()
        devices = bredr_scan()
    display_devices(devices)


@cli.command("enum")
@click.argument("target")
@click.option("--ble", "-b", is_flag=True, default=False,
              help="Use BLE/GATT enumeration")
def enum_cmd(target: str, ble: bool):
    """Enumerate services on a Bluetooth device.

    TARGET is the Bluetooth MAC address, e.g. AA:BB:CC:DD:EE:FF
    """
    if not validate_mac(target):
        log_err(f"Invalid MAC address format: '{target}'. Expected XX:XX:XX:XX:XX:XX")
        sys.exit(1)
    if ble:
        check_ble_available()
        services = ble_enum_services(target)
    else:
        check_bredr_available()
        services = bredr_enum_services(target)
    display_services(services)


@cli.command("interactive")
@click.option("--ble", "-b", is_flag=True, default=False, help="Use BLE mode")
def interactive_cmd(ble: bool):
    """Interactive mode: scan → select device → enumerate services."""
    if ble:
        check_ble_available()
    else:
        check_bredr_available()
    interactive_mode(use_ble=ble)


@cli.command("export")
@click.option("--ble", "-b", is_flag=True, default=False,
              help="Scan BLE devices (default: BR/EDR)")
@click.option("--timeout", "-t", default=5, show_default=True,
              help="Scan duration in seconds (BLE only)")
@click.option("--format", "-f", "fmt", default="csv", show_default=True,
              type=click.Choice(["csv", "json"], case_sensitive=False),
              help="Export format")
@click.option("--output", "-o", default=None, help="Output file path")
def export_cmd(ble: bool, timeout: int, fmt: str, output: str | None):
    """Scan and export results to CSV or JSON."""
    if ble:
        check_ble_available()
        devices = ble_scan(timeout=float(timeout))
    else:
        check_bredr_available()
        devices = bredr_scan()
    if not devices:
        log_warn("No devices found.")
        return
    path = export_scan_results(devices, format_type=fmt, filepath=output)
    if path:
        print(f"{Fore.GREEN}[+] Saved to:{Fore.RESET} {path}")


@cli.command("monitor")
@click.option("--duration", "-d", default=300, show_default=True,
              help="Total monitoring time in seconds")
@click.option("--interval", "-i", default=10.0, show_default=True,
              help="Seconds per scan pass")
@click.option("--export", "-e", "export_fmt", default=None,
              type=click.Choice(["csv", "json"], case_sensitive=False),
              help="Auto-export results on completion")
def monitor_cmd(duration: int, interval: float, export_fmt: str | None):
    """Continuously scan for BLE devices over a time window."""
    check_ble_available()
    devices = monitor_continuous_scan(duration=duration, interval=interval)
    display_devices(devices)
    if export_fmt and devices:
        export_scan_results(devices, format_type=export_fmt)


@cli.command("security")
@click.argument("target")
def security_cmd(target: str):
    """Perform a basic BLE security scan on TARGET (MAC address)."""
    if not validate_mac(target):
        log_err(f"Invalid MAC address: '{target}'")
        sys.exit(1)
    check_ble_available()
    perform_security_scan(target)


@cli.command("report")
@click.argument("target")
@click.option("--output", "-o", default=None, help="JSON output file path")
def report_cmd(target: str, output: str | None):
    """Generate a full JSON report for TARGET (MAC address)."""
    if not validate_mac(target):
        log_err(f"Invalid MAC address: '{target}'")
        sys.exit(1)
    check_ble_available()
    generate_device_report(target, output_path=output)


@cli.command("trend")
@click.argument("target")
@click.option("--duration", "-d", default=60, show_default=True,
              help="Tracking window in seconds")
@click.option("--interval", "-i", default=5.0, show_default=True,
              help="Seconds between scans")
def trend_cmd(target: str, duration: int, interval: float):
    """Track RSSI trend for TARGET (MAC address) over time."""
    if not validate_mac(target):
        log_err(f"Invalid MAC address: '{target}'")
        sys.exit(1)
    check_ble_available()
    trend = get_signal_strength_trend(target, duration=duration, interval=interval)
    if not trend:
        log_warn("No RSSI samples collected.")
        return
    print(f"\n  {'Timestamp':<30} RSSI")
    print("  " + "-" * 40)
    for sample in trend:
        rssi_str = str(sample["rssi"]) if sample["rssi"] is not None else "—"
        print(f"  {sample['timestamp']:<30} {rssi_str}")
    print()


@cli.command("history")
@click.argument("mac")
@click.option("--limit", "-n", default=50, show_default=True,
              help="Maximum number of records to show")
def history_cmd(mac: str, limit: int):
    """Show stored scan history for a specific MAC address."""
    if not validate_mac(mac):
        log_err(f"Invalid MAC address: '{mac}'")
        sys.exit(1)
    records = get_device_history(mac, limit=limit)
    if not records:
        log_warn(f"No history found for {mac}.")
        return
    print(f"\n  History for {Fore.CYAN}{mac.upper()}{Fore.RESET}")
    print(f"  {'#':<4} {'Seen At':<28} {'RSSI':<7} {'Name'}")
    print("  " + "-" * 60)
    for i, r in enumerate(records, 1):
        print(f"  {i:<4} {r['seen_at']:<28} {str(r['rssi'] or '—'):<7} {r['name'] or ''}")
    print()


@cli.command("devices")
@click.argument("target")
@click.option("--threshold", "-t", default=-70, show_default=True,
              help="RSSI threshold for nearby devices")
def devices_cmd(target: str, threshold: int):
    """Show device statistics and nearby device count for TARGET."""
    if not validate_mac(target):
        log_err(f"Invalid MAC address: '{target}'")
        sys.exit(1)

    check_ble_available()

    history = get_device_history(target, limit=100)
    if not history:
        log_warn(f"No history found for {target}.")
        return

    total_scans = len(history)
    rssi_values = [r["rssi"] for r in history if r["rssi"] is not None]

    if rssi_values:
        avg_rssi = sum(rssi_values) / len(rssi_values)
        min_rssi = min(rssi_values)
        max_rssi = max(rssi_values)
    else:
        avg_rssi = min_rssi = max_rssi = None

    nearby_count = sum(
        1 for r in history
        if r.get("rssi") is not None and r["rssi"] > threshold
    )

    print(f"\n  Device Statistics for {Fore.CYAN}{target.upper()}{Fore.RESET}")
    print(f"  {'-'*50}")
    print(f"  Total scans: {total_scans}")
    print(f"  Nearby devices (RSSI > {threshold}): {nearby_count}")

    if rssi_values:
        print(f"  Average RSSI: {avg_rssi:.2f} dBm")
        print(f"  Min RSSI: {min_rssi} dBm")
        print(f"  Max RSSI: {max_rssi} dBm")

    print(f"  {'-'*50}")
    print(f"  Recent scans:")
    print(f"  {'#':<4} {'Seen At':<28} {'RSSI':<7} {'Name'}")
    print(f"  {'-'*60}")

    for i, r in enumerate(history[:10], 1):
        rssi_str = str(r["rssi"]) if r["rssi"] is not None else "—"
        print(f"  {i:<4} {r['seen_at']:<28} {rssi_str:<7} {r['name'] or ''}")

    print()


@cli.command("proximity")
@click.argument("target")
def proximity_cmd(target: str):
    """Generate a full proximity report for TARGET."""
    if not validate_mac(target):
        log_err(f"Invalid MAC address: '{target}'")
        sys.exit(1)

    check_ble_available()

    report = get_proximity_report(target)
    if not report:
        log_warn(f"No history found for {target}.")
        return

    print(f"\n  Proximity Report for {Fore.CYAN}{target.upper()}{Fore.RESET}")
    print(f"  {'='*60}")
    print(f"  Total scans: {report['total_scans']}")
    print(f"  In range (RSSI > -70dBm): {report['in_range_count']}")
    print(f"  Average time between scans: {report['avg_time_between_scans']:.2f} seconds")

    if report["rssi_stats"]["avg"] is not None:
        print(f"  RSSI Statistics:")
        print(f"    Average: {report['rssi_stats']['avg']:.2f} dBm")
        print(f"    Min: {report['rssi_stats']['min']} dBm")
        print(f"    Max: {report['rssi_stats']['max']} dBm")

    print(f"  {'='*60}")
    print()


@cli.command("vendors")
def vendors_cmd():
    """List known vendor OUI prefixes."""
    print(f"\n  {'Vendor':<12} OUI Prefix")
    print(f"  {'-'*12} {'-'*10}")
    for vendor, oui in sorted(VENDORS_OUI.items()):
        print(f"  {Fore.CYAN}{vendor:<12}{Fore.RESET} {Fore.LIGHTGREEN_EX}{oui}{Fore.RESET}")
    print()


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    if sys.version_info < (3, 9):
        print("Python 3.9+ required.")
        sys.exit(1)

    try:
        cli()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrupted.{Fore.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Fore.RESET}")
        sys.exit(1)
