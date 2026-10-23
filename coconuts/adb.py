"""adb device resolution and APK pulling, degrading cleanly to a DeviceError when adb is unusable."""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess

from .log import log

# Skip Android config splits (locale, density, ABI) that never contain assets/*.jsc
SKIP_SPLIT_RE = re.compile(r"(^|/)split_config\.[a-z0-9_]+\.apk$", re.IGNORECASE)

# Seconds before a non-pull adb command is considered hung (first call may also start the adb server)
ADB_TIMEOUT = 30.0


class DeviceError(RuntimeError):
    """adb is missing, no usable device is connected, or pulling from the device failed."""


@functools.lru_cache(maxsize=None)
def find_adb() -> str | None:
    """adb from PATH, else from the Android SDK (Android Studio often doesn't put it on PATH)."""
    found = shutil.which("adb")
    if found:
        return found
    sdk_dirs = [
        os.environ.get("ANDROID_HOME"),
        os.environ.get("ANDROID_SDK_ROOT"),
        os.path.expanduser("~/Library/Android/sdk"),  # Android Studio default on macOS
        os.path.expanduser("~/Android/Sdk"),          # ... and on Linux
    ]
    for sdk in sdk_dirs:
        if sdk:
            cand = os.path.join(sdk, "platform-tools", "adb")
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def adb_base(serial: str | None) -> list[str]:
    return [find_adb() or "adb"] + (["-s", serial] if serial else [])


def _adb_error_text(output: str) -> str:
    # Skip adb server start-up chatter ("* daemon not running; starting now at tcp:5037")
    lines = [ln.strip() for ln in (output or "").splitlines() if ln.strip() and not ln.lstrip().startswith("*")]
    return lines[0] if lines else ""


def adb_run(serial: str | None, args: list[str], timeout: float | None = ADB_TIMEOUT,
            check: bool = True) -> subprocess.CompletedProcess:
    cmd = adb_base(serial) + args
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)
    except FileNotFoundError:
        raise DeviceError("adb not found in PATH, $ANDROID_HOME, $ANDROID_SDK_ROOT or ~/Library/Android/sdk "
                          "(install Android platform-tools, or use --apk with local files)") from None
    except subprocess.TimeoutExpired:
        raise DeviceError(f"'{' '.join(cmd)}' timed out after {timeout:.0f}s; is the device responsive?") from None
    if check and res.returncode != 0:
        detail = _adb_error_text(res.stderr) or _adb_error_text(res.stdout) or f"exit code {res.returncode}"
        raise DeviceError(f"'{' '.join(cmd)}' failed: {detail}")
    return res


def adb_resolve_device(serial: str | None) -> str:
    """Checks that adb can reach a single booted device and returns its serial."""
    devices: dict[str, str] = {}
    for line in adb_run(None, ["devices"]).stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("List of devices"):
            continue
        parts = line.split(None, 1)
        devices[parts[0]] = parts[1].strip() if len(parts) > 1 else "unknown"

    if serial is None:
        if not devices:
            raise DeviceError("No Android device or emulator found by adb. Start an emulator or connect a device "
                              "(check 'adb devices'), or use --apk with local files.")
        ready = [s for s, state in devices.items() if state == "device"]
        if len(ready) > 1:
            raise DeviceError(f"Multiple devices connected ({', '.join(ready)}); pick one with --device <serial>.")
        serial = ready[0] if ready else next(iter(devices))
    elif serial not in devices:
        connected = ", ".join(f"{s} [{st}]" for s, st in devices.items()) or "none"
        raise DeviceError(f"Device {serial!r} not found by adb (connected: {connected}).")

    state = devices[serial]
    if state == "unauthorized":
        raise DeviceError(f"Device {serial} is unauthorized; accept the USB debugging prompt on the device and retry.")
    if state == "offline":
        raise DeviceError(f"Device {serial} is offline; wait for the emulator to finish starting, "
                          f"or try 'adb kill-server' and reconnect.")
    if state != "device":
        raise DeviceError(f"Device {serial} is not ready (state: {state}).")

    boot = adb_run(serial, ["shell", "getprop", "sys.boot_completed"], check=False)
    if boot.returncode != 0 or boot.stdout.strip() != "1":
        detail = _adb_error_text(boot.stderr)
        raise DeviceError(f"Device {serial} hasn't finished booting yet{f' ({detail})' if detail else ''}; "
                          f"wait for the home screen and retry.")
    log.info("Using adb device %s", serial)
    return serial


def pull_apks(package: str, serial: str | None, dest_dir: str, all_splits: bool = False) -> list[str]:
    res = adb_run(serial, ["shell", "pm", "path", package], check=False)
    device_paths = [line.strip()[len("package:"):] for line in res.stdout.splitlines()
                    if line.strip().startswith("package:")]
    if not device_paths:
        # `pm path` exits non-zero with no output for a missing package; anything on stderr is an adb error
        detail = _adb_error_text(res.stderr)
        if res.returncode != 0 and detail:
            raise DeviceError(f"Could not query package {package!r}: {detail}")
        raise DeviceError(f"Package {package!r} not found on device")

    if not all_splits:
        filtered = [p for p in device_paths if not SKIP_SPLIT_RE.search(p)]
        skipped_count = len(device_paths) - len(filtered)
        if filtered and skipped_count:
            log.info("Skipping %d config split APK(s) (use --all-splits to pull everything).", skipped_count)
            device_paths = filtered

    local = []
    for i, dev_path in enumerate(device_paths):
        dst = os.path.join(dest_dir, f"{i:02d}_{os.path.basename(dev_path)}")
        log.info("Pulling %s", dev_path)
        adb_run(serial, ["pull", dev_path, dst], timeout=None)
        local.append(dst)
    return local
