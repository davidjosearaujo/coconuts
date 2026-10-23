#!/usr/bin/env python3

# Usage:
#   coconuts <libcocos.so> <package> [output_dir] [options]
#   (or, from a checkout: python3 -m coconuts <libcocos.so> <package> [output_dir] [options])
#
# Examples:
#   # Parallel static + Frida key capture & dump, then offline decryption of APK assets
#   coconuts ./libcocos.so com.example.game ./out
#
#   # Keep collecting live (incl. hot-updated) scripts for 60s after the key is found
#   coconuts ./libcocos.so com.example.game ./out --live-seconds 60
#
#   # No Frida: try key candidates from the lib's strings against a local APK or raw_jsc folder
#   coconuts ./libcocos.so com.example.game ./out --static-only --apk ./base.apk
#
#   # x-studio / EncryptManager AES-CBC assets with a known key+iv (e.g. from a Frida capture)
#   coconuts ./libcocos.so com.example.game ./out --apk ./base.apk \
#       --aes-key e7895ce80904fced... --aes-iv 9f9da80fee3290bf...
#
# Requirements:
#   - pip install r2pipe frida-tools xxtea pycryptodome
#     (`xxtea`, not `xxtea-py`: both install a module named xxtea, but only `xxtea` has the API used
#      here; without it a ~150x slower pure-Python XXTEA is used.
#      pycryptodome is only needed for EncryptManager AES-CBC assets.)
#   - radare2 installed
#   - adb (unless --apk is used): from PATH, $ANDROID_HOME / $ANDROID_SDK_ROOT, or the default
#     Android Studio SDK location (~/Library/Android/sdk on macOS)

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import sys
import tempfile
import threading

from .adb import DeviceError, adb_resolve_device, pull_apks
from .aes import aes_roll_from_flags
from .ciphers import (
    _xxtea_c,
    _xxtea_import_error,
    describe_key,
    detect_signature_prefix,
    normalize_key,
)
from .extract import collect_jsc_entries, extract_offline
from .frida_dump import FileWriter, build_frida_script, resolve_frida_targets, run_frida_race
from .log import SUCCESS, ConsoleFormatter, flog, log, slog, use_color
from .statickeys import _key_decrypts, _key_samples, recover_key_static, recover_xor_key_kp

DEFAULT_OUTPUT_DIR = "dumped_cocos_assets"


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="coconuts",
                                description="Dump/decrypt Cocos2d-JS / Cocos Creator scripts from an Android app.")
    p.add_argument("lib", help="path to libcocos.so / libcocos2djs.so (arm64)")
    p.add_argument("package", help="target package name, e.g. com.example.game")
    p.add_argument("output", nargs="?", default=DEFAULT_OUTPUT_DIR, help=f"output dir (default: {DEFAULT_OUTPUT_DIR})")
    p.add_argument("--device", help="adb serial / Frida device id (default: first USB device)")
    p.add_argument("--timeout", type=float, default=10.0, help="seconds to wait for the key (default: 10)")
    p.add_argument("--live-seconds", type=float, default=5.0,
                   help="keep the session open this long after the key to collect live dumps (default: 5)")
    p.add_argument("--static-only", action="store_true", help="skip Frida; recover the key from the lib's strings")
    p.add_argument("--key", help="known key (ASCII); skips key discovery")
    p.add_argument("--sign", help="explicit .jsc header signature to strip (default: auto-detect)")
    p.add_argument("--aes-key", metavar="HEX",
                   help="EncryptManager AES key (hex); decrypt x-studio AES-CBC assets instead of XXTEA/XOR")
    p.add_argument("--aes-iv", metavar="HEX", default="",
                   help="EncryptManager AES IV (hex); default is 16 bytes of 0x01")
    p.add_argument("--aes-roll", type=int, default=5,
                   help="EncryptManager signature roll count (default: 5; auto-detected when captured via Frida)")
    p.add_argument("--apk", action="append",
                   help="local APK or directory of .jsc files to decrypt instead of pulling from device (repeatable)")
    p.add_argument("--all-splits", action="store_true",
                   help="pull all split_config.*.apk files instead of only base/feature APKs")
    p.add_argument("-v", "--verbose", action="store_true", help="show debug messages")
    p.add_argument("--no-color", action="store_true", help="disable coloured output (also honours $NO_COLOR)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    handler = logging.StreamHandler()
    handler.setFormatter(ConsoleFormatter(color=use_color(args.no_color)))
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, handlers=[handler])
    if _xxtea_c is None:
        log.warning("Fast XXTEA unavailable; using the ~150x slower pure-Python version. "
                    "To fix: pip uninstall xxtea-py; pip install xxtea")
        log.debug("xxtea import error: %s", _xxtea_import_error)

    if not os.path.isfile(args.lib):
        log.error("%s doesn't exist", args.lib)
        return 1

    key = normalize_key(args.key.encode("utf-8")) if args.key else None
    forced_sign = args.sign.encode("latin-1") if args.sign is not None else None
    serial = args.device

    aes: tuple[bytes, bytes, int] | None = None
    if args.aes_key is not None:
        try:
            aes = (bytes.fromhex(args.aes_key), bytes.fromhex(args.aes_iv), args.aes_roll)
        except ValueError:
            log.error("--aes-key / --aes-iv must be hex strings")
            return 1

    # APKs come from the device unless --apk is given: fail fast if adb can't reach it
    if not args.apk:
        try:
            serial = adb_resolve_device(serial)
        except DeviceError as e:
            log.error("%s", e)
            return 1
    os.makedirs(args.output, exist_ok=True)

    try:
        # Keep TemporaryDirectory in main()'s outer scope so pulled APKs are NEVER deleted early
        with tempfile.TemporaryDirectory() as tmp:
            # Case 1: Static-only mode, a known XXTEA key, or an explicit AES key — go offline directly
            if args.static_only or aes is not None or (key is not None and args.apk):
                apk_paths = args.apk or pull_apks(args.package, serial, tmp, all_splits=args.all_splits)
                extract_offline(apk_paths, key, args.lib, args.output, forced_sign=forced_sign, aes=aes)
                return 0

            # Case 2: Dual-Track Race (Static background pull+solve vs. Dynamic Frida hook)
            log.info("Racing the static key search against Frida...")
            static_won = threading.Event()
            dynamic_won = threading.Event()
            high_prob_done = threading.Event()
            shared_state: dict[str, object] = {
                "apks": [],
                "entries": None,
                "static_key": None,
                "static_searched": False,  # static key search ran to the end (not cut short by Frida)
            }

            def static_worker():
                try:
                    apks = args.apk or pull_apks(args.package, serial, tmp, all_splits=args.all_splits)
                    shared_state["apks"] = apks
                    with contextlib.ExitStack() as stack:
                        entries = collect_jsc_entries(stack, apks)
                    shared_state["entries"] = entries
                    if not entries:
                        slog.warning("No .jsc files found in the APK(s).")
                        return
                    slog.info("Found %d .jsc asset(s) across %d input path(s).", len(entries), len(apks))

                    if key is not None:
                        shared_state["static_key"] = key
                        static_won.set()
                        return

                    if dynamic_won.is_set():
                        slog.info("Frida already captured the key; skipping the static search.")
                        return

                    sign = forced_sign if forced_sign is not None else detect_signature_prefix(list(entries.values()))
                    if recover_xor_key_kp(entries, sign=sign) is not None:
                        shared_state["static_searched"] = True
                        static_won.set()
                        slog.info("XOR encryption detected via known plaintext.")
                        return

                    cand_key = recover_key_static(
                        args.lib, entries, sign=sign, abort_event=dynamic_won, high_prob_done=high_prob_done
                    )
                    shared_state["static_searched"] = cand_key is not None or not dynamic_won.is_set()
                    if cand_key:
                        shared_state["static_key"] = cand_key
                        static_won.set()
                except DeviceError as e:
                    slog.error("%s", e)
                except Exception as e:
                    slog.warning("Failed: %s", e)
                    slog.debug("details", exc_info=True)
                finally:
                    high_prob_done.set()

            static_thread = threading.Thread(target=static_worker, name="StaticSolver", daemon=True)
            static_thread.start()

            dyn_key: bytes | None = None
            aes_box: dict = {}
            writer = FileWriter(args.output)
            try:
                if key is None and not static_won.is_set():
                    try:
                        import frida
                        cocos_symbol, dump_off, key_off, key_is_std_string = resolve_frida_targets(
                            args.lib, abort_event=static_won, high_prob_done=high_prob_done
                        )
                        if not static_won.is_set():
                            device = frida.get_device(serial, timeout=5) if serial else frida.get_usb_device(timeout=5)
                            serial = device.id
                            script_src = build_frida_script(
                                cocos_symbol, dump_off, key_off, key_is_std_string=key_is_std_string
                            )
                            if not static_won.is_set():
                                dyn_key = run_frida_race(
                                    device, args.package, script_src, writer,
                                    args.timeout, args.live_seconds, static_won,
                                    dynamic_won=dynamic_won, aes_box=aes_box,
                                )
                                if dyn_key:
                                    dynamic_won.set()
                    except Exception as e:
                        if not static_won.is_set():
                            flog.warning("Failed (%s); continuing with the static track.", e)
                            flog.debug("details", exc_info=True)
            finally:
                writer.close()  # Flush any live dumps before offline extraction

            if static_thread.is_alive():
                log.info("Waiting for the static track to finish...")
                static_thread.join()

            static_key = shared_state["static_key"]
            entries = shared_state["entries"]
            apks = shared_state["apks"] or args.apk

            # EncryptManager AES captured by Frida: decrypt with key/iv/roll instead of XXTEA/XOR.
            # The captured flags carry the real roll (0 is valid: _aes_derive_sign_key treats it as 1 round).
            if aes_box and not static_key:
                aes = (aes_box["key"], aes_box["iv"], aes_roll_from_flags(aes_box["flags"]))
                if not apks:
                    log.error("No APK(s) available for offline extraction (pulling from the device failed).")
                    log.log(SUCCESS, "AES key captured before the failure: %s iv=%s",
                            describe_key(aes_box["key"]), aes_box["iv"].hex() or "<default>")
                    return 1
                extract_offline(apks, None, None, args.output,
                                preloaded_entries=entries, aes=aes)
                return 0

            # A key from Frida stops the static search, so make sure it actually decrypts the assets
            if dyn_key and not static_key and entries:
                sign = forced_sign if forced_sign is not None else detect_signature_prefix(list(entries.values()))
                samples = _key_samples(entries)
                if all(_key_decrypts(s, dyn_key, sign=sign) for s in samples):
                    flog.log(SUCCESS, "Key verified against %d .jsc file(s).", len(samples))
                else:
                    flog.warning("Captured key %s doesn't decrypt the APK's .jsc files; ignoring it.",
                                describe_key(dyn_key))
                    dyn_key = None
                    if not shared_state["static_searched"]:
                        slog.info("Resuming the search that Frida cut short...")

            final_key = static_key or dyn_key or key
            if not apks:
                log.error("No APK(s) available for offline extraction (pulling from the device failed).")
                if final_key:
                    log.log(SUCCESS, "Key found before the failure: %s", describe_key(final_key))
                return 1
            extract_offline(
                apks,
                final_key,
                None if shared_state["static_searched"] else args.lib,
                args.output,
                forced_sign=forced_sign,
                preloaded_entries=entries,
            )
            return 0

    except DeviceError as e:
        log.error("%s", e)
        return 1
    except RuntimeError as e:
        # e.g. pycryptodome missing for AES (_load_aes); surface it cleanly, not as a traceback
        log.error("%s", e)
        return 1
    except KeyboardInterrupt:
        log.warning("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
