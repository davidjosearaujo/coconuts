"""CLI entry point (`coconuts` / `python -m coconuts`): argument parsing and the static-vs-Frida race.

Usage, examples and requirements are in `coconuts --help` and the README.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import re
import sys
import tempfile
import threading

from .adb import DeviceError, adb_resolve_device, pull_apks
from .manifest import extract_engine_lib, read_apk_metadata
from .aes import aes_roll_from_flags
from .ciphers import (
    _xxtea_c,
    _xxtea_import_error,
    describe_key,
    detect_signature_prefix,
    normalize_key,
)
from .extract import collect_script_entries, extract_offline, split_plain_scripts
from .frida_dump import FileWriter, build_frida_script, resolve_frida_targets, run_frida_race
from .log import SUCCESS, ConsoleFormatter, flog, log, slog, use_color
from .pretty import prettify_dir
from .statickeys import _key_decrypts, _key_samples, recover_key_static, recover_xor_key_kp

DEFAULT_OUTPUT_DIR = "dumped_cocos_assets"

# A dotted identifier with no path separators, e.g. com.example.game — used to tell a package name
# apart from a library path or an output dir among the optional positional arguments.
_PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+\Z")


def _looks_like_package(value: str) -> bool:
    return "/" not in value and os.sep not in value and bool(_PACKAGE_RE.match(value))


def classify_positionals(values: list[str]) -> tuple[str | None, str | None, str | None, list[str]]:
    """Sort the free positionals into (lib, package, output), returning any leftovers.

    Both LIB and PACKAGE are optional now, so a lone positional is ambiguous; we disambiguate by
    shape: a ``.so``/existing file is the library, a dotted identifier is the package, and whatever
    is left is the output dir. This keeps the historical ``LIB PACKAGE [OUTPUT]`` order working.
    """
    remaining = list(values)
    lib = package = output = None
    for v in list(remaining):
        if v.endswith(".so") or os.path.isfile(v):
            lib = v
            remaining.remove(v)
            break
    for v in list(remaining):
        if _looks_like_package(v):
            package = v
            remaining.remove(v)
            break
    if remaining:
        output = remaining.pop(0)
    return lib, package, output, remaining


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="coconuts",
                                description="Dump/decrypt Cocos2d-JS / Cocos Creator / Cocos2d-x Lua scripts from an Android app.")
    p.add_argument("positional", nargs="*", metavar="LIB PACKAGE OUTPUT",
                   help="engine library (libcocos.so / libcocos2djs.so / libcocos2dlua.so, arm64), package name "
                        "(e.g. com.example.game) and output dir, in that order. With --apk, LIB and "
                        "PACKAGE may be omitted: the library is taken from the APK and the package "
                        "from its manifest. OUTPUT defaults to " + DEFAULT_OUTPUT_DIR + ".")
    p.add_argument("--lib", dest="lib_opt", metavar="PATH",
                   help="engine library path (same as the LIB positional; overrides it)")
    p.add_argument("--package", dest="package_opt", metavar="NAME",
                   help="package name (same as the PACKAGE positional; overrides it)")
    p.add_argument("-o", "--output", dest="output_opt", metavar="DIR",
                   help="output dir (same as the OUTPUT positional; overrides it)")
    p.add_argument("--device", help="adb serial / Frida device id (default: first USB device)")
    p.add_argument("--timeout", type=float, default=10.0, help="seconds to wait for the key (default: 10)")
    p.add_argument("--live-seconds", type=float, default=5.0,
                   help="keep the session open this long after the key to collect live dumps (default: 5)")
    p.add_argument("--static-only", action="store_true", help="skip Frida; recover the key from the lib's strings")
    p.add_argument("--key", help="known key (ASCII); skips key discovery")
    p.add_argument("--sign", help="explicit script header signature to strip (default: auto-detect)")
    p.add_argument("--aes-key", metavar="HEX",
                   help="EncryptManager AES key (hex); decrypt x-studio AES-CBC assets instead of XXTEA/XOR")
    p.add_argument("--aes-iv", metavar="HEX", default="",
                   help="EncryptManager AES IV (hex); default is 16 bytes of 0x01")
    p.add_argument("--aes-roll", type=int, default=5,
                   help="EncryptManager signature roll count (default: 5; auto-detected when captured via Frida)")
    p.add_argument("--apk", action="append",
                   help="local APK or directory of .jsc / .luac files to decrypt instead of pulling from device (repeatable)")
    p.add_argument("--all-splits", action="store_true",
                   help="pull all split_config.*.apk files instead of only base/feature APKs")
    p.add_argument("--pretty", action="store_true",
                   help="reformat the dumped .js files in place with jsbeautifier (minified one-liners become readable)")
    p.add_argument("-v", "--verbose", action="store_true", help="show debug messages")
    p.add_argument("--no-color", action="store_true", help="disable coloured output (also honours $NO_COLOR)")
    args = p.parse_args(argv)

    pos_lib, pos_package, pos_output, leftover = classify_positionals(args.positional)
    if leftover:
        p.error("unrecognised positional argument(s): " + " ".join(leftover))
    args.lib = args.lib_opt or pos_lib
    args.package = args.package_opt or pos_package
    args.output = args.output_opt or pos_output or DEFAULT_OUTPUT_DIR
    return args


def _finish(args) -> int:
    """Runs the post-dump steps once the output folder is complete."""
    if args.pretty:
        prettify_dir(args.output)
    return 0


def main(argv=None) -> int:
    args = parse_args(argv)
    handler = logging.StreamHandler()
    handler.setFormatter(ConsoleFormatter(color=use_color(args.no_color)))
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, handlers=[handler])
    if _xxtea_c is None:
        log.warning("Fast XXTEA unavailable; using the ~150x slower pure-Python version. "
                    "To fix: pip uninstall xxtea-py; pip install xxtea")
        log.debug("xxtea import error: %s", _xxtea_import_error)

    if args.lib is not None and not os.path.isfile(args.lib):
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

    # APKs come from the device unless --apk is given: fail fast if adb can't reach it. Pulling needs
    # the package name (there's no manifest to read it from until something is pulled), so require it.
    if not args.apk:
        if not args.package:
            log.error("PACKAGE is required when pulling from the device; pass it, or use --apk to "
                      "read a local APK (the package is then taken from its manifest).")
            return 1
        try:
            serial = adb_resolve_device(serial)
        except DeviceError as e:
            log.error("%s", e)
            return 1
    os.makedirs(args.output, exist_ok=True)

    try:
        # Keep TemporaryDirectory in main()'s outer scope so pulled APKs are NEVER deleted early
        with tempfile.TemporaryDirectory() as tmp:
            # With a local APK we can fill in whatever the user left off the command line: the package
            # from the manifest, and the engine library's base name (android.app.lib_name) for when
            # it isn't the usual libcocos.so / libcocos2djs.so.
            manifest_lib_name = None
            if args.apk:
                man_package, manifest_lib_name = read_apk_metadata(args.apk)
                if not args.package and man_package:
                    args.package = man_package
                    log.info("Package name from the APK manifest: %s", man_package)

            # Case 1: Static-only mode, a known XXTEA key, or an explicit AES key — go offline directly
            if args.static_only or aes is not None or (key is not None and args.apk):
                apk_paths = args.apk or pull_apks(args.package, serial, tmp, all_splits=args.all_splits)
                lib_path = args.lib
                # The XXTEA static search is the only thing that needs the library; a known key, an
                # AES key, or XOR-via-known-plaintext don't. So derive it only when it could be used,
                # and fail soft (XOR can still win) if the APK doesn't carry it.
                if lib_path is None and key is None and aes is None:
                    lib_name = manifest_lib_name if args.apk else read_apk_metadata(apk_paths)[1]
                    lib_path = extract_engine_lib(apk_paths, lib_name, tmp)
                    if lib_path is None:
                        log.warning("No engine library found in the APK(s); the XXTEA key search "
                                    "needs one. Falling back to XOR / known-plaintext only.")
                extract_offline(apk_paths, key, lib_path, args.output, forced_sign=forced_sign, aes=aes)
                return _finish(args)

            # Case 2: Dual-Track Race (Static background pull+solve vs. Dynamic Frida hook)
            # Spawning the game needs the package, and Frida needs the library up front to resolve its
            # hook offsets. Derive the library from --apk when LIB was omitted; without --apk there are
            # no local files yet, so LIB must be given (or use --static-only).
            if not args.package:
                log.error("PACKAGE is required to spawn the game under Frida; pass it, or use "
                          "--static-only with --apk.")
                return 1
            lib_path = args.lib
            if lib_path is None:
                if args.apk:
                    lib_path = extract_engine_lib(args.apk, manifest_lib_name, tmp)
                if lib_path is None:
                    log.error("LIB is required for the static+Frida race; pass it, add --apk so the "
                              "engine library can be read from the APK, or use --static-only.")
                    return 1

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
                        entries = collect_script_entries(stack, apks)
                    shared_state["entries"] = entries
                    if not entries:
                        slog.warning("No .jsc / .luac / .lua files found in the APK(s).")
                        return
                    slog.info("Found %d script(s) across %d input path(s).", len(entries), len(apks))
                    # Unencrypted Lua scripts are copied as-is later; only the rest need (and can test) a key
                    entries, _plain = split_plain_scripts(entries)
                    if not entries:
                        slog.info("None of the scripts are encrypted; no key needed.")
                        shared_state["static_searched"] = True
                        static_won.set()
                        return

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
                        lib_path, entries, sign=sign, abort_event=dynamic_won, high_prob_done=high_prob_done
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
                            lib_path, abort_event=static_won, high_prob_done=high_prob_done
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
                return _finish(args)

            # A key from Frida stops the static search, so make sure it actually decrypts the assets
            encrypted = split_plain_scripts(entries)[0] if entries else {}
            if dyn_key and not static_key and encrypted:
                sign = forced_sign if forced_sign is not None else detect_signature_prefix(list(encrypted.values()))
                samples = _key_samples(encrypted)
                if all(_key_decrypts(s, dyn_key, sign=sign) for s in samples):
                    flog.log(SUCCESS, "Key verified against %d script(s).", len(samples))
                else:
                    flog.warning("Captured key %s doesn't decrypt the APK's scripts; ignoring it.",
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
                None if shared_state["static_searched"] else lib_path,
                args.output,
                forced_sign=forced_sign,
                preloaded_entries=entries,
            )
            return _finish(args)

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
