"""Offline extraction: script collection from APKs/dirs, path safety, and the XXTEA/XOR/AES decrypt loops.

Scripts are Cocos JS (.jsc) and Cocos Lua (.luac, and .lua: the Lua loader decrypts any chunk that
starts with the signature, whatever its extension).
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import zipfile

from .aes import cocos_aes_decrypt
from .ciphers import (
    LUA_MAGICS,
    LuaBytecode,
    cocos_xxtea_decrypt,
    describe_key,
    describe_lua_bytecode,
    detect_signature_prefix,
    unpack_payload,
    xor_decrypt,
)
from .log import SUCCESS, log
from .statickeys import (
    _key_samples,
    recover_key_and_sign_static,
    recover_key_static,
    recover_xor_key_kp,
)


@functools.lru_cache(maxsize=16)
def _realpath(path: str) -> str:
    """realpath() stats every component, and the output dir is resolved once per written file."""
    return os.path.realpath(path)


def safe_join(base: str, rel: str) -> str:
    """Joins rel onto base, refusing paths that escape base (e.g. '../')."""
    base_real = _realpath(base)
    target = os.path.realpath(os.path.join(base_real, rel.replace("\\", "/").lstrip("/")))
    if os.path.commonpath([base_real, target]) != base_real:
        raise ValueError(f"path escapes output directory: {rel!r}")
    return target


SCRIPT_EXTS = (".jsc", ".luac", ".lua")
RAW_FALLBACK_DIR = "raw_scripts"


def jsc_to_js(path: str) -> str:
    return path[:-1] if path.lower().endswith(".jsc") else path


def output_name(rel: str, kind: str) -> str:
    """Output path for a decrypted script: .jsc -> .js, .luac -> .lua, plus a suffix for what the
    payload turned out to be (zip archive, SpiderMonkey bytecode, or a compiled Lua chunk)."""
    base = rel[:-1] if rel.lower().endswith((".jsc", ".luac")) else rel
    if kind == "zip":
        return base + ".zip"
    if kind == "bytecode":
        return base + ".mozjs.jsc"
    if kind == "luabytecode" and base.lower().endswith(".lua"):
        return base + "c"  # still compiled: keep .luac, now decrypted
    return base


def lua_live_name(chunk_name: str, body: bytes) -> str:
    """Output path for a live Lua dump. Chunk names are file paths ('@src/main.lua'), sometimes with
    an assets/ prefix, or module names ('app.MyApp') for scripts loaded from a zip bundle."""
    name = chunk_name.lstrip("@=")
    if name.startswith("assets/"):
        name = name[len("assets/"):]
    if not name.lower().endswith((".lua", ".luac")):
        name += ".lua"
    return output_name(name, "luabytecode" if body.startswith(LUA_MAGICS) else "raw")


def is_plain_script(rel: str, blob: bytes) -> bool:
    """True for Lua scripts shipped unencrypted (compiled bytecode or source text), which the Lua
    loader runs as-is. .jsc files are always encrypted, so this is False for them."""
    if not rel.lower().endswith((".luac", ".lua")):
        return False
    if blob.startswith(LUA_MAGICS):
        return True
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return bool(text) and all(c.isprintable() or c in "\t\r\n" for c in text)


def split_plain_scripts(entries: dict[str, bytes]) -> tuple[dict[str, bytes], dict[str, bytes]]:
    """Splits entries into (encrypted, plain); only the encrypted ones need a key."""
    encrypted: dict[str, bytes] = {}
    plain: dict[str, bytes] = {}
    for rel, blob in entries.items():
        (plain if is_plain_script(rel, blob) else encrypted)[rel] = blob
    return encrypted, plain


def _collect_entries(stack: contextlib.ExitStack, apk_paths: list[str],
                     want) -> dict[str, bytes]:
    """Collects asset files matching want(rel_lower) from APK zip(s) or local directory path(s)."""
    entries: dict[str, bytes] = {}
    for path in apk_paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for fname in files:
                    full = os.path.join(root, fname)
                    rel = os.path.relpath(full, path).replace("\\", "/")
                    if rel.startswith("assets/"):
                        rel = rel[len("assets/"):]
                    if want(rel.lower()):
                        with open(full, "rb") as f:
                            entries.setdefault(rel, f.read())
            continue

        try:
            zf = stack.enter_context(zipfile.ZipFile(path))
        except (OSError, zipfile.BadZipFile) as e:
            log.warning("Skipping %s: %s", path, e)
            continue
        for info in zf.infolist():
            name = info.filename
            if info.is_dir() or not name.startswith("assets/"):
                continue
            rel = name[len("assets/"):]
            if want(rel.lower()):
                entries.setdefault(rel, zf.read(info))
    return entries


def collect_script_entries(stack: contextlib.ExitStack, apk_paths: list[str]) -> dict[str, bytes]:
    """Collects .jsc / .luac / .lua files from APK zip(s) or directly from local directory path(s)."""
    return _collect_entries(stack, apk_paths, lambda rel: rel.endswith(SCRIPT_EXTS))


def collect_scripts(apk_paths: list[str], logger: logging.Logger = log) -> dict[str, bytes]:
    """Collects the scripts from the input paths and reports how many there are."""
    with contextlib.ExitStack() as stack:
        entries = collect_script_entries(stack, apk_paths)
    if entries:
        logger.info("Found %d script(s) across %d input path(s).", len(entries), len(apk_paths))
    return entries


def choose_signature(forced: bytes | None, entries: dict[str, bytes],
                     exact: bytes | None = None) -> bytes:
    """The signature to strip: what the user passed, else what was read out of the engine
    library, else the prefix shared by the encrypted files."""
    if forced is not None:
        return forced
    if exact is not None:
        return exact
    return detect_signature_prefix(list(entries.values()))


def collect_asset_entries(stack: contextlib.ExitStack, apk_paths: list[str]) -> dict[str, bytes]:
    """Collects every asset file (EncryptManager AES wraps all asset types, not only scripts)."""
    return _collect_entries(stack, apk_paths, lambda rel: True)


class LuaBytecodeReport:
    """Counts the flavours of the compiled Lua chunks written in a run.

    A decrypted .luac gives no hint of what opens it, and the PUC Lua and LuaJIT toolchains need
    different decompilers, so the run reports which it produced.
    """

    def __init__(self) -> None:
        self._counts: dict[LuaBytecode, int] = {}

    def add(self, blob: bytes) -> None:
        flavour = describe_lua_bytecode(blob)
        if flavour is not None:
            self._counts[flavour] = self._counts.get(flavour, 0) + 1

    def log(self, logger: logging.Logger = log) -> None:
        for flavour, count in sorted(self._counts.items(), key=lambda kv: (-kv[1], kv[0].label)):
            logger.info("%d compiled Lua chunk(s): %s - decompile with %s",
                        count, flavour.label, flavour.tool)


def save_raw_fallback(entries: dict[str, bytes], out_dir: str) -> None:
    raw_dir = os.path.join(out_dir, RAW_FALLBACK_DIR)
    log.info("Saving %d undecrypted script(s) to %s for manual inspection.", len(entries), raw_dir)
    for rel, blob in sorted(entries.items()):
        try:
            dst = safe_join(raw_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(blob)
        except (OSError, ValueError) as e:
            log.warning("Could not save raw script %s: %s", rel, e)


WRITTEN, SKIPPED, FAILED = "written", "skipped", "failed"


def write_output(out_dir: str, rel: str, body: bytes, report: LuaBytecodeReport | None = None) -> str:
    """Writes one decrypted/copied file into the output tree.

    Returns WRITTEN, SKIPPED (a live dump already claimed the path and wins) or FAILED (the path
    escapes the output directory, or the write itself failed).
    """
    try:
        out_path = safe_join(out_dir, rel)
    except ValueError as e:
        log.warning("Skipping: %s", e)
        return FAILED
    if os.path.exists(out_path):  # live dumps take precedence
        return SKIPPED
    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(body)
    except OSError as e:
        log.warning("Could not write %s: %s", rel, e)
        return FAILED
    if report is not None:
        report.add(body)
    return WRITTEN


def _write_plain_scripts(plain: dict[str, bytes], out_dir: str, report: LuaBytecodeReport) -> int:
    """Copies unencrypted Lua scripts to the output (renamed like decrypted ones); returns the count."""
    if not plain:
        return 0
    log.info("%d Lua script(s) aren't encrypted; copying them as-is.", len(plain))
    copied = 0
    for rel, blob in sorted(plain.items()):
        out_rel = output_name(rel, unpack_payload(blob)[1])
        if write_output(out_dir, out_rel, blob, report) == WRITTEN:
            copied += 1
    return copied


def _extract_offline_aes(stack: contextlib.ExitStack, apk_paths: list[str],
                         aes: tuple[bytes, bytes, int], out_dir: str) -> int:
    """EncryptManager AES path: wraps every asset type, so collect and process them all."""
    aes_key, aes_iv, aes_roll = aes
    entries = collect_asset_entries(stack, apk_paths)
    if not entries:
        log.warning("No asset files found in %d input path(s).", len(apk_paths))
        return 0

    # Encrypted scripts are a safe test of the key: once it's confirmed, a file that doesn't decrypt
    # is a genuinely unencrypted resource (copy-list) rather than a wrong-key failure.
    script_entries, _ = split_plain_scripts(
        {rel: blob for rel, blob in entries.items() if rel.lower().endswith(SCRIPT_EXTS)})
    verified: bool | None = None
    if script_entries:
        samples = _key_samples(script_entries)
        verified = any(cocos_aes_decrypt(s, aes_key, aes_iv, roll=aes_roll) is not None for s in samples)
        if not verified:
            log.error("The AES key/iv/roll doesn't decrypt the encrypted scripts (wrong key); nothing written.")
            save_raw_fallback(script_entries, out_dir)
            return 0
        log.log(SUCCESS, "AES key verified against %d script(s).", len(samples))
    else:
        log.warning("No encrypted scripts to verify the AES key against; files that don't decrypt are copied as-is.")

    log.info("Decrypting %d asset(s) into '%s' with EncryptManager AES-256-CBC key=%s iv=%s (roll=%d)...",
             len(entries), out_dir, aes_key.hex(), aes_iv.hex() or "<default>", aes_roll)
    report = LuaBytecodeReport()
    decrypted = copied = skipped = failed = 0
    for rel, raw_blob in sorted(entries.items()):
        plain = cocos_aes_decrypt(raw_blob, aes_key, aes_iv, roll=aes_roll)
        if plain is not None:
            body, kind = unpack_payload(plain)
            out_rel = output_name(rel, kind)
        else:
            body, out_rel = raw_blob, rel  # unencrypted resource (or unverifiable): preserve verbatim
        result = write_output(out_dir, out_rel, body, report)
        if result == FAILED:
            failed += 1
        elif result == SKIPPED:
            skipped += 1
        elif plain is not None:
            decrypted += 1
        else:
            copied += 1

    log.log(SUCCESS, "Done: %d decrypted, %d copied as-is, %d skipped (already dumped live) into %s.",
            decrypted, copied, skipped, out_dir)
    report.log()
    if failed:
        log.warning("%d file(s) skipped (unsafe output path).", failed)
    return decrypted


def extract_offline(
    apk_paths: list[str],
    key: bytes | None,
    lib_path: str | None,
    out_dir: str,
    forced_sign: bytes | None = None,
    preloaded_entries: dict[str, bytes] | None = None,
    aes: tuple[bytes, bytes, int] | None = None,
) -> int:
    with contextlib.ExitStack() as stack:
        if aes is not None:
            return _extract_offline_aes(stack, apk_paths, aes, out_dir)

        entries = preloaded_entries if preloaded_entries is not None else collect_scripts(apk_paths)
        if not entries:
            log.warning("No .jsc / .luac / .lua files found in %d input path(s).", len(apk_paths))
            return 0

        report = LuaBytecodeReport()
        entries, plain = split_plain_scripts(entries)
        copied = _write_plain_scripts(plain, out_dir, report)
        if not entries:
            log.log(SUCCESS, "Done: none of the scripts are encrypted; %d copied to %s.", copied, out_dir)
            report.log()
            return copied

        xor_key: bytes | None = None

        # The engine passes its key and signature together to setXXTEAKeyAndSign, so when both can
        # be read from the library there is no need to guess the signature from a common prefix.
        exact_sign: bytes | None = None
        if key is None and lib_path:
            exact = recover_key_and_sign_static(lib_path, entries)
            if exact is not None:
                key, exact_sign = exact

        sign = choose_signature(forced_sign, entries, exact_sign)
        if sign:
            log.info("Detected %d-byte script signature prefix: %r (hex: %s)", len(sign), sign, sign.hex())

        if key is None:
            xor_key = recover_xor_key_kp(entries, sign=sign)
            if xor_key:
                log.log(SUCCESS, "XOR key recovered via known plaintext: %s", describe_key(xor_key))
            elif lib_path:
                key = recover_key_static(lib_path, entries, sign=sign)

            if key is None and xor_key is None:
                log.error("No working key found; run with -v for details, or pass --key if you know it.")
                save_raw_fallback(entries, out_dir)
                return 0

        cipher_desc = f"XOR key {describe_key(xor_key)}" if xor_key else f"XXTEA key {describe_key(key)}"

        log.info("Decrypting %d asset(s) into '%s' with %s...", len(entries), out_dir, cipher_desc)
        written = skipped = failed = 0
        for rel, raw_blob in sorted(entries.items()):
            plain = (
                xor_decrypt(raw_blob, xor_key, sign=sign)
                if xor_key
                else cocos_xxtea_decrypt(raw_blob, key, sign=sign)
            )
            if plain is None:
                failed += 1
                log.debug("Decryption failed: %s", rel)
                continue
            body, kind = unpack_payload(plain)
            result = write_output(out_dir, output_name(rel, kind), body, report)
            if result == FAILED:
                failed += 1
            elif result == SKIPPED:
                skipped += 1
            else:
                written += 1

        if failed and not (written or skipped):
            log.error("Every file failed to decrypt; the key is probably wrong for these assets.")
            save_raw_fallback(entries, out_dir)
            return written + copied
        log.log(SUCCESS, "Done: %d file(s) decrypted to %s, %d skipped (already dumped live).",
                written, out_dir, skipped)
        report.log()
        if failed:
            log.warning("%d file(s) failed to decrypt (run with -v to list them).", failed)
        return written + copied
