"""Offline extraction: asset collection from APKs/dirs, path safety, and the XXTEA/XOR/AES decrypt loops."""

from __future__ import annotations

import contextlib
import os
import zipfile

from .aes import cocos_aes_decrypt
from .ciphers import (
    cocos_xxtea_decrypt,
    describe_key,
    detect_signature_prefix,
    unpack_payload,
    xor_decrypt,
)
from .log import SUCCESS, log
from .statickeys import _key_samples, recover_key_static, recover_xor_key_kp


def safe_join(base: str, rel: str) -> str:
    """Joins rel onto base, refusing paths that escape base (e.g. '../')."""
    base_real = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base_real, rel.replace("\\", "/").lstrip("/")))
    if os.path.commonpath([base_real, target]) != base_real:
        raise ValueError(f"path escapes output directory: {rel!r}")
    return target


def jsc_to_js(path: str) -> str:
    return path[:-1] if path.lower().endswith(".jsc") else path


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


def collect_jsc_entries(stack: contextlib.ExitStack, apk_paths: list[str]) -> dict[str, bytes]:
    """Collects .jsc files from APK zip(s) or directly from local directory path(s)."""
    return _collect_entries(stack, apk_paths, lambda rel: rel.endswith(".jsc"))


def collect_asset_entries(stack: contextlib.ExitStack, apk_paths: list[str]) -> dict[str, bytes]:
    """Collects every asset file (EncryptManager AES wraps all asset types, not only .jsc)."""
    return _collect_entries(stack, apk_paths, lambda rel: True)


def save_raw_jsc_fallback(entries: dict[str, bytes], out_dir: str) -> None:
    raw_dir = os.path.join(out_dir, "raw_jsc")
    log.info("Saving %d undecrypted .jsc file(s) to %s for manual inspection.", len(entries), raw_dir)
    for rel, blob in sorted(entries.items()):
        try:
            dst = safe_join(raw_dir, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(blob)
        except (OSError, ValueError) as e:
            log.warning("Could not save raw .jsc %s: %s", rel, e)


def _extract_offline_aes(stack: contextlib.ExitStack, apk_paths: list[str],
                         aes: tuple[bytes, bytes, int], out_dir: str) -> int:
    """EncryptManager AES path: wraps every asset type, so collect and process them all."""
    aes_key, aes_iv, aes_roll = aes
    entries = collect_asset_entries(stack, apk_paths)
    if not entries:
        log.warning("No asset files found in %d input path(s).", len(apk_paths))
        return 0

    # .jsc assets are always encrypted, so verify the key against them: once confirmed, a file that
    # doesn't decrypt is a genuinely unencrypted resource (copy-list) rather than a wrong-key failure.
    jsc_entries = {rel: blob for rel, blob in entries.items() if rel.lower().endswith(".jsc")}
    verified: bool | None = None
    if jsc_entries:
        samples = _key_samples(jsc_entries)
        verified = any(cocos_aes_decrypt(s, aes_key, aes_iv, roll=aes_roll) is not None for s in samples)
        if not verified:
            log.error("The AES key/iv/roll doesn't decrypt the .jsc assets (wrong key); nothing written.")
            save_raw_jsc_fallback(jsc_entries, out_dir)
            return 0
        log.log(SUCCESS, "AES key verified against %d .jsc file(s).", len(samples))
    else:
        log.warning("No .jsc files to verify the AES key against; files that don't decrypt are copied as-is.")

    log.info("Decrypting %d asset(s) into '%s' with EncryptManager AES-256-CBC key=%s iv=%s (roll=%d)...",
             len(entries), out_dir, aes_key.hex(), aes_iv.hex() or "<default>", aes_roll)
    decrypted = copied = skipped = failed = 0
    for rel, raw_blob in sorted(entries.items()):
        plain = cocos_aes_decrypt(raw_blob, aes_key, aes_iv, roll=aes_roll)
        if plain is not None:
            body, kind = unpack_payload(plain)
            ext_suffix = ".zip" if kind == "zip" else (".mozjs.jsc" if kind == "bytecode" else "")
            out_rel = jsc_to_js(rel) + ext_suffix
        else:
            body, out_rel = raw_blob, rel  # unencrypted resource (or unverifiable): preserve verbatim
        try:
            out_path = safe_join(out_dir, out_rel)
        except ValueError as e:
            failed += 1
            log.warning("Skipping: %s", e)
            continue
        if os.path.exists(out_path):  # live dumps take precedence
            skipped += 1
            continue
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(body)
        if plain is not None:
            decrypted += 1
        else:
            copied += 1

    log.log(SUCCESS, "Done: %d decrypted, %d copied as-is, %d skipped (already dumped live) into %s.",
            decrypted, copied, skipped, out_dir)
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

        entries = preloaded_entries if preloaded_entries is not None else collect_jsc_entries(stack, apk_paths)
        if not entries:
            log.warning("No .jsc files found in %d input path(s).", len(apk_paths))
            return 0
        if preloaded_entries is None:
            log.info("Found %d .jsc asset(s) across %d input path(s).", len(entries), len(apk_paths))

        xor_key: bytes | None = None
        sign = forced_sign if forced_sign is not None else detect_signature_prefix(list(entries.values()))
        if sign:
            log.info("Detected %d-byte .jsc signature prefix: %r (hex: %s)", len(sign), sign, sign.hex())

        if key is None:
            xor_key = recover_xor_key_kp(entries, sign=sign)
            if xor_key:
                log.log(SUCCESS, "XOR key recovered via known plaintext: %s", describe_key(xor_key))
            elif lib_path:
                key = recover_key_static(lib_path, entries, sign=sign)

            if key is None and xor_key is None:
                log.error("No working key found; run with -v for details, or pass --key if you know it.")
                save_raw_jsc_fallback(entries, out_dir)
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
            ext_suffix = ".zip" if kind == "zip" else (".mozjs.jsc" if kind == "bytecode" else "")
            out_rel = jsc_to_js(rel) + ext_suffix
            try:
                out_path = safe_join(out_dir, out_rel)
            except ValueError as e:
                failed += 1
                log.warning("Skipping: %s", e)
                continue
            if os.path.exists(out_path):  # live dumps take precedence
                skipped += 1
                continue
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(body)
            written += 1

        if failed and not (written or skipped):
            log.error("Every file failed to decrypt; the key is probably wrong for these assets.")
            save_raw_jsc_fallback(entries, out_dir)
            return written
        log.log(SUCCESS, "Done: %d file(s) decrypted to %s, %d skipped (already dumped live).",
                written, out_dir, skipped)
        if failed:
            log.warning("%d file(s) failed to decrypt (run with -v to list them).", failed)
        return written
