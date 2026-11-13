"""Offline extraction: script collection from APKs/dirs, path safety, and the XXTEA/XOR/AES decrypt loops.

Scripts are Cocos JS (.jsc) and Cocos Lua (.luac, and .lua: the Lua loader decrypts any chunk that
starts with the signature, whatever its extension).
"""

from __future__ import annotations

import collections
import contextlib
import functools
import io
import logging
import os
import re
import zipfile
from collections.abc import Callable, Iterator

from .aes import cocos_aes_decrypt
from .ciphers import (
    LUA_MAGICS,
    ZIP_MAGIC,
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
    _key_decrypts,
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
        return base if base.lower().endswith(".zip") else base + ".zip"
    if kind == "bytecode":
        return base + ".mozjs.jsc"
    if kind == "luabytecode":
        # Still compiled: keep .luac, now decrypted. A name that says nothing (a bundle entry is
        # a module name with the extension stripped) gets one, so the output says what it holds.
        return base + "c" if base.lower().endswith(".lua") else base + ".luac"
    return base


# The app's writable directory, which is where a hot update puts its scripts and so where their
# chunk names point: /data/user/0/<pkg>/files/, /data/data/<pkg>/files/, or the external-storage
# equivalents. Cocos's getWritablePath() is this directory.
_WRITABLE_DIR = re.compile(
    r"^/(?:data/(?:user/\d+|data)|(?:storage/emulated/\d+|sdcard)/Android/data)/[^/]+/(?:files|cache)/")


def lua_live_name(chunk_name: str, body: bytes) -> str:
    """Output path for a live Lua dump. Chunk names are full file paths as Cocos resolves them
    ('assets/src/main.lua'), absolute paths in the writable directory for hot updates, or module
    names ('app.MyApp') for scripts loaded from a zip bundle. A leading '@' or '=' (plain Lua's own
    convention, which Cocos doesn't use) is dropped too."""
    name = _WRITABLE_DIR.sub("", chunk_name.lstrip("@="))
    if name.startswith("assets/"):
        name = name[len("assets/"):]
    if not name.lower().endswith((".lua", ".luac")):
        name += ".lua"
    return output_name(name, "luabytecode" if body.startswith(LUA_MAGICS) else "raw")


def is_plain_script(rel: str, blob: bytes) -> bool:
    """True for anything shipped unencrypted that the Lua loader runs as-is: compiled bytecode or
    source text. .jsc files are always encrypted, so this is False for them.

    What a file holds decides, not what it is called. Callers only ask about things already
    established to be scripts or bundle entries, and a bundle's entries are module names with no
    extension (see is_script_member) — judging those by name would call an unencrypted chunk
    encrypted and send the run looking for a key that doesn't exist.
    """
    if rel.lower().endswith(".jsc"):
        return False
    if blob.startswith(LUA_MAGICS):
        return True  # a compiled chunk, whatever the file is called
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


def _read_file(path: str, n: int | None = None) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def _read_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, n: int | None = None) -> bytes:
    with zf.open(info) as f:
        return f.read(n)


def _iter_assets(stack: contextlib.ExitStack,
                 apk_paths: list[str]) -> Iterator[tuple[str, int, Callable[..., bytes]]]:
    """Every asset in the APK zip(s) / directories as (path under assets/, size, read), where
    read(n) returns the first n bytes (all of them by default) and nothing is read until asked."""
    for path in apk_paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for fname in files:
                    full = os.path.join(root, fname)
                    rel = os.path.relpath(full, path).replace("\\", "/")
                    if rel.startswith("assets/"):
                        rel = rel[len("assets/"):]
                    yield rel, os.path.getsize(full), functools.partial(_read_file, full)
            continue

        try:
            zf = stack.enter_context(zipfile.ZipFile(path))
        except (OSError, zipfile.BadZipFile) as e:
            log.warning("Skipping %s: %s", path, e)
            continue
        for info in zf.infolist():
            if info.is_dir() or not info.filename.startswith("assets/"):
                continue
            yield info.filename[len("assets/"):], info.file_size, functools.partial(_read_member, zf, info)


Asset = tuple[int, Callable[..., bytes]]  # (size, read): see _iter_assets


def _asset_index(stack: contextlib.ExitStack, apk_paths: list[str]) -> dict[str, Asset]:
    """Every asset by path, without reading any of them. The first input to carry a path wins."""
    index: dict[str, Asset] = {}
    for rel, size, read in _iter_assets(stack, apk_paths):
        index.setdefault(rel, (size, read))
    return index


def _collect_entries(index: dict[str, Asset], want, max_size: int | None = None) -> dict[str, bytes]:
    """Reads the assets whose path satisfies want(rel_lower); files over max_size bytes are left alone."""
    entries: dict[str, bytes] = {}
    for rel, (size, read) in index.items():
        if not want(rel.lower()):
            continue
        if max_size is not None and size > max_size:
            log.debug("Skipping %s: %d bytes is over the %d byte limit.", rel, size, max_size)
            continue
        entries[rel] = read()
    return entries


BUNDLE_EXT = ".zip"
COLLECTED_EXTS = SCRIPT_EXTS + (BUNDLE_EXT,)   # what collection looks at before anything is read
MAX_SCRIPT_BYTES = 256 * 1024 * 1024  # a script bundle bigger than this is a resource pack
MIN_SIGN_LEN = 2                      # a shorter signature would match arbitrary assets


def is_script_member(name: str, head: bytes) -> bool:
    """True when a zip entry is a script, by its name or by what it starts with.

    LuaStack::loadChunksFromZIP registers each entry under its own name with the extension
    stripped ('app.config.ConstantsConfig'), so the entries of a real Lua bundle often carry no
    extension at all and only their first bytes give them away. `head` need only be the first
    four bytes.
    """
    return name.lower().endswith(SCRIPT_EXTS) or head.startswith(LUA_MAGICS)


def _bundle_members(blob: bytes) -> dict[str, bytes] | None:
    """The entries of a zip that is a script bundle, or None if it isn't a zip or holds no script.

    One identifiable entry is enough: loadChunksFromZIP registers every entry of the zip it is
    given as a chunk, so the rest are chunks too — including any encrypted inside the bundle,
    which start with a signature instead of a header anything could recognise. A zip with no
    script in it is a resource pack, and only the first four bytes of its entries are ever read,
    so it is never decompressed whole.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            infos = [i for i in zf.infolist() if not i.is_dir()]
            # Names first: that pass is central-directory work already done, where reading heads
            # opens and inflates each entry. Only a bundle named like this game's needs the heads.
            if not (any(i.filename.lower().endswith(SCRIPT_EXTS) for i in infos)
                    or any(is_script_member(i.filename, _read_member(zf, i, 4)) for i in infos)):
                return None
            return {i.filename: zf.read(i) for i in infos}
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError) as e:
        log.debug("Not a readable zip: %s", e)
        return None


def _flatten_plain_bundles(entries: dict[str, bytes]) -> dict[str, bytes]:
    """Replaces each unencrypted .zip by the scripts inside it.

    Lua games often ship their scripts as a zip that LuaStack::loadChunksFromZIP registers as
    modules. Taken apart here, the entries go through the same plain / encrypted handling as any
    other script, so an entry that is itself encrypted still counts as a sample for the key
    search. A zip with no scripts in it is a resource pack and is dropped. A .zip that isn't a
    zip at all is an encrypted bundle and stays as it is, to be decrypted and unpacked later.

    Entries are recognised by content as well as by name, because loadChunksFromZIP strips the
    extension off the module names it registers (see is_script_member).
    """
    flat: dict[str, bytes] = {}
    bundles: list[tuple[str, dict[str, bytes]]] = []
    for rel, blob in entries.items():
        if rel.lower().endswith(BUNDLE_EXT) and blob.startswith(ZIP_MAGIC):
            members = _bundle_members(blob)
            if members:
                bundles.append((rel, members))
        else:
            flat[rel] = blob

    # A game that ships one bundle per ABI (game32.zip and game64.zip, the same modules compiled
    # for a different word size) has every module name in both. Neither copy is the one to drop,
    # so a name carrying different bytes in another bundle keeps both, under its bundle's name.
    first: dict[str, bytes] = {}
    clashing: set[str] = set()
    for _rel, members in bundles:
        for name, member in members.items():
            if first.setdefault(name, member) != member:
                clashing.add(name)
    if clashing:
        log.info("%d module name(s) differ between the %d script bundles; keeping each bundle's "
                 "copy under the bundle's own name.", len(clashing), len(bundles))

    # The bundle's whole path, so same-named bundles in two directories don't collide in turn.
    # setdefault, so a script shipped loose keeps its own copy over a bundle's.
    for rel, members in bundles:
        stem = rel[:-len(BUNDLE_EXT)]
        for name, member in members.items():
            flat.setdefault(f"{stem}/{name}" if name in clashing else name, member)
    return flat


def collect_script_entries(index: dict[str, Asset]) -> dict[str, bytes]:
    """The .jsc / .luac / .lua files in an asset index, plus the scripts inside any script bundle
    (.zip) that isn't encrypted."""
    return _flatten_plain_bundles(_collect_entries(
        index, lambda rel: rel.endswith(COLLECTED_EXTS), MAX_SCRIPT_BYTES))


def collect_signed_assets(index: dict[str, Asset], sign: bytes, known) -> dict[str, bytes]:
    """Assets under any extension that start with the script signature, other than `known` paths.

    An encrypted script bundle can be named anything (game.bin, res.dat); what gives it away is
    the signature the engine looks for before decrypting. Only the first bytes of each asset are
    read to find out.
    """
    if len(sign) < MIN_SIGN_LEN:
        return {}
    found: dict[str, bytes] = {}
    for rel, (size, read) in index.items():
        if rel not in known and len(sign) < size <= MAX_SCRIPT_BYTES and read(len(sign)) == sign:
            found[rel] = read()
    return found


def collect_scripts(apk_paths: list[str], logger: logging.Logger = log,
                    index: dict[str, Asset] | None = None) -> dict[str, bytes]:
    """Collects the scripts from the input paths and reports how many there are.

    `index` reuses an asset index already built for the same paths, so a caller that needs one
    anyway (extract_offline, for the signature scan) does not walk the inputs twice.
    """
    if index is not None:
        entries = collect_script_entries(index)
    else:
        with contextlib.ExitStack() as stack:
            entries = collect_script_entries(_asset_index(stack, apk_paths))
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


def verify_captured_key(key: bytes, encrypted: dict[str, bytes], forced: bytes | None,
                        exact: bytes | None) -> tuple[bool, bytes | None, int]:
    """Checks a key captured at runtime against the encrypted scripts.

    Tries the signature the engine passed with the key first, then the guessed prefix, so a bad
    capture can't cost a key that would have worked. Returns (ok, signature that verified, number of
    scripts tested).
    """
    samples = _key_samples(encrypted)
    sign = choose_signature(forced, encrypted, exact=exact)
    if not all(_key_decrypts(s, key, sign=sign) for s in samples) and exact is not None:
        sign = choose_signature(forced, encrypted)
    if all(_key_decrypts(s, key, sign=sign) for s in samples):
        return True, sign, len(samples)
    return False, None, len(samples)


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


def _write_bundle(out_dir: str, members: dict[str, bytes], sign: bytes,
                  decrypt: Callable[[bytes], bytes | None], report: LuaBytecodeReport) -> list[str]:
    """Writes the files of a script bundle into the output tree, one result each.

    An entry starting with the signature is encrypted (LuaStack::luaLoadBuffer decrypts those
    whatever holds them) and is decrypted here; anything else is written as it is.
    """
    results: list[str] = []
    for name, blob in sorted(members.items()):
        if sign and blob.startswith(sign):
            blob = decrypt(blob)
            if blob is None:
                log.debug("Decryption failed: %s", name)
                results.append(FAILED)
                continue
        elif not is_script_member(name, blob):
            results.append(write_output(out_dir, name, blob, report))  # a resource, not a script
            continue
        body, kind = unpack_payload(blob)
        results.append(write_output(out_dir, output_name(name, kind), body, report))
    return results


def _write_payload(out_dir: str, rel: str, plain: bytes, sign: bytes,
                   decrypt: Callable[[bytes], bytes | None], report: LuaBytecodeReport) -> list[str]:
    """Writes one decrypted script; a script bundle (a zip) is unpacked into its entries instead."""
    body, kind = unpack_payload(plain)
    if kind == "zip":
        # Only a zip of scripts is a bundle. A Creator "zip compress" build also wraps a script in
        # a zip, but that one holds a single .js that isn't named after the file it came from, so
        # unpacking it would lose the name: it is kept as a .zip instead.
        members = _bundle_members(body)
        if members:
            log.info("%s is a script bundle: unpacking %d file(s).", rel, len(members))
            return _write_bundle(out_dir, members, sign, decrypt, report)
    return [write_output(out_dir, output_name(rel, kind), body, report)]


def _extract_offline_aes(stack: contextlib.ExitStack, apk_paths: list[str],
                         aes: tuple[bytes, bytes, int], out_dir: str) -> int:
    """EncryptManager AES path: wraps every asset type, so every asset is processed.

    Only the scripts are held in memory (to check the key against). The rest, which can be
    hundreds of megabytes of textures and audio, is read, decrypted and written one file at a time.
    """
    aes_key, aes_iv, aes_roll = aes
    index = _asset_index(stack, apk_paths)
    if not index:
        log.warning("No asset files found in %d input path(s).", len(apk_paths))
        return 0

    # Encrypted scripts are a safe test of the key: once it's confirmed, a file that doesn't decrypt
    # is a genuinely unencrypted resource (copy-list) rather than a wrong-key failure.
    script_entries, _ = split_plain_scripts(
        _collect_entries(index, lambda rel: rel.endswith(SCRIPT_EXTS), MAX_SCRIPT_BYTES))
    if script_entries:
        samples = _key_samples(script_entries)
        if not any(cocos_aes_decrypt(s, aes_key, aes_iv, roll=aes_roll) is not None for s in samples):
            log.error("The AES key/iv/roll doesn't decrypt the encrypted scripts (wrong key); nothing written.")
            save_raw_fallback(script_entries, out_dir)
            return 0
        log.log(SUCCESS, "AES key verified against %d script(s).", len(samples))
    else:
        log.warning("No encrypted scripts to verify the AES key against; files that don't decrypt are copied as-is.")
    del script_entries

    log.info("Decrypting %d asset(s) into '%s' with EncryptManager AES-256-CBC key=%s iv=%s (roll=%d)...",
             len(index), out_dir, aes_key.hex(), aes_iv.hex() or "<default>", aes_roll)
    report = LuaBytecodeReport()
    decrypted = copied = skipped = failed = 0
    for rel, (_size, read) in sorted(index.items()):
        raw_blob = read()
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
    exact_sign: bytes | None = None,
) -> int:
    """`exact_sign` is a signature read from the engine (e.g. the one the Frida hook saw with the key).
    It is used in preference to guessing one, but --sign still wins over it."""
    with contextlib.ExitStack() as stack:
        if aes is not None:
            return _extract_offline_aes(stack, apk_paths, aes, out_dir)

        # One pass over the inputs, shared by script collection and the signature scan below:
        # for an APK that means parsing its central directory once rather than twice. Built on
        # demand, since neither is needed when the caller already collected the scripts and no
        # signature is known to scan for.
        index: dict[str, Asset] | None = None

        def asset_index() -> dict[str, Asset]:
            nonlocal index
            if index is None:
                index = _asset_index(stack, apk_paths)
            return index

        entries = (preloaded_entries if preloaded_entries is not None
                   else collect_scripts(apk_paths, index=asset_index()))

        report = LuaBytecodeReport()
        known = set(entries)
        entries, plain = split_plain_scripts(entries)
        copied = _write_plain_scripts(plain, out_dir, report)

        # An encrypted bundle can carry any extension, and the only way to find one is by its
        # signature. When the signature is already given (--sign, or seen by Frida) that can be
        # done now; otherwise as soon as it has been worked out from the scripts found by name.
        scanned = False

        def add_signed_assets(sign: bytes) -> None:
            nonlocal scanned
            scanned = True
            extra = collect_signed_assets(asset_index(), sign, known)
            if extra:
                log.info("%d more asset(s) start with the script signature (script bundle?).", len(extra))
                entries.update(extra)

        if forced_sign or exact_sign:
            add_signed_assets(forced_sign or exact_sign)
        if not entries and not plain:  # nothing by name, and no signature to find anything by
            log.warning("No .jsc / .luac / .lua files found in %d input path(s).", len(apk_paths))
            return 0
        if not entries:
            log.log(SUCCESS, "Done: none of the scripts are encrypted; %d copied to %s.", copied, out_dir)
            report.log()
            return copied

        xor_key: bytes | None = None

        # The engine passes its key and signature together to setXXTEAKeyAndSign, so when both can
        # be read from the library there is no need to guess the signature from a common prefix.
        if key is None and lib_path:
            exact = recover_key_and_sign_static(lib_path, entries)
            if exact is not None:
                key, exact_sign = exact

        sign = choose_signature(forced_sign, entries, exact_sign)
        if sign:
            log.info("Detected %d-byte script signature prefix: %r (hex: %s)", len(sign), sign, sign.hex())
        if sign and not scanned:
            add_signed_assets(sign)

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

        def decrypt(blob: bytes) -> bytes | None:
            return (xor_decrypt(blob, xor_key, sign=sign) if xor_key
                    else cocos_xxtea_decrypt(blob, key, sign=sign))

        log.info("Decrypting %d asset(s) into '%s' with %s...", len(entries), out_dir, cipher_desc)
        results: collections.Counter[str] = collections.Counter()
        for rel, raw_blob in sorted(entries.items()):
            plain = decrypt(raw_blob)
            if plain is None:
                results[FAILED] += 1
                log.debug("Decryption failed: %s", rel)
                continue
            results.update(_write_payload(out_dir, rel, plain, sign, decrypt, report))
        written, skipped, failed = results[WRITTEN], results[SKIPPED], results[FAILED]

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
