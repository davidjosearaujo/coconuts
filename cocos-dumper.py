#!/usr/bin/env python3

# Usage:
#   python3 cocos-dumper.py <libcocos.so> <package> [output_dir] [options]
#
# Examples:
#   # Parallel static + Frida key capture & dump, then offline decryption of APK assets
#   python3 cocos-dumper.py ./libcocos.so com.example.game ./out
#
#   # Keep collecting live (incl. hot-updated) scripts for 60s after the key is found
#   python3 cocos-dumper.py ./libcocos.so com.example.game ./out --live-seconds 60
#
#   # No Frida: try key candidates from the lib's strings against a local APK or raw_jsc folder
#   python3 cocos-dumper.py ./libcocos.so com.example.game ./out --static-only --apk ./base.apk
#
#   # x-studio / EncryptManager AES-CBC assets with a known key+iv (e.g. from a Frida capture)
#   python3 cocos-dumper.py ./libcocos.so com.example.game ./out --apk ./base.apk \
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
import functools
import json
import logging
import os
import queue
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import zlib

log = logging.getLogger("cocos-dumper")
slog = log.getChild("static")  # static key search track
flog = log.getChild("frida")   # Frida / hook resolution track

SUCCESS = 25  # between INFO and WARNING: results worth spotting (key found, files written)
logging.addLevelName(SUCCESS, "SUCCESS")


class ConsoleFormatter(logging.Formatter):
    """Formats records as '[+] frida: message', coloured by level when writing to a terminal."""

    STYLES = {  # level: (tag, tag colour, message colour) as ANSI SGR codes
        logging.DEBUG: ("[.]", "2", "2"),
        logging.INFO: ("[*]", "36", ""),
        SUCCESS: ("[+]", "1;32", "32"),
        logging.WARNING: ("[!]", "1;33", "33"),
        logging.ERROR: ("[-]", "1;31", "31"),
    }

    def __init__(self, color: bool):
        super().__init__("%(message)s")
        self.color = color

    def _paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color and code else text

    def format(self, record: logging.LogRecord) -> str:
        style = max((lv for lv in self.STYLES if lv <= record.levelno), default=logging.DEBUG)
        tag, tag_code, msg_code = self.STYLES[style]
        prefix = self._paint(tag, tag_code) + " "
        if record.name.startswith(log.name + "."):
            prefix += self._paint(record.name[len(log.name) + 1:] + ":", "2") + " "
        # Indent continuation lines (tracebacks, Frida stacks) under the message
        body = "\n    ".join(super().format(record).splitlines())
        return prefix + self._paint(body, msg_code)


def use_color(disabled: bool) -> bool:
    return (not disabled and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
            and sys.stderr.isatty())

DEFAULT_OUTPUT_DIR = "dumped_cocos_assets"
ZIP_MAGIC = b"PK\x03\x04"
SPIDERMONKEY_MAGICS = (b"\x2c\xc0\x73\xb9", b"\x1c\xc0\x73\xb9", b"\x2b\xc0\x73\xb9")

# Strings used to locate functions in libcocos / libcocos2djs with radare2
EVAL_STRING_NEEDLES = [
    "evalString script %s, failed",
    "evaluating script %s",
    "(evaluatedOK == JS_FALSE)",  # Cocos2d-JS ScriptingCore::runScript
]
DECRYPT_FAIL_NEEDLES = [
    "t decrypt code for %s",
    "Can't decrypt code for",
]

# Known plaintexts from 'Framework: Cocos2d-js' for instant (<1ms) XOR key recovery
KNOWN_PLAINTEXT_HEADERS = [
    b"(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){",
    b"\x2c\xc0\x73\xb9\x00\x00\x00\x00\x00\x00\x00\x00",  # Compiled SpiderMonkey JS
]

# Empirical: in the builds this tool was developed against, the 13th `bl` inside the
# "Can't decrypt code for %s" function is the call to xxtea_decrypt. This depends on the
# Cocos version, hence the xref-count fallback in find_key_function().
KEY_CALL_INDEX = 12

# Skip Android config splits (locale, density, ABI) that never contain assets/*.jsc
SKIP_SPLIT_RE = re.compile(r"(^|/)split_config\.[a-z0-9_]+\.apk$", re.IGNORECASE)

# Seconds before a non-pull adb command is considered hung (first call may also start the adb server)
ADB_TIMEOUT = 30.0


# --------------------------------------------------------------------------------------
# Cocos-compatible XXTEA & XOR
# Cocos (xxtea.c): key zero-padded/truncated to 16 bytes, little-endian words,
# and the plaintext length stored in the last 32-bit word (no PKCS#7 padding).
# --------------------------------------------------------------------------------------
_DELTA = 0x9E3779B9
_MASK = 0xFFFFFFFF


def normalize_key(key: bytes) -> bytes:
    """Cocos zero-pads keys shorter than 16 bytes and truncates longer ones."""
    return key[:16].ljust(16, b"\0")


def _xxtea_raw_decrypt_py(data: bytes, key16: bytes) -> bytes:
    """Reference (pure Python) XXTEA block decryption, no length/padding handling."""
    if len(data) % 4:
        data += b"\0" * (4 - len(data) % 4)
    n_words = len(data) // 4
    v = list(struct.unpack(f"<{n_words}I", data))
    k = struct.unpack("<4I", key16)
    n = n_words - 1
    if n < 1:
        return data
    q = 6 + 52 // (n + 1)
    total = (q * _DELTA) & _MASK
    y = v[0]
    while total:
        e = (total >> 2) & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
            y = v[p] = (v[p] - mx) & _MASK
        z = v[n]
        mx = (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[e] ^ z))
        y = v[0] = (v[0] - mx) & _MASK
        total = (total - _DELTA) & _MASK
    return struct.pack(f"<{n_words}I", *v)


_xxtea_import_error: str | None = None
try:
    import xxtea as _xxtea_c  # optional fast path (PyPI `xxtea`)
    _xxtea_c.decrypt(b"\0" * 8, b"\0" * 16, padding=False)
except Exception as _e:  # also catches `xxtea-py`: same module name, no padding=False, may fail to build on import
    _xxtea_c = None
    _xxtea_import_error = f"{type(_e).__name__}: {_e}"

_fast_state = {"enabled": _xxtea_c is not None, "verified": False}


def _xxtea_raw_decrypt(data: bytes, key16: bytes) -> bytes:
    """Uses the xxtea C extension (padding=False) if available, after checking it once against the reference."""
    if _fast_state["enabled"] and len(data) % 4 == 0 and len(data) >= 8:
        try:
            fast = _xxtea_c.decrypt(data, key16, padding=False)
        except Exception as e:
            log.debug("xxtea fast path unavailable (%s); using pure Python", e)
            _fast_state["enabled"] = False
        else:
            if _fast_state["verified"]:
                return fast
            slow = _xxtea_raw_decrypt_py(data, key16)
            if fast == slow:
                _fast_state["verified"] = True
                log.debug("xxtea fast path verified")
            else:
                log.debug("xxtea output differs from reference; using pure Python")
                _fast_state["enabled"] = False
            return slow
    return _xxtea_raw_decrypt_py(data, key16)


def detect_signature_prefix(samples: list[bytes], max_len: int = 32) -> bytes:
    """Detects a shared signature prefix (e.g. b'kkk' from setXXTEAKeyAndSign) across .jsc samples."""
    non_empty = [s for s in samples if len(s) >= 8]
    if not non_empty:
        return b""

    first = non_empty[0]
    if first.startswith((ZIP_MAGIC, b"\x1f\x8b")) or first[:4] in SPIDERMONKEY_MAGICS:
        return b""

    prefix = bytearray()
    if len(non_empty) >= 2:
        limit = min(max_len, min(len(s) for s in non_empty))
        for i in range(limit):
            b = first[i]
            if all(s[i] == b for s in non_empty[1:]):
                prefix.append(b)
            else:
                break
        while prefix and any((len(s) - len(prefix)) % 4 != 0 for s in non_empty):
            prefix.pop()

    if not prefix:
        rems = {len(s) % 4 for s in non_empty}
        if len(rems) == 1:
            rem = rems.pop()
            if rem != 0 and all(s[:rem] == first[:rem] for s in non_empty):
                return first[:rem]

    return bytes(prefix)


def strip_signature(data: bytes, sign: bytes) -> bytes:
    if sign and data.startswith(sign):
        return data[len(sign):]
    return data


def cocos_xxtea_decrypt(data: bytes, key16: bytes, sign: bytes = b"") -> bytes | None:
    """Returns plaintext, or None if the embedded length word is invalid (wrong key/format)."""
    payload = strip_signature(data, sign)
    if len(payload) < 8 or len(payload) % 4 != 0:
        return None
    raw = _xxtea_raw_decrypt(payload, key16)
    n = len(raw)
    m = struct.unpack_from("<I", raw, n - 4)[0]
    if m < n - 7 or m > n - 4:
        return None
    return raw[:m]


def xor_decrypt(data: bytes, xor_key: bytes, sign: bytes = b"") -> bytes:
    """Decrypts repeating-key XOR payload after stripping any header signature."""
    payload = strip_signature(data, sign)
    klen = len(xor_key)
    if not klen:
        return payload
    repeated = (xor_key * (len(payload) // klen + 1))[:len(payload)]
    # One big-int XOR runs in C (~10x faster than XORing byte by byte in Python)
    n = len(payload)
    return (int.from_bytes(payload, "little") ^ int.from_bytes(repeated, "little")).to_bytes(n, "little")


# --------------------------------------------------------------------------------------
# x-studio / EncryptManager AES-CBC (cocos2d-x & axmol EncryptManager::setEncryptEnabled)
#
# Layout of an encrypted asset, mirroring EncryptManager.cpp from simdsoft's HelloCrypto:
#   body = AES-256-CBC( PKCS7( zlib.compress(plaintext) ) )      # zlib only if ENCF_COMPRESS
#   file = body + sign_block                                     # sign_block only if ENCF_SIGNATURE
# The 16-byte sign_block is AES-128-ECB(sign_key) of:
#   <u32 mask><u32 sigval><u8 flags><i32 original_size><3 bytes reserved>
# and is valid iff (mask ^ sigval) == 0xDEADBEEF. flags & 3 => the data was zlib-compressed.
# sign_key is derived from key+iv by `roll` rounds of AES-128-ECB (see _aes_derive_sign_key).
# Defaults (setEncryptEnabled's default `flags`): ENCF_COMPRESS|ENCF_SIGNATURE, roll = 5.
# --------------------------------------------------------------------------------------
AES_DEADBEEF = 0xDEADBEEF
ENCF_COMPRESS = 1
ENCF_SIGNATURE = 2


def _load_aes():
    """Imports pycryptodome's AES lazily so the XXTEA/XOR paths work without it installed."""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise RuntimeError("AES decryption needs pycryptodome (pip install pycryptodome)") from None
    return AES


def aes_roll_from_flags(flags: int) -> int:
    """EncryptManager stores the signature 'roll' count in bits 16..31 of its flags word."""
    return (flags >> 16) & 0xFFFF


def _aes_norm_key(key: bytes) -> bytes:
    """EncryptManager zero-pads the key to 32 bytes (AES-256) and truncates anything longer."""
    return key[:32].ljust(32, b"\0")


def _aes_norm_iv(iv: bytes) -> bytes:
    """IV is truncated/zero-filled to 16 bytes; an empty IV becomes 16 x 0x01."""
    return (b"\x01" * 16) if not iv else iv[:16].ljust(16, b"\0")


def _aes_derive_sign_key(key: bytes, iv: bytes, roll: int) -> bytes:
    """Reproduces EncryptManager's signature-key schedule: `roll` rounds of AES-128-ECB."""
    AES = _load_aes()
    key32 = _aes_norm_key(key)
    # The ECB key starts as the first min(|key|,|iv|) bytes of the padded key (AES-128 reads 16).
    n = min(len(key), len(iv)) if iv else 0
    ecb_key = key32[:n].ljust(16, b"\0")[:16]
    sign_key = _aes_norm_iv(iv)
    for _ in range(roll if roll > 0 else 1):  # C do..while(--roll > 0): always runs at least once
        sign_key = AES.new(ecb_key, AES.MODE_ECB).encrypt(sign_key)
        ecb_key = sign_key
    return sign_key


def _aes_parse_signature(data: bytes, sign_key: bytes) -> tuple[bool, int] | None:
    """Returns (compressed, original_size) if the trailing signature validates, else None."""
    if len(data) <= 16:
        return None
    AES = _load_aes()
    sig = AES.new(sign_key, AES.MODE_ECB).decrypt(data[-16:])
    mask, sigval = struct.unpack_from("<II", sig, 0)
    if (mask ^ sigval) != AES_DEADBEEF:
        return None
    flags = sig[8]
    (original_size,) = struct.unpack_from("<i", sig, 9)
    return bool(flags & 0x3), original_size


def _strip_pkcs7(data: bytes) -> bytes:
    pad = data[-1] if data else 0
    if 1 <= pad <= 16 and data.endswith(bytes([pad]) * pad):
        return data[:-pad]
    return data


def cocos_aes_decrypt(data: bytes, key: bytes, iv: bytes, roll: int = 5,
                      signature: bool = True, compressed: bool | None = None) -> bytes | None:
    """
    Decrypts an EncryptManager AES-CBC asset. Returns plaintext, or None when the signature
    doesn't validate (wrong key/iv/roll, or the file isn't EncryptManager-encrypted).
    With signature=False there's no integrity check, so `compressed` must say whether to inflate.
    """
    AES = _load_aes()
    if signature:
        parsed = _aes_parse_signature(data, _aes_derive_sign_key(key, iv, roll))
        if parsed is None:
            return None
        compressed, _orig = parsed
        body = data[:-16]
    else:
        if compressed is None:
            compressed = True  # ENCF_COMPRESS is on by default
        body = data
    if not body or len(body) % 16 != 0:
        return None
    plain = AES.new(_aes_norm_key(key), AES.MODE_CBC, _aes_norm_iv(iv)).decrypt(body)
    if not compressed:
        return _strip_pkcs7(plain)
    try:
        # Raw zlib stream; inflate stops at stream end and ignores the trailing PKCS7 padding
        d = zlib.decompressobj()
        return d.decompress(plain) + d.flush()
    except zlib.error:
        return None


def recover_xor_key_kp(entries: dict[str, bytes], sign: bytes = b"") -> bytes | None:
    """
    Known-Plaintext XOR attack from 'Framework: Cocos2d-js'.
    Recovers repeating XOR keys in <1ms against jsb-builtin.jsc / jsb-engine.jsc / bytecode.
    """
    prioritized = sorted(
        entries.items(),
        key=lambda kv: (0 if any(k in kv[0] for k in ("jsb-builtin", "jsb-engine", "jsb_polyfill")) else 1, len(kv[1])),
    )
    for _, raw in prioritized[:5]:
        payload = strip_signature(raw, sign)
        for kp in KNOWN_PLAINTEXT_HEADERS:
            if len(payload) < len(kp):
                continue
            keystream = bytes(payload[i] ^ kp[i] for i in range(len(kp)))
            for klen in range(1, min(33, len(keystream) // 2)):
                cand = keystream[:klen]
                if (cand * (len(keystream) // klen + 1))[:len(keystream)] == keystream:
                    if all(32 <= b < 127 for b in cand):
                        test_dec = xor_decrypt(raw, cand, sign=sign)
                        body, kind = unpack_payload(test_dec)
                        if looks_like_script(body, kind):
                            return cand
    return None


def unpack_payload(data: bytes) -> tuple[bytes, str]:
    """Returns (body, kind) where kind is 'zip', 'gzip' (decompressed), 'bytecode', or 'raw'."""
    if data.startswith(ZIP_MAGIC):
        return data, "zip"
    if data[:4] in SPIDERMONKEY_MAGICS:
        return data, "bytecode"
    try:
        return zlib.decompress(data, 15 + 32), "gzip"
    except zlib.error:
        return data, "raw"


def looks_like_script(body: bytes, kind: str) -> bool:
    if not body:
        return False
    if kind in ("gzip", "zip", "bytecode"):
        return True
    if body[:4] in SPIDERMONKEY_MAGICS:
        return True
    try:
        body.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def describe_key(key: bytes) -> str:
    text = key.rstrip(b"\0")
    try:
        s = text.decode("ascii")
        if s.isprintable():
            return f"'{s}'"
    except UnicodeDecodeError:
        pass
    return f"hex:{key.hex()}"


# --------------------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------------------
def safe_join(base: str, rel: str) -> str:
    """Joins rel onto base, refusing paths that escape base (e.g. '../')."""
    base_real = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base_real, rel.replace("\\", "/").lstrip("/")))
    if os.path.commonpath([base_real, target]) != base_real:
        raise ValueError(f"path escapes output directory: {rel!r}")
    return target


def jsc_to_js(path: str) -> str:
    return path[:-1] if path.lower().endswith(".jsc") else path


class FileWriter:
    """Background writer for live dumps. Must be close()d to flush."""

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.saved = 0
        self._q: queue.Queue = queue.Queue()
        self._t = threading.Thread(target=self._run, name="file-writer")
        self._t.start()

    def submit(self, rel_path: str, data: bytes) -> None:
        self._q.put((rel_path, data))

    def close(self) -> None:
        self._q.put(None)
        self._t.join()
        if self.saved:
            flog.log(SUCCESS, "Saved %d live script dump(s) to %s", self.saved, self.base_dir)

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                return
            rel_path, data = item
            try:
                out_path = safe_join(self.base_dir, rel_path)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(data)
                self.saved += 1
                flog.info("Live dump: %s", out_path)
            except (OSError, ValueError) as e:
                flog.warning("Could not write live dump %r: %s", rel_path, e)


# --------------------------------------------------------------------------------------
# Static key candidates (Ranked Tier 0 -> Tier 3)
# --------------------------------------------------------------------------------------
_KEY_PATTERNS = [
    re.compile(r"[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{2}"),      # 16
    re.compile(r"[0-9a-z]{5}-[0-9a-z]{4}-[0-9a-z]{4}"),      # 15
    re.compile(r"[0-9a-z]{4}-[0-9a-z]{6}-[0-9a-z]{4}"),      # 16
    re.compile(r"[0-9]{4}[a-z]{2}[0-9]{2}[a-z]{2}[0-9]{4}"), # 14
    re.compile(r"[0-9a-zA-Z]{16}"),                          # 16
]
_KEY_EXCLUDE = {
    "code-source-info",
    "applicationDidFinishLaunching",
    "jsb-adapter/jsb-builtin.js",
    "jsb-adapter/jsb-engine.js",
}


@contextlib.contextmanager
def _r2_abort_guard(r2, abort_event: threading.Event | None):
    """Immediately terminates the underlying radare2 subprocess if abort_event is set."""
    if abort_event is None:
        yield
        return
    done = threading.Event()

    def _watcher():
        while not done.is_set():
            if abort_event.is_set():
                proc = getattr(r2, "process", None)
                if proc is not None:
                    with contextlib.suppress(Exception):
                        proc.terminate()
                    with contextlib.suppress(Exception):
                        proc.kill()
                return
            done.wait(0.05)

    t = threading.Thread(target=_watcher, name="r2-abort-guard", daemon=True)
    t.start()
    try:
        yield
    finally:
        done.set()


def extract_r2_priority_keys(
    lib_path: str,
    abort_event: threading.Event | None = None,
) -> list[str]:
    """
    Tier 0 ('Framework: Cocos2d-js'):
    Extracts string literals referenced directly inside AppDelegate::applicationDidFinishLaunching
    or jsb_set_xxtea_key callers via lightweight single-function r2 disassembly (no `aap; aaef`).
    """
    if abort_event and abort_event.is_set():
        return []
    try:
        import r2pipe
    except ImportError:
        return []

    out: dict[str, None] = {}
    try:
        r2 = r2pipe.open(os.path.abspath(lib_path), flags=["-2"])
    except Exception as e:  # e.g. radare2 not installed: the string tiers below still work without it
        slog.debug("Tier-0 r2 key extraction skipped: %s", e)
        return []
    try:
        with _r2_abort_guard(r2, abort_event):
            symbols = r2.cmdj("isj") or []
            target_fns = [
                s["vaddr"] for s in symbols
                if s.get("vaddr") and not s.get("is_imported") and any(
                    k in s.get("name", "")
                    for k in ("applicationDidFinishLaunching", "jsb_set_xxtea_key", "setXXTeaKey")
                )
            ]
            for fn_addr in target_fns:
                if abort_event and abort_event.is_set():
                    break
                r2.cmd(f"af @ {fn_addr:#x}")
                ops = (r2.cmdj(f"pdfj @ {fn_addr:#x}") or {}).get("ops", [])
                for op in ops:
                    if abort_event and abort_event.is_set():
                        break
                    ptr = op.get("ptr")
                    if ptr and ptr > 0x1000:
                        s = r2.cmd(f"psz @ {ptr:#x}").strip()
                        if 3 <= len(s) <= 32 and s.isprintable() and s not in _KEY_EXCLUDE:
                            out.setdefault(s, None)
    except Exception as e:
        slog.debug("Tier-0 r2 key extraction skipped: %s", e)
    finally:
        with contextlib.suppress(Exception):
            r2.quit()
    return list(out)


def find_possible_keys(
    lib_path: str,
    sig_prefix: bytes = b"",
    abort_event: threading.Event | None = None,
    tier_stats: dict[str, int] | None = None,
) -> list[str]:
    if abort_event and abort_event.is_set():
        return []
    slog.info("Collecting candidate keys from %s...", lib_path)
    with open(lib_path, "rb") as f:
        data = f.read()

    found: dict[str, None] = {}  # ordered de-dup

    def _add(raw_bytes: bytes) -> None:
        try:
            s = raw_bytes.decode("ascii")
        except UnicodeDecodeError:
            return
        if s and s not in _KEY_EXCLUDE and s.isprintable():
            found.setdefault(s, None)

    # Tier 0: Exact string pointers from AppDelegate::applicationDidFinishLaunching via r2
    for s in extract_r2_priority_keys(lib_path, abort_event=abort_event):
        found.setdefault(s, None)
    tier0_count = len(found)
    if abort_event and abort_event.is_set():
        return []

    # Tier 1a: Immediate 128-byte pre-window before 'main.js\0' and '<sig_prefix>\0'
    tight_anchors = [b"main.js\x00", b"jsb-adapter/jsb-builtin.js\x00", b"0.0.0.0\x00"]
    if sig_prefix:
        tight_anchors.insert(0, sig_prefix + b"\x00")

    for anchor in tight_anchors:
        idx = 0
        while (idx := data.find(anchor, idx)) != -1:
            pre_win = data[max(0, idx - 128): min(len(data), idx + 64)]
            for token in re.split(rb"[\x00-\x1f\x7f-\xff]+", pre_win):
                if 3 <= len(token) <= 32:
                    _add(token)
            idx += len(anchor)

    # Tier 1b: Wider 512-byte neighborhood around Cocos boot strings
    for anchor in (b"main.js\x00", b"jsb-adapter", b"jsb_polyfill", b"project.jsc", b"0.0.0.0\x00"):
        idx = 0
        while (idx := data.find(anchor, idx)) != -1:
            window = data[max(0, idx - 512): min(len(data), idx + 512)]
            for token in re.split(rb"[\x00-\x1f\x7f-\xff]+", window):
                if 3 <= len(token) <= 32:
                    _add(token)
            idx += len(anchor)
    tier1_count = len(found) - tier0_count

    # Tier 2: Standard 14..16 char Cocos key regex patterns across the binary
    all_tokens = re.split(rb"[\x00-\x1f\x7f-\xff]+", data)
    for token in all_tokens:
        if 14 <= len(token) <= 16:
            try:
                s = token.decode("ascii")
            except UnicodeDecodeError:
                continue
            if s not in _KEY_EXCLUDE and any(p.fullmatch(s) for p in _KEY_PATTERNS):
                found.setdefault(s, None)
    tier2_count = len(found) - tier0_count - tier1_count

    # Tier 3: Broader printable ASCII tokens (4..32 chars, no spaces/paths/format specifiers)
    for token in all_tokens:
        if 4 <= len(token) <= 32 and not any(c in token for c in b" \t\r\n/%<>();,"):
            _add(token)
    tier3_count = len(found) - tier0_count - tier1_count - tier2_count

    if tier_stats is not None:
        tier_stats["high_prob_count"] = tier0_count + tier1_count + tier2_count

    slog.info(
        "%d candidate keys ranked (Tier0 r2=%d, Tier1 rodata=%d, Tier2 regex=%d, Tier3 general=%d).",
        len(found), tier0_count, tier1_count, tier2_count, tier3_count,
    )
    return list(found)


# --------------------------------------------------------------------------------------
# radare2 analysis (with O(1) symbol & .data.rel.ro vtable fast paths)
# --------------------------------------------------------------------------------------
def find_symbol_vaddr(symbols: list[dict], patterns: list[str]) -> int | None:
    """Finds a defined function vaddr in the symbol table matching any regex pattern."""
    for pat in patterns:
        rx = re.compile(pat)
        for s in symbols:
            vaddr = s.get("vaddr") or 0
            if not vaddr or s.get("is_imported"):
                continue
            if rx.search(s.get("name", "")):
                return vaddr
    return None


def _resolve_relro_set_xxtea_key(r2) -> int | None:
    """
    Fast path from 'Framework: Cocos2d-js' (.data.rel.ro section):
    On stripped arm64 libcocos.so, .data.rel.ro + 0xa0 holds cc::CocosApplication::setXXTeaKey.
    """
    sections = r2.cmdj("iSj") or []
    relro = next((s for s in sections if s.get("name") == ".data.rel.ro"), None)
    if not relro or not relro.get("vaddr"):
        return None
    slot_addr = relro["vaddr"] + 0xA0
    vals = r2.cmdj(f"pxqj 8 @ {slot_addr:#x}") or []
    if vals and vals[0] > 0x1000:
        exec_secs = [s for s in sections if "x" in (s.get("perm") or "")]
        if any(s["vaddr"] <= vals[0] < s["vaddr"] + s.get("vsize", 0) for s in exec_secs):
            return vals[0]
    return None


def r2_open_and_analyse(
    lib_path: str,
    run_heavy_analysis: bool = False,
    abort_event: threading.Event | None = None,
):
    import r2pipe

    r2 = r2pipe.open(os.path.abspath(lib_path), flags=["-2"])
    try:
        with _r2_abort_guard(r2, abort_event):
            r2.cmd("e asm.comments=false")
            r2.cmd("e asm.usercomments=true")

            info = (r2.cmdj("ij") or {}).get("bin", {})
            if abort_event and abort_event.is_set():
                return r2, "", [], []
            if info.get("arch") != "arm" or info.get("bits") != 64:
                raise RuntimeError(f"Only arm64 libs are supported (arch={info.get('arch')}, bits={info.get('bits')})")

            symbols = r2.cmdj("isj") or []
            if abort_event and abort_event.is_set():
                return r2, "", [], symbols
            bridge = sorted({m.group(0) for s in symbols
                             for m in [re.search(r"Java_\w*JavascriptJavaBridge\w*", s.get("name", ""))] if m})
            if not bridge:
                raise RuntimeError("No JavascriptJavaBridge JNI export found; this doesn't look like a cocos2d-js lib")
            if len(bridge) > 1:
                flog.debug("Multiple bridge symbols %s; using %s", bridge, bridge[0])
            cocos_symbol = bridge[0]

            strings = []
            if run_heavy_analysis and not (abort_event and abort_event.is_set()):
                jdiv_addrs = [s["vaddr"] for s in symbols if "jdiv" in s.get("name", "") and s.get("vaddr")]
                flog.info("Running radare2 code analysis (this can take a while)...")
                if jdiv_addrs:
                    anal_end = min(jdiv_addrs)
                    r2.cmd(f"e anal.limits=true; e anal.from=entry0; e anal.to={anal_end:#x}; aap; "
                           f"e anal.in=io.maps.x; aaef")
                else:
                    flog.warning("No 'jdiv' symbol to bound analysis; analysing without limits (slower).")
                    r2.cmd("aap; e anal.in=io.maps.x; aaef")

                if not (abort_event and abort_event.is_set()):
                    strings = r2.cmdj("izzj") or []
                    if isinstance(strings, dict):
                        strings = strings.get("strings", [])

            return r2, cocos_symbol, strings, symbols
    except Exception:
        with contextlib.suppress(Exception):
            r2.quit()
        raise


def _resolve_enclosing_function(r2, code_addr: int) -> int | None:
    """Attempts to define or locate the function containing code_addr when fcn_addr is 0."""
    r2.cmd(f"e anal.limits=false; af @ {code_addr:#x}")
    info = r2.cmdj(f"afij @ {code_addr:#x}") or []
    if info and info[0].get("offset"):
        return info[0]["offset"]
    ops = r2.cmdj(f"pdj -256 @ {code_addr:#x}") or []
    for op in reversed(ops):
        if op.get("fcn_addr"):
            return op["fcn_addr"]
    return code_addr


def find_string_xref_function(r2, strings, needles: str | list[str]) -> int:
    if isinstance(needles, str):
        needles = [needles]

    matched_targets = []
    for needle in needles:
        for s in strings:
            if needle in s.get("string", ""):
                matched_targets.append((needle, s))

    if not matched_targets:
        raise RuntimeError(f"String not found: {needles[0]!r}")

    for _, target in matched_targets:
        vaddr = target["vaddr"]
        xrefs = r2.cmdj(f"axtj @ {vaddr:#x}") or []
        if not xrefs:
            r2.cmd("e anal.limits=false; aae")
            xrefs = r2.cmdj(f"axtj @ {vaddr:#x}") or []
        for x in xrefs:
            if x.get("fcn_addr"):
                return x["fcn_addr"]
            if x.get("from"):
                resolved = _resolve_enclosing_function(r2, x["from"])
                if resolved:
                    return resolved

    raise RuntimeError(f"No function references {needles[0]!r}")


def _xref_count(r2, addr: int) -> int:
    return len(r2.cmdj(f"axtj @ {addr:#x}") or [])


def find_key_function(r2, strings, symbols) -> int:
    fn = find_string_xref_function(r2, strings, DECRYPT_FAIL_NEEDLES)
    ops = (r2.cmdj(f"pdfj @ {fn:#x}") or {}).get("ops", [])
    calls = [op["jump"] for op in ops
             if op.get("jump") and op.get("disasm", "").split(None, 1)[:1] == ["bl"]]
    if not calls:
        raise RuntimeError("No `bl` calls found in the decrypt-failure function")

    fun_key = calls[KEY_CALL_INDEX] if len(calls) > KEY_CALL_INDEX else calls[-1]
    if _xref_count(r2, fun_key) != 2:
        for c in calls[:KEY_CALL_INDEX + 1]:
            if _xref_count(r2, c) == 2:
                fun_key = c
                break

    head = r2.cmd(f"pd 4 @ {fun_key:#x}")
    if "x16" in head or "x17" in head:  # PLT stub -> resolve the real symbol
        sym = next((s for s in symbols if "xxtea_decrypt" in s.get("name", "") and s.get("vaddr")), None)
        if sym:
            fun_key = sym["vaddr"]
        else:
            flog.warning("Key function looks like a PLT stub and no xxtea_decrypt symbol was found; hooking the stub.")
    return fun_key


# --------------------------------------------------------------------------------------
# Frida (Supports XXTEA, setXXTeaKey, AES EncryptManager, and XOR FileUtils::init)
# --------------------------------------------------------------------------------------
FRIDA_TEMPLATE = r"""
'use strict';

var COCOS_SYMBOL = __COCOS_SYMBOL__;
var DUMP_OFFSET  = __DUMP_OFFSET__;
var KEY_OFFSET   = __KEY_OFFSET__;
var KEY_IS_STD_STRING = __KEY_IS_STD_STRING__;
var MAX_KEY_LEN  = 64;

var hooked = false;
var keySent = false;
var aesSent = false;

function toHex(buf) {
    var bytes = new Uint8Array(buf);
    var out = '';
    for (var i = 0; i < bytes.length; i++) out += ('0' + bytes[i].toString(16)).slice(-2);
    return out;
}

// A string_view passed by value spans two arg slots: one pointer, one length. The order is
// STL-dependent (libc++ is {ptr,len}, libstdc++ is {len,ptr}), so rather than guess, try both
// orderings and keep whichever gives a plausible length AND a readable span. A wrong guess is
// rejected because the length is out of range or the "pointer" doesn't point at readable memory.
function readSpan(pp, lp) {
    if (!lp.toUInt32) return null;
    var len = lp.toUInt32();
    if (len === 0 || len > MAX_KEY_LEN || pp.isNull()) return null;
    try {
        return pp.readByteArray(len);  // throws if pp isn't readable (i.e. pp was really the length)
    } catch (e) {
        return null;
    }
}

function readStringView(a, b) {
    return readSpan(a, b) || readSpan(b, a);  // {ptr,len} first, then {len,ptr}
}

function readStdString(strPtr) {
    if (strPtr.isNull()) return null;
    var firstByte = strPtr.readU8();
    if ((firstByte & 1) === 0) {
        var len = firstByte >> 1;
        if (len === 0 || len > MAX_KEY_LEN) return null;
        return strPtr.add(1).readByteArray(len);
    } else {
        var len = strPtr.add(8).readU64().toNumber();
        if (len === 0 || len > MAX_KEY_LEN) return null;
        var dataPtr = strPtr.add(16).readPointer();
        return dataPtr.isNull() ? null : dataPtr.readByteArray(len);
    }
}

function findExportMatching(lib, substrings) {
    var exps = lib.enumerateExports();
    for (var i = 0; i < exps.length; i++) {
        var name = exps[i].name;
        var matchAll = true;
        for (var j = 0; j < substrings.length; j++) {
            if (name.indexOf(substrings[j]) < 0) {
                matchAll = false;
                break;
            }
        }
        if (matchAll) return exps[i].address;
    }
    return null;
}

function installHooks(lib) {
    hooked = true;
    var base = lib.base;

    // 1. ScriptEngine::evalString(this, const char *script, ssize_t length, Value *ret, const char *fileName)
    var dumpAddr = (DUMP_OFFSET !== null)
        ? base.add(DUMP_OFFSET)
        : (findExportMatching(lib, ['ScriptEngine', 'evalString']) ||
           findExportMatching(lib, ['ScriptingCore', 'evalString']));

    if (dumpAddr !== null) {
        Interceptor.attach(dumpAddr, {
            onEnter: function (args) {
                try {
                    var script = args[1], name = args[4];
                    if (script.isNull() || name.isNull()) return;
                    var path = name.readCString();
                    if (!path) return;
                    var len = args[2].toInt32();
                    if (len > 0) {
                        send({type: 'file', path: path}, script.readByteArray(len));
                    } else {
                        send({type: 'file', path: path, text: script.readUtf8String()});
                    }
                } catch (e) {
                    send({type: 'log', level: 'debug', msg: 'dump hook: ' + e});
                }
            }
        });
    } else {
        send({type: 'log', level: 'warning', msg: 'No evalString hook found; live script dumps disabled (key capture only).'});
    }

    // 2. XXTEA Key Hook: xxtea_decrypt or setXXTeaKey / jsb_set_xxtea_key
    var keyAddr = (KEY_OFFSET !== null)
        ? base.add(KEY_OFFSET)
        : (lib.findExportByName('xxtea_decrypt') || findExportMatching(lib, ['xxtea_decrypt']));

    if (keyAddr !== null) {
        Interceptor.attach(keyAddr, {
            onEnter: function (args) {
                if (keySent) return;
                try {
                    if (KEY_IS_STD_STRING) {
                        var buf = readStdString(args[1]) || readStdString(args[0]);
                        if (buf) {
                            send({type: 'key', key: toHex(buf)});
                            keySent = true;
                        }
                    } else {
                        if (args[2].isNull()) return;
                        var keyLen = args[3].toUInt32();
                        if (keyLen === 0 || keyLen > MAX_KEY_LEN) return;
                        send({type: 'key', key: toHex(args[2].readByteArray(keyLen))});
                        keySent = true;
                    }
                } catch (e) {
                    send({type: 'log', level: 'debug', msg: 'key hook: ' + e});
                }
            }
        });
    }

    var setKeyExp = findExportMatching(lib, ['jsb_set_xxtea_key']) || findExportMatching(lib, ['setXXTeaKey']);
    if (setKeyExp !== null && (keyAddr === null || !setKeyExp.equals(keyAddr))) {
        Interceptor.attach(setKeyExp, {
            onEnter: function (args) {
                if (keySent) return;
                try {
                    var buf = readStdString(args[0]) || readStdString(args[1]);
                    if (buf) {
                        send({type: 'key', key: toHex(buf)});
                        keySent = true;
                    }
                } catch (e) {}
            }
        });
    }

    // 3. AES key capture (EncryptManager::setEncryptEnabled(this, bool, string_view key,
    //    string_view ivec, int flags)). Each string_view occupies two arg slots {ptr,len};
    //    which slot is which varies by STL, so pick the pointer-looking one and read `len` bytes.
    var aesExp = findExportMatching(lib, ['EncryptManager', 'setEncryptEnabled']);
    if (aesExp !== null) {
        Interceptor.attach(aesExp, {
            onEnter: function (args) {
                if (aesSent) return;
                try {
                    if (args[1].toInt32() === 0) return;  // bVal == false: encryption being disabled
                    var key = readStringView(args[2], args[3]);
                    var iv  = readStringView(args[4], args[5]);
                    if (!key) return;
                    send({type: 'aeskey', key: toHex(key), iv: iv ? toHex(iv) : '',
                          flags: args[6].toInt32()});
                    aesSent = true;
                } catch (e) {
                    send({type: 'log', level: 'debug', msg: 'aes hook: ' + e});
                }
            }
        });
    }

    send({type: 'log', level: 'info', msg: 'Hooks installed in ' + lib.name + ' @ ' + base});
}

function tryHook(libname) {
    if (hooked || !libname) return;
    var lib = Process.findModuleByName(libname);
    if (lib !== null && lib.findExportByName(COCOS_SYMBOL) !== null) installHooks(lib);
}

var linker = Process.findModuleByName(Process.pointerSize === 4 ? 'linker' : 'linker64');
if (linker === null) throw new Error('linker module not found');
var doDlopen = null;
linker.enumerateSymbols().forEach(function (sym) {
    if (sym.name.indexOf('do_dlopen') >= 0) doDlopen = sym.address;
});
if (doDlopen === null) throw new Error('do_dlopen not found in ' + linker.name);

Interceptor.attach(doDlopen, {
    onEnter: function (args) {
        var p = args[0].isNull() ? null : args[0].readCString();
        this.libname = p ? p.split('/').pop() : '';
    },
    onLeave: function (retval) {
        tryHook(this.libname);
    }
});

// In case the lib is already loaded
Process.enumerateModules().forEach(function (m) { tryHook(m.name); });
"""


def build_frida_script(
    cocos_symbol: str,
    dump_off: int | None,
    key_off: int | None,
    key_is_std_string: bool = False,
) -> str:
    return (FRIDA_TEMPLATE
            .replace("__COCOS_SYMBOL__", json.dumps(cocos_symbol))
            .replace("__DUMP_OFFSET__", f'ptr("{dump_off:#x}")' if dump_off is not None else "null")
            .replace("__KEY_OFFSET__", f'ptr("{key_off:#x}")' if key_off is not None else "null")
            .replace("__KEY_IS_STD_STRING__", "true" if key_is_std_string else "false"))


def resolve_frida_targets(
    lib_path: str,
    abort_event: threading.Event | None = None,
    high_prob_done: threading.Event | None = None,
) -> tuple[str, int | None, int | None, bool]:
    """Resolves JNI symbol, dump_off, and key_off using fast symbol/relro check first."""
    if abort_event and abort_event.is_set():
        return "", None, None, False

    r2, cocos_symbol, _, symbols = r2_open_and_analyse(
        lib_path, run_heavy_analysis=False, abort_event=abort_event
    )
    key_is_std_string = False
    dump_off = None
    key_off = None
    try:
        if not (abort_event and abort_event.is_set()):
            with _r2_abort_guard(r2, abort_event):
                key_off = find_symbol_vaddr(symbols, [r"(^|_)xxtea_decrypt$", r"xxtea_decrypt"])
                if key_off:
                    flog.info("xxtea_decrypt found in the symbol table at %#x", key_off)
                else:
                    relro_off = _resolve_relro_set_xxtea_key(r2)
                    if relro_off:
                        flog.info("setXXTeaKey found via .data.rel.ro+0xa0 at %#x", relro_off)
                        key_off = relro_off
                        key_is_std_string = True

                dump_off = find_symbol_vaddr(symbols, [
                    r"ScriptEngine.*evalString",
                    r"ScriptingCore.*evalString",
                ])
                if dump_off:
                    flog.info("evalString found in the symbol table at %#x", dump_off)
    finally:
        with contextlib.suppress(Exception):
            r2.quit()

    if abort_event and abort_event.is_set():
        return cocos_symbol, dump_off, key_off, key_is_std_string

    # Only run heavy `aap; aaef` if key_off was not found via symbol table or .data.rel.ro.
    # Wait for high-probability static tiers (vtable + Tier0..Tier2) first; if Tier 3 continues,
    # race heavy r2 analysis in parallel and kill r2 immediately if abort_event fires.
    if key_off is None:
        if high_prob_done is not None and not (abort_event and abort_event.is_set()):
            high_prob_done.wait()

        if abort_event and abort_event.is_set():
            flog.info("Static track already found the key; skipping radare2 analysis.")
            return cocos_symbol, dump_off, key_off, key_is_std_string

        r2, cocos_symbol, strings, symbols = r2_open_and_analyse(
            lib_path, run_heavy_analysis=True, abort_event=abort_event
        )
        try:
            with _r2_abort_guard(r2, abort_event):
                if not (abort_event and abort_event.is_set()):
                    try:
                        key_off = find_key_function(r2, strings, symbols)
                        flog.info("Key function at %#x", key_off)
                    except Exception as e:
                        if not (abort_event and abort_event.is_set()):
                            flog.warning("Key function not found statically (%s); Frida will try symbol exports.", e)
                            flog.debug("details", exc_info=True)

                if dump_off is None and not (abort_event and abort_event.is_set()):
                    try:
                        dump_off = find_string_xref_function(r2, strings, EVAL_STRING_NEEDLES)
                        flog.info("Dump function at %#x", dump_off)
                    except Exception as e:
                        if not (abort_event and abort_event.is_set()):
                            flog.warning("Dump function not found statically (%s); continuing with key-only/export hooks.", e)
                            flog.debug("details", exc_info=True)
        finally:
            with contextlib.suppress(Exception):
                r2.quit()

        if abort_event and abort_event.is_set():
            flog.info("Static track found the key; stopping.")

    return cocos_symbol, dump_off, key_off, key_is_std_string


def run_frida_race(
    device,
    package: str,
    script_src: str,
    writer: FileWriter,
    timeout: float,
    live_seconds: float,
    abort_event: threading.Event,
    dynamic_won: threading.Event | None = None,
    aes_box: dict | None = None,
) -> bytes | None:
    """Runs Frida dynamic interception, aborting early if `abort_event` (static track) wins.

    Returns the captured XXTEA key (or None). A captured EncryptManager AES key/iv is stored in
    `aes_box` (keys 'key', 'iv', 'flags') and also counts as winning the race.
    """
    key_box: dict[str, bytes] = {}
    key_event = threading.Event()
    gone_event = threading.Event()

    def on_message(message, data):
        mtype = message.get("type")
        if mtype == "error":
            flog.error("Script error: %s", message.get("stack") or message.get("description"))
            return
        if mtype != "send":
            return
        p = message.get("payload") or {}
        kind = p.get("type")
        if kind == "key":
            if key_event.is_set():
                return
            try:
                key = normalize_key(bytes.fromhex(p["key"]))
            except (KeyError, ValueError):
                flog.warning("Malformed key message: %r", p)
                return
            key_box["key"] = key
            flog.log(SUCCESS, "Key captured: %s", describe_key(key))
            if dynamic_won is not None:
                dynamic_won.set()
            key_event.set()
        elif kind == "aeskey":
            if aes_box is None or aes_box or key_event.is_set():
                return
            try:
                aes_box["key"] = bytes.fromhex(p["key"])
                aes_box["iv"] = bytes.fromhex(p.get("iv") or "")
                aes_box["flags"] = int(p.get("flags") or 0)
            except (KeyError, ValueError):
                flog.warning("Malformed AES key message: %r", p)
                aes_box.clear()
                return
            roll = aes_roll_from_flags(aes_box["flags"])
            flog.log(SUCCESS, "AES key captured: %s iv=%s (roll=%d)",
                     describe_key(aes_box["key"]), aes_box["iv"].hex() or "<default>", roll)
            if dynamic_won is not None:
                dynamic_won.set()
            key_event.set()
        elif kind == "file":
            path = p.get("path") or ""
            if not path:
                return
            body = data if data is not None else (p.get("text") or "").encode("utf-8", errors="replace")
            writer.submit(jsc_to_js(path), body)
        elif kind == "log":
            level = {"debug": logging.DEBUG, "warning": logging.WARNING}.get(p.get("level"), logging.INFO)
            flog.log(level, "%s", p.get("msg"))

    flog.info("Spawning %s on %s", package, device.name)
    pid = device.spawn([package])
    session = device.attach(pid)
    session.on("detached", lambda *a: gone_event.set())
    try:
        script = session.create_script(script_src)
        script.on("message", on_message)
        script.load()
    except Exception:
        with contextlib.suppress(Exception):
            device.kill(pid)
        with contextlib.suppress(Exception):
            session.detach()
        raise

    try:
        device.resume(pid)
        flog.info("Waiting up to %.0fs for the key...", timeout)
        try:
            deadline = time.monotonic() + timeout
            while not key_event.is_set() and not gone_event.is_set() and not abort_event.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                key_event.wait(min(0.2, remaining))

            if abort_event.is_set() and not key_event.is_set():
                flog.info("Static track found the key first; stopping Frida.")
                return None

            if not key_event.is_set():
                if gone_event.is_set():
                    flog.warning("App exited or crashed before the key was captured.")
                else:
                    flog.warning("No key captured within %.0fs.", timeout)

            if live_seconds > 0 and not gone_event.is_set() and not abort_event.is_set():
                flog.info("Collecting live dumps for %.0fs more (Ctrl-C to stop early)...", live_seconds)
                gone_event.wait(live_seconds)
        except KeyboardInterrupt:
            flog.info("Interrupted: stopping live capture, continuing with offline extraction.")
    finally:
        with contextlib.suppress(Exception):
            session.detach()
        if abort_event.is_set():
            with contextlib.suppress(Exception):
                device.kill(pid)
    return key_box.get("key")


# --------------------------------------------------------------------------------------
# Offline extraction
# --------------------------------------------------------------------------------------
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


def _key_samples(entries: dict[str, bytes], count: int = 3) -> list[bytes]:
    """Smallest .jsc files (>= 64 bytes when possible): fastest to trial-decrypt."""
    by_size = sorted(entries.values(), key=len)
    pool = [blob for blob in by_size if len(blob) >= 64] or by_size
    return pool[:count]


def _key_decrypts(data: bytes, key: bytes, sign: bytes = b"") -> bool:
    plain = cocos_xxtea_decrypt(data, key, sign=sign)
    if plain is None:
        return False
    body, kind = unpack_payload(plain)
    return looks_like_script(body, kind)


def recover_key_static(
    lib_path: str,
    entries: dict[str, bytes],
    sign: bytes = b"",
    abort_event: threading.Event | None = None,
    high_prob_done: threading.Event | None = None,
) -> bytes | None:
    if not entries or (abort_event and abort_event.is_set()):
        if high_prob_done is not None:
            high_prob_done.set()
        return None
    t0 = time.monotonic()
    samples = _key_samples(entries)

    # Universal Optimization (Tier 0b - static .data.rel.ro vtable resolution)
    vtable_key = None
    try:
        import r2pipe
        r2 = r2pipe.open(os.path.abspath(lib_path), flags=["-2"])
        try:
            with _r2_abort_guard(r2, abort_event):
                relro_off = _resolve_relro_set_xxtea_key(r2)
                if relro_off and not (abort_event and abort_event.is_set()):
                    raw_bytes = r2.cmd(f"psz @ {relro_off:#x}").strip().encode("latin-1", errors="ignore")
                    if 3 <= len(raw_bytes) <= 32:
                        vtable_key = normalize_key(raw_bytes)
                        slog.info("Candidate key from the .data.rel.ro vtable pointer: %r", vtable_key)
        finally:
            with contextlib.suppress(Exception):
                r2.quit()
    except Exception as e:
        slog.debug("Static vtable check skipped: %s", e)

    if abort_event and abort_event.is_set():
        slog.info("Frida captured the key first; stopping the static search.")
        if high_prob_done is not None:
            high_prob_done.set()
        return None

    if vtable_key and all(_key_decrypts(s, vtable_key, sign=sign) for s in samples):
        elapsed_ms = (time.monotonic() - t0) * 1000
        slog.log(SUCCESS, "Key found via the .data.rel.ro vtable pointer (%.1f ms): %s", elapsed_ms,
                 describe_key(vtable_key))
        if high_prob_done is not None:
            high_prob_done.set()
        return vtable_key

    # Standard tiered scan fallback
    tier_stats: dict[str, int] = {}
    candidates = find_possible_keys(lib_path, sig_prefix=sign, abort_event=abort_event, tier_stats=tier_stats)
    if not candidates or (abort_event and abort_event.is_set()):
        if abort_event and abort_event.is_set():
            slog.info("Frida captured the key first; stopping the static search.")
        if high_prob_done is not None:
            high_prob_done.set()
        return None

    high_prob_count = tier_stats.get("high_prob_count", 0)
    if high_prob_count == 0 and high_prob_done is not None:
        high_prob_done.set()

    slog.info(
        "Testing %d candidate keys against %d sample file(s)%s...",
        len(candidates),
        len(samples),
        f" (stripping {len(sign)}-byte signature {sign!r})" if sign else "",
    )
    for idx, cand in enumerate(candidates, 1):
        if abort_event and abort_event.is_set():
            slog.info("Frida captured the key first; stopping the static search at candidate #%d.", idx)
            if high_prob_done is not None:
                high_prob_done.set()
            return None
        key = normalize_key(cand.encode("latin-1", errors="ignore"))
        if all(_key_decrypts(s, key, sign=sign) for s in samples):
            elapsed_ms = (time.monotonic() - t0) * 1000
            slog.log(SUCCESS, "Key found (candidate #%d, %.1f ms): %s", idx, elapsed_ms, describe_key(key))
            if high_prob_done is not None:
                high_prob_done.set()
            return key
        if idx == high_prob_count and high_prob_done is not None:
            high_prob_done.set()

    if high_prob_done is not None:
        high_prob_done.set()
    return None


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


# --------------------------------------------------------------------------------------
# CLI & Dual-Track Orchestrator
# --------------------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Dump/decrypt Cocos2d-JS / Cocos Creator scripts from an Android app.")
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
