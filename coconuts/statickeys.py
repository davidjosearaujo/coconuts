"""
Static XXTEA/XOR key recovery from the library's strings (ranked Tier 0 -> Tier 3), plus the
known-plaintext XOR attack and the key-verification helpers.
"""

from __future__ import annotations

import contextlib
import os
import re
import threading
import time

from .ciphers import (
    cocos_xxtea_decrypt,
    describe_key,
    looks_like_script,
    normalize_key,
    strip_signature,
    unpack_payload,
    xor_decrypt,
)
from .arm64 import find_key_and_sign
from .log import SUCCESS, slog
from .r2 import _r2_abort_guard

# Known plaintexts for instant (<1ms) XOR key recovery: the first bytes of a script are the same in
# every game, so the keystream can be read straight off an encrypted file.
#
# A repeating key of length k needs a known run of at least 2k bytes to be told from chance, so the
# length of each header sets the longest key the attack can find: 66 bytes for the Cocos2d-js
# bundle, 12-33 for the PUC Lua headers, but only 5 for LuaJIT, where just the single-byte keys
# can be seen.
KNOWN_PLAINTEXT_HEADERS = [
    # Cocos2d-js
    b"(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){",
    b"\x2c\xc0\x73\xb9\x00\x00\x00\x00\x00\x00\x00\x00",  # Compiled SpiderMonkey JS
    # PUC Lua bytecode, up to and including the format check: version, format, then the sizes of
    # int / size_t / Instruction (/ lua_Integer / lua_Number) and, from 5.2 on, LUAC_DATA, and from
    # 5.3 on LUAC_INT and LUAC_NUM. The 5.1 variants are the 64-bit and the 32-bit ARM layouts.
    bytes.fromhex("1b4c7561510001040804080" "0"),
    bytes.fromhex("1b4c7561510001040404080" "0"),
    bytes.fromhex("1b4c75615200010408040800" "19930d0a1a0a"),
    bytes.fromhex("1b4c756153" "00" "19930d0a1a0a" "0408040808" "7856000000000000" "0000000000" "287740"),
    bytes.fromhex("1b4c756154" "00" "19930d0a1a0a" "040808" "7856000000000000" "0000000000" "287740"),
]
# LuaJIT: ESC 'L' 'J' and the dump version (1 = 2.0, 2 = 2.1). The flags byte that follows varies
# between builds, and knowing it would gain nothing: a repeating key needs a known run of 2k bytes
# to be told from chance, so both 4 and 5 known bytes only ever expose a 1-byte key. Four bytes it
# is, rather than enumerating the eight plausible flag values for the same result.
KNOWN_PLAINTEXT_HEADERS += [b"\x1bLJ" + bytes([version]) for version in (1, 2)]

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
    "src/main.lua",
}


_ADRP_RE = re.compile(r"adrp\s+(\w+),")
_ADD_RE = re.compile(r"add\s+(\w+),\s*(\w+),\s*#?(?:0x[0-9a-fA-F]+|\d+)")
# `psz` prints non-printable bytes as escapes, so binary data comes back as literal "\x7f..."
# text, which passes str.isprintable() and used to be collected as a candidate key.
_ESCAPED_RE = re.compile(r"\\[xu]")


def _add_string_at(r2, out: dict[str, None], addr: int) -> None:
    """Reads a C string at `addr` and keeps it if it could plausibly be a key."""
    if addr <= 0x1000:
        return
    try:
        s = r2.cmd(f"psz @ {addr:#x}").strip()
    except Exception:
        return
    if 3 <= len(s) <= 32 and s.isprintable() and not _ESCAPED_RE.search(s) and s not in _KEY_EXCLUDE:
        out.setdefault(s, None)


def recover_xor_key_kp(entries: dict[str, bytes], sign: bytes = b"") -> bytes | None:
    """
    Known-plaintext XOR attack against Cocos2d-js bundles and compiled Lua chunks.
    Recovers repeating XOR keys in <1ms (see KNOWN_PLAINTEXT_HEADERS for which lengths).
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


def extract_r2_priority_keys(
    lib_path: str,
    abort_event: threading.Event | None = None,
) -> list[str]:
    """
    Tier 0 ('Framework: Cocos2d-js'):
    Extracts string literals referenced directly inside AppDelegate::applicationDidFinishLaunching
    or jsb_set_xxtea_key callers via lightweight single-function r2 disassembly (no `aap; aaef`).
    Lua games pass their literal key to LuaStack::setXXTEAKeyAndSign from the same AppDelegate
    function, so this covers them too.
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
                pages: dict[str, int] = {}  # register -> page base from the last adrp into it
                for op in ops:
                    if abort_event and abort_event.is_set():
                        break
                    disasm = op.get("disasm") or ""

                    # arm64 builds a string address as `adrp xN, <page>` + `add xN, xN, #<off>`.
                    # Only the adrp carries a `ptr`, and it is the 4 KB page base, not the string:
                    # following it alone reads whatever sits at the page boundary. r2 resolves the
                    # pair into op["refs"], but only after a full `aaa`, which is far too slow
                    # here, so the two halves are joined from what the cheap `af` already gives.
                    adrp = _ADRP_RE.match(disasm)
                    if adrp:
                        if op.get("ptr"):
                            pages[adrp.group(1)] = op["ptr"]
                        continue
                    add = _ADD_RE.match(disasm)
                    if add and add.group(2) in pages and op.get("val") is not None:
                        _add_string_at(r2, out, pages[add.group(2)] + op["val"])
                        continue

                    for ref in op.get("refs") or []:  # present when richer analysis has run
                        if ref.get("type") in ("STRN", "STRING") and ref.get("addr"):
                            _add_string_at(r2, out, ref["addr"])
                    ptr = op.get("ptr")
                    if ptr and ptr > 0x1000:
                        _add_string_at(r2, out, ptr)
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

    # Tier 0a: the exact arguments of the setXXTEAKeyAndSign call, read from the instructions.
    # No radare2 needed, and unlike the string tiers this knows which literal is the key.
    for pair in find_key_and_sign(lib_path):
        with contextlib.suppress(UnicodeDecodeError):
            found.setdefault(pair.key.decode("ascii"), None)

    # Tier 0b: Exact string pointers from AppDelegate::applicationDidFinishLaunching via r2
    for s in extract_r2_priority_keys(lib_path, abort_event=abort_event):
        found.setdefault(s, None)
    tier0_count = len(found)
    if abort_event and abort_event.is_set():
        return []

    # Tier 1a: Immediate 128-byte pre-window before 'main.js\0' and '<sig_prefix>\0'
    tight_anchors = [b"main.js\x00", b"jsb-adapter/jsb-builtin.js\x00", b"main.lua\x00", b"0.0.0.0\x00"]
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
    for anchor in (b"main.js\x00", b"jsb-adapter", b"jsb_polyfill", b"project.jsc", b"main.lua\x00",
                   b"0.0.0.0\x00"):
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


def _key_samples(entries: dict[str, bytes], count: int = 3) -> list[bytes]:
    """Smallest encrypted scripts (>= 64 bytes when possible): fastest to trial-decrypt."""
    by_size = sorted(entries.values(), key=len)
    pool = [blob for blob in by_size if len(blob) >= 64] or by_size
    return pool[:count]


def _key_decrypts(data: bytes, key: bytes, sign: bytes = b"") -> bool:
    plain = cocos_xxtea_decrypt(data, key, sign=sign)
    if plain is None:
        return False
    body, kind = unpack_payload(plain)
    return looks_like_script(body, kind)


def recover_key_and_sign_static(
    lib_path: str,
    entries: dict[str, bytes],
) -> tuple[bytes, bytes] | None:
    """Reads the key and its signature from the setXXTEAKeyAndSign call site, both verified.

    This is the precise counterpart to the string tiers: instead of collecting every literal in
    applicationDidFinishLaunching and trial-decrypting them, it reads the two arguments the engine
    actually passes, so the signature is known rather than guessed from a common prefix.
    """
    if not entries or not lib_path:
        return None
    pairs = find_key_and_sign(lib_path)
    if not pairs:
        return None
    samples = _key_samples(entries)
    for pair in pairs:
        key = normalize_key(pair.key)
        if all(_key_decrypts(s, key, sign=pair.sign) for s in samples):
            slog.log(SUCCESS, "Key and signature read from the engine library (%s): %s, "
                              "signature %r", pair.where, describe_key(key), pair.sign)
            return key, pair.sign
    slog.debug("arm64 scan found %d pair(s), none of which decrypt the scripts.", len(pairs))
    return None


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

    # No static .data.rel.ro probe here: that slot points at setXXTeaKey's code, and the key is only
    # its argument. The Frida track hooks that function to read the argument at runtime instead.
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
