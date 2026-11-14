"""
Cocos-compatible XXTEA & XOR ciphers, plus payload/signature helpers.

Cocos (xxtea.c): key zero-padded/truncated to 16 bytes, little-endian words, and the plaintext
length stored in the last 32-bit word (no PKCS#7 padding).
"""

from __future__ import annotations

import collections
import struct
import zlib
from typing import NamedTuple

from .log import log

ZIP_MAGIC = b"PK\x03\x04"
SPIDERMONKEY_MAGICS = (b"\x2c\xc0\x73\xb9", b"\x1c\xc0\x73\xb9", b"\x2b\xc0\x73\xb9")
PUC_LUA_MAGIC = b"\x1bLua"  # compiled chunk from luac (PUC Lua)
LUAJIT_MAGIC = b"\x1bLJ"    # compiled chunk from luajit -b
LUA_MAGICS = (PUC_LUA_MAGIC, LUAJIT_MAGIC)

# The two Lua toolchains are disjoint, and so are their decompilers, so the flavour is worth
# reporting: a .luac on its own gives no hint of what opens it.
UNLUAC = "unluac"                          # PUC Lua 5.0-5.4; the only tool that reads that format
LUAJIT_DECOMPILER = "a LuaJIT decompiler"  # ljd or luajit-decompiler-v2 (see decompile.py)

_PUC_VERSIONS = {0x51: "5.1", 0x52: "5.2", 0x53: "5.3", 0x54: "5.4", 0x55: "5.5"}
_LUAJIT_VERSIONS = {1: "2.0", 2: "2.1"}

# luajit/src/lj_bcdump.h
_LJ_FLAG_BE = 0x01      # big-endian
_LJ_FLAG_STRIP = 0x02   # debug info stripped
_LJ_FLAG_FFI = 0x04     # uses the FFI library
_LJ_FLAG_FR2 = 0x08     # two-slot frame info, i.e. a GC64 (64-bit) build; LuaJIT 2.1 only


class LuaBytecode(NamedTuple):
    label: str  # e.g. 'LuaJIT 2.1 bytecode (64-bit, stripped)'
    tool: str   # decompiler that handles it


def _read_uleb128(data: bytes, pos: int) -> int | None:
    """Reads a ULEB128 at pos, as LuaJIT's bcdump writes its header fields."""
    result = shift = 0
    for _ in range(5):  # a 32-bit value needs at most 5 bytes
        if pos >= len(data):
            return None
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result
        shift += 7
        pos += 1
    return None


def _labelled(name: str, notes: list[str]) -> str:
    return f"{name} ({', '.join(notes)})" if notes else name


def _describe_luajit(data: bytes) -> LuaBytecode:
    """LuaJIT bcdump header: ESC 'L' 'J', version byte, then ULEB128 flags."""
    if len(data) < 4:
        return LuaBytecode("LuaJIT bytecode (truncated header)", LUAJIT_DECOMPILER)
    known = data[3] in _LUAJIT_VERSIONS
    name = (f"LuaJIT {_LUAJIT_VERSIONS[data[3]]} bytecode" if known
            else f"LuaJIT bytecode (dump version {data[3]})")
    flags = _read_uleb128(data, 4)
    notes = []
    if flags is not None:
        # FR2 only exists from 2.1: on 2.0 its absence says nothing about bitness, and on an
        # unknown dump version the flag layout itself can't be assumed.
        if known and data[3] >= 2:
            notes.append("64-bit (GC64)" if flags & _LJ_FLAG_FR2 else "32-bit")
        if flags & _LJ_FLAG_STRIP:
            notes.append("stripped")
        if flags & _LJ_FLAG_BE:
            notes.append("big-endian")
        if flags & _LJ_FLAG_FFI:
            notes.append("FFI")
    return LuaBytecode(_labelled(name, notes), LUAJIT_DECOMPILER)


def _describe_puc_lua(data: bytes) -> LuaBytecode:
    """PUC Lua header: ESC 'L' 'u' 'a', version byte, format byte, then size fields whose layout
    changed between releases (5.3 inserted LUAC_DATA; 5.4 dropped size_t entirely)."""
    if len(data) < 5:
        return LuaBytecode("PUC Lua bytecode (truncated header)", UNLUAC)
    version_byte = data[4]
    name = (f"PUC Lua {_PUC_VERSIONS[version_byte]} bytecode" if version_byte in _PUC_VERSIONS
            else f"PUC Lua bytecode (version byte {version_byte:#04x})")
    notes = []
    # 5.4 and 5.5 dropped size_t from the header, so there's no bitness to report for them.
    size_t_at = {0x51: 8, 0x52: 8, 0x53: 13}.get(version_byte)
    if version_byte in (0x51, 0x52) and len(data) > 6 and data[6] == 0:
        notes.append("big-endian")
    if size_t_at is not None and len(data) > size_t_at and data[size_t_at] in (4, 8):
        notes.append(f"{data[size_t_at] * 8}-bit")
    # Whether debug info was stripped isn't in the PUC header; it is per-function.
    return LuaBytecode(_labelled(name, notes), UNLUAC)


def describe_lua_bytecode(data: bytes) -> LuaBytecode | None:
    """Identifies a compiled Lua chunk and the decompiler for it, or None if it isn't bytecode."""
    if data.startswith(LUAJIT_MAGIC):
        return _describe_luajit(data)
    if data.startswith(PUC_LUA_MAGIC):
        return _describe_puc_lua(data)
    return None


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
    """Detects a shared signature prefix (e.g. b'kkk' from setXXTEAKeyAndSign) across samples.

    The prefix is taken from the samples that agree, not from all of them. A real game ships the
    odd file that carries no signature among scripts that all do -- an unencrypted chunk, or a
    localisation table -- and taking the prefix common to every sample let one such file reduce it
    to nothing, which leaves the whole game undecryptable: without the signature even the right
    key decrypts none of it.
    A clear majority has to agree, so a few coincidentally alike resources cannot invent a
    signature either. Samples that are recognisably some other format are set aside first, rather
    than the whole search giving up because the one it looked at first was a plain chunk.

    The majority is strict, chosen with no counter-example to tune it against: a game that is half
    signed and half not would still come out with no signature. If one turns up, this is the rule
    to revisit.
    """
    usable = [s for s in samples
              if len(s) >= 8
              and not s.startswith((ZIP_MAGIC, b"\x1f\x8b") + LUA_MAGICS)
              and s[:4] not in SPIDERMONKEY_MAGICS]
    if not usable:
        return b""

    signed = usable
    if len(usable) >= 2:
        # The largest group of samples that even begin alike. Short of a majority there is
        # nothing here worth calling the game's signature.
        lead, agreeing = collections.Counter(s[:1] for s in usable).most_common(1)[0]
        if agreeing < 2 or agreeing * 2 <= len(usable):
            return b""
        signed = [s for s in usable if s[:1] == lead]

    first = signed[0]
    prefix = bytearray()
    if len(signed) >= 2:   # one sample has nothing to share a prefix with
        limit = min(max_len, min(len(s) for s in signed))
        for i in range(limit):
            b = first[i]
            if all(s[i] == b for s in signed[1:]):
                prefix.append(b)
            else:
                break
        # XXTEA ciphertext is a whole number of 32-bit words, so a prefix leaving a remainder
        # behind cannot all be signature.
        while prefix and any((len(s) - len(prefix)) % 4 != 0 for s in signed):
            prefix.pop()

    if not prefix:
        rems = {len(s) % 4 for s in signed}
        if len(rems) == 1:
            rem = rems.pop()
            if rem != 0 and all(s[:rem] == first[:rem] for s in signed):
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


def unpack_payload(data: bytes) -> tuple[bytes, str]:
    """Returns (body, kind): kind is 'zip', 'gzip' (decompressed), 'bytecode' (SpiderMonkey),
    'luabytecode', or 'raw'."""
    if data.startswith(ZIP_MAGIC):
        return data, "zip"
    if data[:4] in SPIDERMONKEY_MAGICS:
        return data, "bytecode"
    if data.startswith(LUA_MAGICS):
        return data, "luabytecode"
    try:
        return zlib.decompress(data, 15 + 32), "gzip"
    except zlib.error:
        return data, "raw"


def looks_like_script(body: bytes, kind: str) -> bool:
    if not body:
        return False
    if kind in ("gzip", "zip", "bytecode", "luabytecode"):
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
