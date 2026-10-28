"""
Cocos-compatible XXTEA & XOR ciphers, plus payload/signature helpers.

Cocos (xxtea.c): key zero-padded/truncated to 16 bytes, little-endian words, and the plaintext
length stored in the last 32-bit word (no PKCS#7 padding).
"""

from __future__ import annotations

import struct
import zlib

from .log import log

ZIP_MAGIC = b"PK\x03\x04"
SPIDERMONKEY_MAGICS = (b"\x2c\xc0\x73\xb9", b"\x1c\xc0\x73\xb9", b"\x2b\xc0\x73\xb9")
LUA_MAGICS = (b"\x1bLua", b"\x1bLJ")  # compiled chunks: PUC Lua (luac) and LuaJIT

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
    if first.startswith((ZIP_MAGIC, b"\x1f\x8b") + LUA_MAGICS) or first[:4] in SPIDERMONKEY_MAGICS:
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
