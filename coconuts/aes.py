"""
x-studio / EncryptManager AES-CBC (cocos2d-x & axmol EncryptManager::setEncryptEnabled).

Layout of an encrypted asset, mirroring EncryptManager.cpp from simdsoft's HelloCrypto:
  body = AES-256-CBC( PKCS7( zlib.compress(plaintext) ) )      # zlib only if ENCF_COMPRESS
  file = body + sign_block                                     # sign_block only if ENCF_SIGNATURE
The 16-byte sign_block is AES-128-ECB(sign_key) of:
  <u32 mask><u32 sigval><u8 flags><i32 original_size><3 bytes reserved>
and is valid iff (mask ^ sigval) == 0xDEADBEEF. flags & 3 => the data was zlib-compressed.
sign_key is derived from key+iv by `roll` rounds of AES-128-ECB (see _aes_derive_sign_key).
Defaults (setEncryptEnabled's default `flags`): ENCF_COMPRESS|ENCF_SIGNATURE, roll = 5.
"""

from __future__ import annotations

import struct
import zlib

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
