"""Shared fixtures: synthetic Cocos assets built the way a real game ships them."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from coconuts.ciphers import normalize_key

_DELTA = 0x9E3779B9
_MASK = 0xFFFFFFFF

# Compiled-chunk headers. LuaJIT: ESC L J, dump version 2 (2.1), flags FR2|STRIP.
# PUC: ESC L u a, 5.1, official format, little-endian, 4/8/4/8 size fields, non-integral.
LUAJIT_CHUNK = b"\x1bLJ\x02\x0a" + b"\x00" * 40
PUC_CHUNK = b"\x1bLua\x51\x00\x01\x04\x08\x04\x08\x00" + b"\x00" * 32
LUA_SOURCE = b"local M = {}\nfunction M.run() print('hi') end\nreturn M\n"

SIGN = b"XXTEA"
KEY_TEXT = b"thekey"


def xxtea_encrypt(data: bytes, key16: bytes) -> bytes:
    """Cocos xxtea.c encrypt: little-endian words with the plaintext length in the last word."""
    pad = (-len(data)) % 4
    v = list(struct.unpack(f"<{(len(data) + pad) // 4}I", data + b"\0" * pad)) + [len(data)]
    k = list(struct.unpack("<4I", key16))
    n = len(v)
    rounds, s = 6 + 52 // n, 0
    z = v[n - 1]
    for _ in range(rounds):
        s = (s + _DELTA) & _MASK
        e = (s >> 2) & 3
        for p in range(n):
            y = v[(p + 1) % n]
            mx = ((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
                  ^ ((s ^ y) + (k[(p & 3) ^ e] ^ z))) & _MASK
            v[p] = z = (v[p] + mx) & _MASK
    return struct.pack(f"<{n}I", *v)


def encrypt_asset(data: bytes, key: bytes = KEY_TEXT, sign: bytes = SIGN) -> bytes:
    return sign + xxtea_encrypt(data, normalize_key(key))


@pytest.fixture
def key() -> bytes:
    return normalize_key(KEY_TEXT)


@pytest.fixture
def assets() -> dict[str, bytes]:
    """A mixed Lua game: encrypted LuaJIT and PUC chunks, plus scripts shipped in the clear."""
    return {
        "src/main.luac": encrypt_asset(LUAJIT_CHUNK),
        "src/app/MyApp.luac": encrypt_asset(LUAJIT_CHUNK + b"\x01"),
        "src/legacy.luac": encrypt_asset(PUC_CHUNK),
        "src/config.lua": encrypt_asset(LUA_SOURCE),
        "src/plain.luac": PUC_CHUNK,   # unencrypted bytecode: copied as-is
        "src/plain.lua": LUA_SOURCE,   # unencrypted source: copied as-is
        "res/logo.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 16,  # not a script
    }


@pytest.fixture
def asset_dir(tmp_path: Path, assets: dict[str, bytes]) -> Path:
    """An extracted APK tree (assets/... on disk), which --apk also accepts."""
    root = tmp_path / "game"
    for rel, blob in assets.items():
        path = root / "assets" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
    return root


@pytest.fixture
def apk(tmp_path: Path, assets: dict[str, bytes]) -> Path:
    """A zip shaped like an APK, so the zip reading path is covered too."""
    path = tmp_path / "game.apk"
    with zipfile.ZipFile(path, "w") as zf:
        for rel, blob in assets.items():
            zf.writestr(f"assets/{rel}", blob)
        zf.writestr("classes.dex", b"dex\n035\x00")
    return path
