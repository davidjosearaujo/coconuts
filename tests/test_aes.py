"""EncryptManager AES-256-CBC: the cipher layout and the offline path that streams every asset.

The encryptor here is written from the layout documented in coconuts/aes.py rather than by calling
the decrypt code backwards, so a mistake in the shared key schedule can't cancel out.
"""

from __future__ import annotations

import struct
import tracemalloc
import zlib
from pathlib import Path

import pytest
from Crypto.Cipher import AES

from coconuts.aes import (
    AES_DEADBEEF,
    _aes_derive_sign_key,
    _aes_norm_iv,
    _aes_norm_key,
    aes_roll_from_flags,
    cocos_aes_decrypt,
)
from coconuts.extract import extract_offline

from .conftest import LUA_SOURCE, LUAJIT_CHUNK, asset_source, write_asset_dir

KEY, IV, ROLL = b"aes-test-key", b"0123456789abcdef", 5


def aes_encrypt(data: bytes, key: bytes = KEY, iv: bytes = IV, roll: int = ROLL,
                compress: bool = True) -> bytes:
    body = zlib.compress(data) if compress else data
    pad = 16 - len(body) % 16
    body += bytes([pad]) * pad
    cipher = AES.new(_aes_norm_key(key), AES.MODE_CBC, _aes_norm_iv(iv)).encrypt(body)
    # <u32 mask><u32 sigval><u8 flags><i32 original_size><3 reserved>, sealed with the sign key
    sig = struct.pack("<II", 0x12345678, 0x12345678 ^ AES_DEADBEEF)
    sig += struct.pack("<Bi", 1 if compress else 0, len(data)) + b"\0\0\0"
    return cipher + AES.new(_aes_derive_sign_key(key, iv, roll), AES.MODE_ECB).encrypt(sig)


class TestCipher:
    @pytest.mark.parametrize("compress", [True, False])
    def test_round_trip(self, compress: bool) -> None:
        blob = LUA_SOURCE * 20
        assert cocos_aes_decrypt(aes_encrypt(blob, compress=compress), KEY, IV, ROLL) == blob

    @pytest.mark.parametrize("what,key,iv,roll", [
        ("key", b"other", IV, ROLL), ("iv", KEY, b"fedcba9876543210", ROLL), ("roll", KEY, IV, 4),
    ])
    def test_wrong_parameter_is_detected_by_the_signature(self, what, key, iv, roll) -> None:
        assert cocos_aes_decrypt(aes_encrypt(LUA_SOURCE), key, iv, roll) is None, what

    def test_a_file_that_is_not_encrypted_is_not_mistaken_for_one(self) -> None:
        assert cocos_aes_decrypt(b"\x89PNG\r\n\x1a\n" + b"\0" * 64, KEY, IV, ROLL) is None
        assert cocos_aes_decrypt(b"short", KEY, IV, ROLL) is None

    def test_empty_iv_means_sixteen_ones(self) -> None:
        assert _aes_norm_iv(b"") == b"\x01" * 16
        assert cocos_aes_decrypt(aes_encrypt(LUA_SOURCE, iv=b""), KEY, b"", ROLL) == LUA_SOURCE

    def test_key_is_padded_and_truncated_to_32(self) -> None:
        assert _aes_norm_key(b"k") == b"k" + b"\0" * 31
        assert _aes_norm_key(b"x" * 40) == b"x" * 32

    def test_roll_lives_in_the_high_half_of_the_flags_word(self) -> None:
        assert aes_roll_from_flags(0x0005_0003) == 5
        assert aes_roll_from_flags(0x0003) == 0

    def test_without_a_signature_there_is_no_integrity_check(self) -> None:
        body = aes_encrypt(LUA_SOURCE)[:-16]  # drop the sign block
        assert cocos_aes_decrypt(body, KEY, IV, signature=False, compressed=True) == LUA_SOURCE


@pytest.fixture
def assets() -> dict[str, bytes]:
    return {
        "src/main.luac": aes_encrypt(LUAJIT_CHUNK),
        "src/app.lua": aes_encrypt(LUA_SOURCE),
        "res/config.json": aes_encrypt(b'{"level": 1}'),
        "res/logo.png": aes_encrypt(b"\x89PNG\r\n\x1a\n" + b"\0" * 32),
        "res/readme.txt": b"shipped in the clear",
    }


def as_apk(tmp_path: Path, assets: dict[str, bytes]) -> str:
    return asset_source(tmp_path, "apk", assets)


class TestOfflineAes:
    def test_every_asset_type_is_decrypted(self, tmp_path: Path, kind: str, assets) -> None:
        out = tmp_path / "out"
        source = asset_source(tmp_path, kind, assets)
        n = extract_offline([source], None, None, str(out), aes=(KEY, IV, ROLL))
        assert n == 4
        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "src/app.lua").read_bytes() == LUA_SOURCE
        assert (out / "res/config.json").read_bytes() == b'{"level": 1}'
        assert (out / "res/logo.png").read_bytes().startswith(b"\x89PNG")
        assert (out / "res/readme.txt").read_bytes() == b"shipped in the clear"  # copied as-is

    def test_a_wrong_key_writes_nothing_but_the_raw_scripts(self, tmp_path: Path, assets) -> None:
        out = tmp_path / "out"
        n = extract_offline([as_apk(tmp_path, assets)], None, None, str(out), aes=(b"wrong", IV, ROLL))
        assert n == 0
        assert not (out / "res/config.json").exists()
        assert (out / "raw_scripts/src/main.luac").exists()

    def test_live_dumps_win(self, tmp_path: Path, assets) -> None:
        out = tmp_path / "out"
        (out / "src").mkdir(parents=True)
        (out / "src/app.lua").write_bytes(b"live")
        extract_offline([as_apk(tmp_path, assets)], None, None, str(out), aes=(KEY, IV, ROLL))
        assert (out / "src/app.lua").read_bytes() == b"live"

    def test_no_assets(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        assert extract_offline([str(empty)], None, None, str(tmp_path / "out"), aes=(KEY, IV, ROLL)) == 0

    def test_without_scripts_the_key_is_unverified_but_assets_still_decrypt(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        only_res = {"res/config.json": aes_encrypt(b'{"a": 1}')}
        out = tmp_path / "out"
        with caplog.at_level("WARNING"):
            n = extract_offline([as_apk(tmp_path, only_res)], None, None, str(out), aes=(KEY, IV, ROLL))
        assert n == 1
        assert "No encrypted scripts to verify the AES key" in caplog.text

    def test_assets_are_streamed_rather_than_held_all_at_once(self, tmp_path: Path) -> None:
        """Peak memory stays near one asset's size, however many assets there are."""
        size, count = 1 << 20, 24
        incompressible = [bytes((i * 31 + j * 7) & 0xFF for j in range(1024)) * (size // 1024)
                          for i in range(count)]
        loose = {f"res/blob{i}.bin": aes_encrypt(b, compress=False) for i, b in enumerate(incompressible)}
        loose["src/app.lua"] = aes_encrypt(LUA_SOURCE)
        root = write_asset_dir(tmp_path / "game", loose)
        del loose, incompressible

        tracemalloc.start()
        try:
            n = extract_offline([root], None, None, str(tmp_path / "out"), aes=(KEY, IV, ROLL))
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert n == count + 1
        # Holding everything would cost count * size (24 MiB) plus the decrypted copies.
        assert peak < 8 * size, f"peak {peak / size:.1f} MiB for {count} one-MiB assets"
