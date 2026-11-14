"""Cipher helpers and compiled-Lua identification."""

from __future__ import annotations

import pytest

from coconuts.ciphers import (
    LUAJIT_DECOMPILER,
    UNLUAC,
    cocos_xxtea_decrypt,
    describe_lua_bytecode,
    detect_signature_prefix,
    normalize_key,
    unpack_payload,
)

from .conftest import LUA_SOURCE, LUAJIT_CHUNK, PUC_CHUNK, SIGN, encrypt_asset, xxtea_encrypt


class TestXxtea:
    def test_roundtrip_with_signature(self, key: bytes) -> None:
        assert cocos_xxtea_decrypt(encrypt_asset(LUA_SOURCE), key, sign=SIGN) == LUA_SOURCE

    def test_wrong_key_is_rejected(self, key: bytes) -> None:
        wrong = normalize_key(b"nothekey")
        assert cocos_xxtea_decrypt(encrypt_asset(LUA_SOURCE), wrong, sign=SIGN) != LUA_SOURCE

    def test_key_is_padded_to_sixteen_bytes(self) -> None:
        assert len(normalize_key(b"short")) == 16
        assert len(normalize_key(b"x" * 40)) == 16

    def test_short_input_does_not_raise(self, key: bytes) -> None:
        assert cocos_xxtea_decrypt(b"", key) is None
        assert cocos_xxtea_decrypt(SIGN + b"\x01\x02", key, sign=SIGN) is None


class TestSignatureDetection:
    def test_common_prefix_is_found(self, key: bytes) -> None:
        samples = [encrypt_asset(LUA_SOURCE), encrypt_asset(LUAJIT_CHUNK), encrypt_asset(PUC_CHUNK)]
        assert detect_signature_prefix(samples) == SIGN

    def test_unsigned_payloads_report_no_prefix(self) -> None:
        # Distinct plaintexts, so the ciphertexts share nothing but chance.
        key = normalize_key(b"k")
        samples = [xxtea_encrypt(LUA_SOURCE + bytes([i]) * (i + 1), key) for i in range(4)]
        assert detect_signature_prefix(samples) == b""

    def test_plain_bytecode_is_not_mistaken_for_a_signature(self) -> None:
        assert detect_signature_prefix([LUAJIT_CHUNK, LUAJIT_CHUNK]) == b""

    def test_one_unsigned_file_does_not_hide_the_signature(self) -> None:
        """The real failure this came from: a game ships a localisation table in plain Lua among
        scripts that all carry the signature. Taking the prefix common to every sample let that
        one file reduce it to nothing, and without the signature nothing decrypts at all."""
        samples = [encrypt_asset(LUA_SOURCE), encrypt_asset(LUAJIT_CHUNK),
                   encrypt_asset(PUC_CHUNK), b"local root = { a = 'Hallo' }\n"]
        assert detect_signature_prefix(samples) == SIGN

    def test_a_plain_chunk_first_does_not_abort_the_search(self) -> None:
        """It used to look only at the first sample to decide the whole list was unsigned."""
        samples = [LUAJIT_CHUNK, encrypt_asset(LUA_SOURCE), encrypt_asset(PUC_CHUNK),
                   encrypt_asset(LUAJIT_CHUNK)]
        assert detect_signature_prefix(samples) == SIGN

    def test_a_signature_needs_a_majority(self) -> None:
        """Half the samples agreeing is not a game's signature, it is a coincidence."""
        samples = [encrypt_asset(LUA_SOURCE), encrypt_asset(PUC_CHUNK),
                   b"AAAA" + b"\x11" * 12, b"BBBB" + b"\x22" * 12]
        assert detect_signature_prefix(samples) == b""

    def test_a_single_script_still_yields_its_signature(self) -> None:
        """A game with one encrypted script has nothing to share a prefix with, but the length
        left over once whole 32-bit words are taken away still gives the signature up."""
        sample = b"kkk" + bytes(range(8, 48))      # 43 bytes: 3 left over after the words
        assert detect_signature_prefix([sample]) == b"kkk"

    def test_two_lookalike_resources_do_not_invent_one(self) -> None:
        samples = [b"RIFFxxxxWAVE1234", b"RIFFyyyyWAVE5678"]
        assert detect_signature_prefix(samples) in (b"", b"RIFF")  # never a longer invention


class TestUnpackPayload:
    @pytest.mark.parametrize("blob,kind", [
        (LUAJIT_CHUNK, "luabytecode"),
        (PUC_CHUNK, "luabytecode"),
        (LUA_SOURCE, "raw"),
        (b"PK\x03\x04rest", "zip"),
    ])
    def test_kind(self, blob: bytes, kind: str) -> None:
        assert unpack_payload(blob)[1] == kind


class TestDescribeLuaBytecode:
    @pytest.mark.parametrize("data,label,tool", [
        (b"\x1bLJ\x02\x0a", "LuaJIT 2.1 bytecode (64-bit (GC64), stripped)", LUAJIT_DECOMPILER),
        (b"\x1bLJ\x02\x00", "LuaJIT 2.1 bytecode (32-bit)", LUAJIT_DECOMPILER),
        (b"\x1bLJ\x02\x0e", "LuaJIT 2.1 bytecode (64-bit (GC64), stripped, FFI)", LUAJIT_DECOMPILER),
        (b"\x1bLJ\x01\x02", "LuaJIT 2.0 bytecode (stripped)", LUAJIT_DECOMPILER),
        (b"\x1bLJ\x01\x01", "LuaJIT 2.0 bytecode (big-endian)", LUAJIT_DECOMPILER),
        (b"\x1bLua\x51\x00\x01\x04\x08\x04\x08\x00", "PUC Lua 5.1 bytecode (64-bit)", UNLUAC),
        (b"\x1bLua\x51\x00\x01\x04\x04\x04\x08\x00", "PUC Lua 5.1 bytecode (32-bit)", UNLUAC),
        (b"\x1bLua\x51\x00\x00\x04\x04\x04\x08\x00", "PUC Lua 5.1 bytecode (big-endian, 32-bit)", UNLUAC),
        (b"\x1bLua\x52\x00\x01\x04\x08\x04\x08\x00", "PUC Lua 5.2 bytecode (64-bit)", UNLUAC),
        (b"\x1bLua\x53\x00\x19\x93\r\n\x1a\n\x04\x08\x04\x08\x08", "PUC Lua 5.3 bytecode (64-bit)", UNLUAC),
        (b"\x1bLua\x54\x00\x19\x93\r\n\x1a\n\x04\x08\x08", "PUC Lua 5.4 bytecode", UNLUAC),
    ])
    def test_known_headers(self, data: bytes, label: str, tool: str) -> None:
        got = describe_lua_bytecode(data)
        assert got is not None
        assert (got.label, got.tool) == (label, tool)

    @pytest.mark.parametrize("data", [b"", b"print(1)", b"PK\x03\x04", b"\x1bLu", b"\x1bL"])
    def test_not_bytecode(self, data: bytes) -> None:
        assert describe_lua_bytecode(data) is None

    def test_truncated_headers_say_so(self) -> None:
        assert describe_lua_bytecode(b"\x1bLJ").label == "LuaJIT bytecode (truncated header)"
        assert describe_lua_bytecode(b"\x1bLua").label == "PUC Lua bytecode (truncated header)"

    def test_unknown_luajit_version_does_not_guess_bitness(self) -> None:
        # The FR2 flag only exists from 2.1; on an unknown dump version the layout is unknown too.
        label = describe_lua_bytecode(b"\x1bLJ\x09\x0a").label
        assert "dump version 9" in label
        assert "bit" not in label

    def test_unknown_puc_version_is_reported_verbatim(self) -> None:
        assert describe_lua_bytecode(b"\x1bLua\x99\x00").label == "PUC Lua bytecode (version byte 0x99)"

    def test_missing_luajit_flags_byte_is_tolerated(self) -> None:
        assert describe_lua_bytecode(b"\x1bLJ\x02").label == "LuaJIT 2.1 bytecode"
