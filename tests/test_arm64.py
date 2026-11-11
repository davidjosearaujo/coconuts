"""Reading the key and signature out of the engine library's instructions.

There is no aarch64 linker on most dev hosts, so fixtures/mkelf.py assembles the shared objects
directly. That also lets each test vary one thing -- the vtable offset, the symbol, the argument
order -- which a compiler wouldn't let us control.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coconuts.arm64 import find_key_and_sign
from coconuts.ciphers import normalize_key
from coconuts.extract import extract_offline
from coconuts.statickeys import recover_key_and_sign_static

from .conftest import LUA_SOURCE, LUAJIT_CHUNK, xxtea_encrypt
from .fixtures.mkelf import build

KEY = b"cocos2d_lua_js"   # the key from the Ghidra listing this was written against
SIGN = b"LJ"
DECOYS = (b"base/", b"res/raw", b"applicationDidFinishLaunching", b"0.0.0.0")


def write_lib(tmp_path: Path, name: str = "libcocos2dlua.so", **kwargs) -> str:
    kwargs.setdefault("decoy_strings", DECOYS)
    path = tmp_path / name
    path.write_bytes(build(KEY, SIGN, **kwargs))
    return str(path)


class TestFindKeyAndSign:
    def test_reads_both_arguments(self, tmp_path: Path) -> None:
        pairs = find_key_and_sign(write_lib(tmp_path))
        assert pairs, "nothing found"
        assert (pairs[0].key, pairs[0].sign) == (KEY, SIGN)
        assert "vtable+0xe8" in pairs[0].where

    def test_offers_the_reversed_reading_second(self, tmp_path: Path) -> None:
        """Which argument is the key can't be known from the shape alone, so both orders are
        offered and trial decryption settles it. The canonical one comes first."""
        pairs = find_key_and_sign(write_lib(tmp_path))
        assert (pairs[1].key, pairs[1].sign) == (SIGN, KEY)

    def test_works_on_a_stripped_library(self, tmp_path: Path) -> None:
        """No symbol to start from, so the executable sections are swept instead."""
        pairs = find_key_and_sign(write_lib(tmp_path, symbols={}))
        assert (pairs[0].key, pairs[0].sign) == (KEY, SIGN)

    def test_unknown_vtable_offset_still_matches(self, tmp_path: Path) -> None:
        """The offset varies by Cocos version, so it's a hint; the argument shape is the signal."""
        pairs = find_key_and_sign(write_lib(tmp_path, vtable_off=0x120))
        assert (pairs[0].key, pairs[0].sign) == (KEY, SIGN)
        assert "vtable" not in pairs[0].where

    def test_decoy_strings_are_not_picked_up(self, tmp_path: Path) -> None:
        for pair in find_key_and_sign(write_lib(tmp_path)):
            assert pair.key not in DECOYS and pair.sign not in DECOYS

    def test_swapped_arguments_are_still_found(self, tmp_path: Path) -> None:
        pairs = find_key_and_sign(write_lib(tmp_path, swap_arg_order=True))
        assert {(p.key, p.sign) for p in pairs} == {(KEY, SIGN), (SIGN, KEY)}

    @pytest.mark.parametrize("blob", [
        b"",
        b"not an elf at all",
        b"\x7fELF\x01\x01\x01" + b"\0" * 200,            # 32-bit
        b"\x7fELF\x02\x02\x01" + b"\0" * 200,            # big-endian
        b"\x7fELF\x02\x01\x01" + b"\0" * 11 + b"\x3e\x00" + b"\0" * 200,  # x86-64
    ])
    def test_rejects_what_it_cannot_read(self, tmp_path: Path, blob: bytes) -> None:
        path = tmp_path / "odd.so"
        path.write_bytes(blob)
        assert find_key_and_sign(str(path)) == []

    def test_truncated_library(self, tmp_path: Path) -> None:
        full = build(KEY, SIGN)
        path = tmp_path / "cut.so"
        path.write_bytes(full[:len(full) // 2])
        assert find_key_and_sign(str(path)) == []       # no crash, no result

    def test_missing_file(self, tmp_path: Path) -> None:
        assert find_key_and_sign(str(tmp_path / "nope.so")) == []

    def test_length_must_match_the_string(self, tmp_path: Path) -> None:
        """A call passing two strings but the wrong lengths isn't a key/signature call."""
        path = tmp_path / "wrong.so"
        path.write_bytes(build(KEY, SIGN, wrong_lengths=True))
        assert find_key_and_sign(str(path)) == []


class TestRecoverKeyAndSignStatic:
    @pytest.fixture
    def entries(self) -> dict[str, bytes]:
        enc = lambda blob: SIGN + xxtea_encrypt(blob, normalize_key(KEY))
        return {"src/main.luac": enc(LUAJIT_CHUNK), "src/app.lua": enc(LUA_SOURCE)}

    def test_verified_pair(self, tmp_path: Path, entries: dict[str, bytes]) -> None:
        got = recover_key_and_sign_static(write_lib(tmp_path), entries)
        assert got == (normalize_key(KEY), SIGN)

    def test_reversed_reading_is_rejected_by_verification(self, tmp_path: Path,
                                                          entries: dict[str, bytes]) -> None:
        """Both orders are offered; only the one that actually decrypts survives."""
        lib = write_lib(tmp_path, swap_arg_order=True)
        assert recover_key_and_sign_static(lib, entries) == (normalize_key(KEY), SIGN)

    def test_wrong_library_yields_nothing(self, tmp_path: Path,
                                          entries: dict[str, bytes]) -> None:
        other = tmp_path / "other.so"
        other.write_bytes(build(b"a_different_key", b"ZZ"))
        assert recover_key_and_sign_static(str(other), entries) is None

    def test_no_entries(self, tmp_path: Path) -> None:
        assert recover_key_and_sign_static(write_lib(tmp_path), {}) is None


class TestEndToEnd:
    def test_decrypts_with_neither_key_nor_signature_given(self, tmp_path: Path,
                                                           caplog: pytest.LogCaptureFixture) -> None:
        """The whole point: a Lua game whose key and 2-byte signature are both unknown."""
        game = tmp_path / "game"
        (game / "assets/src").mkdir(parents=True)
        enc = lambda blob: SIGN + xxtea_encrypt(blob, normalize_key(KEY))
        (game / "assets/src/main.luac").write_bytes(enc(LUAJIT_CHUNK))
        (game / "assets/src/app.lua").write_bytes(enc(LUA_SOURCE))
        lib = write_lib(tmp_path)

        out = tmp_path / "out"
        with caplog.at_level("INFO"):
            written = extract_offline([str(game)], None, lib, str(out))

        assert written == 2
        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "src/app.lua").read_bytes() == LUA_SOURCE
        assert "Key and signature read from the engine library" in caplog.text

    def test_explicit_sign_still_wins(self, tmp_path: Path) -> None:
        """--sign is the user overriding us; it must not be replaced by what we read."""
        game = tmp_path / "game"
        (game / "assets/src").mkdir(parents=True)
        (game / "assets/src/main.luac").write_bytes(
            b"ZZ" + xxtea_encrypt(LUAJIT_CHUNK, normalize_key(KEY)))
        out = tmp_path / "out"
        written = extract_offline([str(game)], None, write_lib(tmp_path), str(out),
                                  forced_sign=b"ZZ")
        assert written == 1
        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK


class TestStaleRegisters:
    def test_a_later_call_does_not_reuse_the_first_call_s_arguments(self, tmp_path: Path) -> None:
        """A call clobbers x0-x17, so a following call that sets up only x1 has no lengths or
        signature of its own. Without that rule the leftovers pair up into a bogus key."""
        decoy = b"notthekeyzzzzz"
        assert len(decoy) == len(KEY)  # same length, so a stale w2 would otherwise still "match"
        path = tmp_path / "libtwocalls.so"
        path.write_bytes(build(KEY, SIGN, decoy_strings=DECOYS, trailing_call_string=decoy))
        pairs = find_key_and_sign(str(path))
        assert {(p.key, p.sign) for p in pairs} == {(KEY, SIGN), (SIGN, KEY)}
        assert all(decoy not in (p.key, p.sign) for p in pairs)
