"""Offline extraction: output paths, the write helper, and end-to-end decryption."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from coconuts.extract import (
    FAILED,
    RAW_FALLBACK_DIR,
    SKIPPED,
    WRITTEN,
    LuaBytecodeReport,
    extract_offline,
    is_plain_script,
    lua_live_name,
    output_name,
    safe_join,
    split_plain_scripts,
    write_output,
)

from coconuts.ciphers import LUAJIT_DECOMPILER, UNLUAC

from .conftest import LUA_SOURCE, LUAJIT_CHUNK, PUC_CHUNK, encrypt_asset, write_asset_dir


class TestSafeJoin:
    def test_normal_path(self, tmp_path: Path) -> None:
        assert safe_join(str(tmp_path), "src/main.lua") == str(tmp_path / "src/main.lua")

    def test_leading_slash_is_treated_as_relative(self, tmp_path: Path) -> None:
        assert safe_join(str(tmp_path), "/src/main.lua") == str(tmp_path / "src/main.lua")

    def test_backslashes_are_normalised(self, tmp_path: Path) -> None:
        assert safe_join(str(tmp_path), "src\\main.lua") == str(tmp_path / "src/main.lua")

    @pytest.mark.parametrize("rel", ["../evil", "src/../../evil", "a/b/../../../evil"])
    def test_traversal_is_refused(self, tmp_path: Path, rel: str) -> None:
        with pytest.raises(ValueError):
            safe_join(str(tmp_path), rel)


class TestOutputName:
    @pytest.mark.parametrize("rel,kind,expected", [
        ("src/main.jsc", "raw", "src/main.js"),
        # The payload extension is appended to the decrypted name, not swapped for it.
        ("src/main.jsc", "zip", "src/main.js.zip"),
        ("src.zip", "zip", "src.zip"),  # already a .zip: not doubled
        ("src/main.jsc", "bytecode", "src/main.js.mozjs.jsc"),
        ("src/main.luac", "raw", "src/main.lua"),
        ("src/main.luac", "luabytecode", "src/main.luac"),
        ("src/main.lua", "luabytecode", "src/main.luac"),
        ("src/main.lua", "raw", "src/main.lua"),
    ])
    def test_extension(self, rel: str, kind: str, expected: str) -> None:
        assert output_name(rel, kind) == expected


class TestLuaLiveName:
    @pytest.mark.parametrize("chunk,body,expected", [
        ("@src/main.lua", LUA_SOURCE, "src/main.lua"),
        ("=src/main.lua", LUA_SOURCE, "src/main.lua"),
        ("@assets/src/main.lua", LUA_SOURCE, "src/main.lua"),
        ("app.MyApp", LUA_SOURCE, "app.MyApp.lua"),
        ("@src/main.lua", LUAJIT_CHUNK, "src/main.luac"),
        ("app.MyApp", LUAJIT_CHUNK, "app.MyApp.luac"),
        # The forms a real Cocos engine passes (verified on a device).
        ("assets/src/main.lua", LUA_SOURCE, "src/main.lua"),
        ("app.views.MainScene", LUA_SOURCE, "app.views.MainScene.lua"),
        # Hot updates: an absolute path in the app's writable directory.
        ("/data/user/0/com.example.game/files/src/hot.lua", LUA_SOURCE, "src/hot.lua"),
        ("/data/data/com.example.game/files/src/hot.lua", LUA_SOURCE, "src/hot.lua"),
        ("/data/user/0/com.example.game/files/assets/src/hot.lua", LUAJIT_CHUNK, "src/hot.luac"),
        ("/storage/emulated/0/Android/data/com.example.game/files/src/hot.lua", LUA_SOURCE, "src/hot.lua"),
        ("/data/user/10/com.example.game/cache/src/hot.lua", LUA_SOURCE, "src/hot.lua"),
        # Anything else absolute is left as it is (the writer treats it as relative).
        ("/opt/game/src/main.lua", LUA_SOURCE, "/opt/game/src/main.lua"),
    ])
    def test_name(self, chunk: str, body: bytes, expected: str) -> None:
        assert lua_live_name(chunk, body) == expected


class TestPlainScriptDetection:
    @pytest.mark.parametrize("rel,blob,plain", [
        ("src/a.luac", LUAJIT_CHUNK, True),
        ("src/a.luac", PUC_CHUNK, True),
        ("src/a.lua", LUA_SOURCE, True),
        ("src/a.luac", encrypt_asset(LUAJIT_CHUNK), False),
        ("src/a.jsc", LUA_SOURCE, False),   # .jsc is always encrypted
        ("src/a.jsc", encrypt_asset(LUA_SOURCE), False),
    ])
    def test_is_plain_script(self, rel: str, blob: bytes, plain: bool) -> None:
        assert is_plain_script(rel, blob) is plain

    def test_split(self) -> None:
        entries = {"a.luac": LUAJIT_CHUNK, "b.luac": encrypt_asset(LUAJIT_CHUNK)}
        encrypted, plain = split_plain_scripts(entries)
        assert set(encrypted) == {"b.luac"}
        assert set(plain) == {"a.luac"}


class TestWriteOutput:
    def test_writes_and_reports_bytecode(self, tmp_path: Path) -> None:
        report = LuaBytecodeReport()
        assert write_output(str(tmp_path), "src/main.luac", LUAJIT_CHUNK, report) == WRITTEN
        assert (tmp_path / "src/main.luac").read_bytes() == LUAJIT_CHUNK
        assert report._counts  # the chunk was identified

    def test_existing_file_is_kept(self, tmp_path: Path) -> None:
        write_output(str(tmp_path), "a.lua", b"first")
        assert write_output(str(tmp_path), "a.lua", b"second") == SKIPPED
        assert (tmp_path / "a.lua").read_bytes() == b"first"

    def test_escaping_path_is_refused(self, tmp_path: Path) -> None:
        assert write_output(str(tmp_path), "../evil", b"x") == FAILED
        assert not (tmp_path.parent / "evil").exists()

    def test_unwritable_target_is_reported_not_raised(self, tmp_path: Path) -> None:
        out = tmp_path / "out"
        out.mkdir()
        os.chmod(out, 0o500)
        try:
            assert write_output(str(out), "sub/a.lua", b"x") == FAILED
        finally:
            os.chmod(out, 0o700)


class TestLuaBytecodeReport:
    def test_groups_by_flavour(self, caplog: pytest.LogCaptureFixture) -> None:
        report = LuaBytecodeReport()
        for blob in (LUAJIT_CHUNK, LUAJIT_CHUNK, PUC_CHUNK, LUA_SOURCE):
            report.add(blob)
        with caplog.at_level("INFO"):
            report.log()
        text = caplog.text
        assert "2 compiled Lua chunk(s): LuaJIT 2.1 bytecode" in text
        assert "1 compiled Lua chunk(s): PUC Lua 5.1 bytecode" in text
        assert LUAJIT_DECOMPILER in text and UNLUAC in text

    def test_silent_when_nothing_compiled(self, caplog: pytest.LogCaptureFixture) -> None:
        report = LuaBytecodeReport()
        report.add(LUA_SOURCE)
        with caplog.at_level("INFO"):
            report.log()
        assert caplog.text == ""


class TestExtractOffline:
    @pytest.fixture(params=["dir", "apk"])
    def source(self, request: pytest.FixtureRequest, asset_dir: Path, apk: Path) -> str:
        return str(asset_dir if request.param == "dir" else apk)

    def test_decrypts_everything(self, source: str, tmp_path: Path, key: bytes) -> None:
        out = tmp_path / "out"
        written = extract_offline([source], key, None, str(out))
        assert written == 6  # four encrypted scripts + two shipped in the clear

        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "src/legacy.luac").read_bytes() == PUC_CHUNK
        assert (out / "src/config.lua").read_bytes() == LUA_SOURCE  # decrypted source keeps .lua
        assert (out / "src/app/MyApp.luac").exists()                # nested path preserved
        assert (out / "src/plain.luac").read_bytes() == PUC_CHUNK   # copied as-is
        assert (out / "src/plain.lua").read_bytes() == LUA_SOURCE
        assert not (out / "res/logo.png").exists()                  # not a script

    def test_reports_both_flavours(self, source: str, tmp_path: Path, key: bytes,
                                   caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("INFO"):
            extract_offline([source], key, None, str(tmp_path / "out"))
        assert ("LuaJIT 2.1 bytecode (64-bit (GC64), stripped) - decompile with "
                f"{LUAJIT_DECOMPILER}") in caplog.text
        assert "PUC Lua 5.1 bytecode (64-bit) - decompile with unluac" in caplog.text

    def test_live_dumps_win_over_offline(self, source: str, tmp_path: Path, key: bytes) -> None:
        out = tmp_path / "out"
        (out / "src").mkdir(parents=True)
        (out / "src/main.luac").write_bytes(b"from the live dump")
        extract_offline([source], key, None, str(out))
        assert (out / "src/main.luac").read_bytes() == b"from the live dump"

    def test_wrong_key_saves_raw_scripts(self, source: str, tmp_path: Path) -> None:
        from coconuts.ciphers import normalize_key
        out = tmp_path / "out"
        assert extract_offline([source], normalize_key(b"wrong"), None, str(out)) == 2  # plain ones
        raw = out / RAW_FALLBACK_DIR
        assert (raw / "src/main.luac").exists()
        assert not (out / "src/main.luac").exists()

    def test_no_scripts_found(self, tmp_path: Path, key: bytes) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        assert extract_offline([str(empty)], key, None, str(tmp_path / "out")) == 0


class TestXorLuaEndToEnd:
    """A Lua game whose scripts are repeating-key XOR: no engine library and no key given."""

    def test_recovers_the_key_and_decrypts(self, tmp_path: Path) -> None:
        from coconuts.ciphers import xor_decrypt

        fx = Path(__file__).parent / "fixtures" / "bytecode"
        plain = {"src/main.luac": (fx / "lua53.luac").read_bytes(),
                 "src/app/a.luac": (fx / "lua53_stripped.luac").read_bytes()}
        root = write_asset_dir(tmp_path / "game",
                               {rel: xor_decrypt(blob, b"xorkey") for rel, blob in plain.items()})

        out = tmp_path / "out"
        assert extract_offline([root], None, None, str(out)) == 2
        for rel, blob in plain.items():
            assert (out / rel).read_bytes() == blob
