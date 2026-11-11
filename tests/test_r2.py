"""The radare2-backed paths, which only run when radare2 is actually installed.

These exist because the r2 code had never been exercised: with radare2 absent, Tier 0 silently
returns nothing and every one of these paths is skipped, so a defect in them looks exactly like a
missing dependency.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from .fixtures.mkelf import BASE, TEXT_OFF, build

pytestmark = pytest.mark.skipif(shutil.which("r2") is None, reason="radare2 is not installed")

KEY = b"cocos2d_lua_js"
SIGN = b"LJ"
TEXT = BASE + TEXT_OFF
APP_DELEGATE = "_ZN11AppDelegate29applicationDidFinishLaunchingEv"
LUA_BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxLuaJavaBridge_callLuaFunctionWithString"
JS_BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxJavascriptJavaBridge_evalString"


def engine_lib(tmp_path: Path, *, bridge: str = LUA_BRIDGE, stubs=("xxtea_decrypt",),
               name: str = "libcocos2dlua.so") -> str:
    path = tmp_path / name
    path.write_bytes(build(KEY, SIGN,
                           symbols={APP_DELEGATE: TEXT, bridge: TEXT} if bridge else {APP_DELEGATE: TEXT},
                           decoy_strings=(b"base/", b"0.0.0.0"),
                           stub_symbols=stubs))
    return str(path)


class TestTier0:
    """Tier 0 reads the literals referenced by applicationDidFinishLaunching."""

    def test_finds_the_key(self, tmp_path: Path) -> None:
        from coconuts.statickeys import extract_r2_priority_keys
        assert KEY.decode() in extract_r2_priority_keys(engine_lib(tmp_path))

    def test_does_not_collect_the_page_base(self, tmp_path: Path) -> None:
        """arm64 forms a string address as `adrp` (page) + `add` (offset). Only the adrp carries a
        `ptr`, and it points at the 4 KB page boundary -- following it alone reads whatever sits
        there, which for the first page is the ELF header."""
        from coconuts.statickeys import extract_r2_priority_keys
        for found in extract_r2_priority_keys(engine_lib(tmp_path)):
            assert "ELF" not in found
            assert "\\x" not in found  # `psz` escapes binary, which then looks printable

    def test_survives_a_library_with_no_such_function(self, tmp_path: Path) -> None:
        from coconuts.statickeys import extract_r2_priority_keys
        path = tmp_path / "libplain.so"
        path.write_bytes(build(KEY, SIGN, symbols={"unrelated": TEXT}))
        assert extract_r2_priority_keys(str(path)) == []

    def test_missing_file_is_not_fatal(self, tmp_path: Path) -> None:
        from coconuts.statickeys import extract_r2_priority_keys
        assert extract_r2_priority_keys(str(tmp_path / "nope.so")) == []


class TestOpenAndAnalyse:
    def test_identifies_a_lua_engine(self, tmp_path: Path) -> None:
        from coconuts.r2 import r2_open_and_analyse
        r2, symbol, _strings, symbols = r2_open_and_analyse(engine_lib(tmp_path),
                                                            run_heavy_analysis=False)
        try:
            assert symbol == LUA_BRIDGE
            assert len(symbols) >= 2
        finally:
            r2.quit()

    def test_identifies_a_js_engine(self, tmp_path: Path) -> None:
        from coconuts.r2 import r2_open_and_analyse
        r2, symbol, _s, _y = r2_open_and_analyse(engine_lib(tmp_path, bridge=JS_BRIDGE),
                                                 run_heavy_analysis=False)
        try:
            assert symbol == JS_BRIDGE
        finally:
            r2.quit()

    def test_rejects_a_library_that_is_not_a_cocos_engine(self, tmp_path: Path) -> None:
        from coconuts.r2 import r2_open_and_analyse
        with pytest.raises(RuntimeError, match="JavaBridge"):
            r2_open_and_analyse(engine_lib(tmp_path, bridge=""), run_heavy_analysis=False)


class TestResolveFridaTargets:
    def test_finds_xxtea_decrypt(self, tmp_path: Path) -> None:
        from coconuts.frida_dump import resolve_frida_targets
        symbol, dump_off, key_off, is_std_string = resolve_frida_targets(engine_lib(tmp_path))
        assert symbol == LUA_BRIDGE
        assert key_off is not None and not is_std_string
        assert dump_off is None  # no evalString in a Lua engine

    def test_offset_is_relative_to_the_library_base(self, tmp_path: Path) -> None:
        """The agent does base.add(KEY_OFFSET) at runtime, so this must be an offset into the
        image, not an absolute address. Android links shared objects at base vaddr 0, which is
        what makes the symbol's vaddr usable directly."""
        from coconuts.frida_dump import resolve_frida_targets
        _sym, _dump, key_off, _ = resolve_frida_targets(engine_lib(tmp_path))
        # xxtea_decrypt is the first stub, placed right after the main function.
        assert key_off == TEXT + 12 * 4 - BASE

    def test_finds_evalstring_in_a_js_engine(self, tmp_path: Path) -> None:
        from coconuts.frida_dump import resolve_frida_targets
        lib = engine_lib(tmp_path, bridge=JS_BRIDGE,
                         stubs=("_ZN7cocos2d12ScriptEngine10evalStringEPKcl", "xxtea_decrypt"),
                         name="libcocos2djs.so")
        _sym, dump_off, key_off, _ = resolve_frida_targets(lib)
        assert dump_off is not None
        assert key_off is not None and key_off != dump_off
