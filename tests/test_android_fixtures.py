"""The real arm64 engine libraries in tests/fixtures/android.

These are not synthetic ELFs: each one is a libcocos2dlua.so built with the NDK from real Lua
5.1.5, Lua 5.3.6 or LuaJIT 2.1 sources plus a transcription of cocos2d-x's LuaStack, in the four
symbol shapes a shipped engine library can have. They were used to verify the Frida Lua loader
hook on a Pixel 7 (Android 14); see tests/fixtures/android/README.md.

What runs here is the static half: that the fixtures still have the symbol shape the device
matrix was established against, and that coconuts' own radare2 path copes with real libraries
rather than only with the hand-built ELFs in fixtures/mkelf.py.
"""

from __future__ import annotations

import shutil
import struct
from pathlib import Path

import pytest

from coconuts.arm64 import _Elf

FIXTURES = Path(__file__).parent / "fixtures" / "android"
RUNTIMES = ("lua51", "lua53", "luajit")
VARIANTS = ("default-unstripped", "default-stripped", "hidden-unstripped", "hidden-stripped")

# Which loader symbols each runtime's binary carries at all. Lua 5.2+ turns luaL_loadbuffer into
# a macro around luaL_loadbufferx, Lua 5.1 has no luaL_loadbufferx, and LuaJIT declares both.
LOADERS = {
    "lua51": {"luaL_loadbuffer"},
    "lua53": {"luaL_loadbufferx"},
    "luajit": {"luaL_loadbuffer", "luaL_loadbufferx"},
}
SHT_SYMTAB, SHT_DYNSYM = 2, 11
BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxLuaJavaBridge_retainLuaFunction"


def lib_path(runtime: str, variant: str) -> Path:
    return FIXTURES / runtime / variant / "libcocos2dlua.so"


def symbol_tables(path: Path) -> dict[str, set[str]]:
    """{'dynsym': {...}, 'symtab': {...}} -- a missing table comes back as an empty set."""
    elf = _Elf(path.read_bytes())
    assert elf.ok, f"{path} is not a 64-bit little-endian arm64 ELF"
    out: dict[str, set[str]] = {"dynsym": set(), "symtab": set()}
    for s in elf.sections:
        if s["type"] not in (SHT_SYMTAB, SHT_DYNSYM) or not s["entsize"]:
            continue
        kind = "symtab" if s["type"] == SHT_SYMTAB else "dynsym"
        strtab = elf.sections[s["link"]]
        for off in range(0, s["size"], s["entsize"]):
            (st_name,) = struct.unpack_from("<I", elf.data, s["off"] + off)
            if not st_name:
                continue
            base = strtab["off"] + st_name
            end = elf.data.find(b"\0", base)
            out[kind].add(elf.data[base:end].decode("utf-8", "replace"))
    return out


@pytest.mark.parametrize("runtime", RUNTIMES)
@pytest.mark.parametrize("variant", VARIANTS)
class TestFixtureShape:
    """The fixtures are only useful as long as they still have the shape they were built for."""

    def test_is_arm64_elf(self, runtime: str, variant: str) -> None:
        symbol_tables(lib_path(runtime, variant))  # asserts elf.ok

    def test_loader_symbols_are_where_the_variant_says(self, runtime: str, variant: str) -> None:
        tables = symbol_tables(lib_path(runtime, variant))
        want = LOADERS[runtime]
        exported = {n for n in tables["dynsym"] if n in want}
        local = {n for n in tables["symtab"] if n in want}

        if variant == "default-unstripped":
            assert exported == want and local == want
        elif variant == "default-stripped":
            # An export survives --strip-all: .dynsym is needed at runtime, .symtab is not.
            assert exported == want and not tables["symtab"]
        elif variant == "hidden-unstripped":
            # Hidden visibility keeps the symbol out of .dynsym but leaves it in .symtab, which
            # is the case the agent needs enumerateSymbols() for.
            assert not exported and local == want
        else:  # hidden-stripped
            assert not exported and not local, "nothing should be findable in this one"

    def test_the_jni_bridge_export_always_survives(self, runtime: str, variant: str) -> None:
        """Without it coconuts would not recognise the library as a Cocos engine lib at all."""
        assert BRIDGE in symbol_tables(lib_path(runtime, variant))["dynsym"]


@pytest.mark.skipif(shutil.which("r2") is None, reason="radare2 is not installed")
@pytest.mark.parametrize("runtime", RUNTIMES)
class TestStaticTrackOnRealLibraries:
    """r2.py against real compiler output, not fixtures/mkelf.py's hand-assembled ELFs."""

    def test_identifies_the_engine_library(self, runtime: str) -> None:
        from coconuts.r2 import r2_open_and_analyse

        r2, cocos_symbol, _strings, symbols = r2_open_and_analyse(
            str(lib_path(runtime, "default-unstripped")), run_heavy_analysis=False)
        try:
            assert cocos_symbol == BRIDGE
            assert any("luaL_loadbuffer" in s.get("name", "") for s in symbols)
        finally:
            r2.quit()

    def test_resolves_the_key_function_from_the_symbol_table(self, runtime: str) -> None:
        from coconuts.frida_dump import resolve_frida_targets

        cocos_symbol, dump_off, key_off, is_std_string, lua_load_off = resolve_frida_targets(
            str(lib_path(runtime, "default-unstripped")))
        assert cocos_symbol == BRIDGE
        assert key_off, "xxtea_decrypt is an export here, so it must resolve"
        assert not is_std_string
        # There is no ScriptEngine::evalString in a Lua lib: the agent resolves the Lua loader
        # itself, which is exactly why dump_off being None must not disable Lua dumping.
        assert dump_off is None
        assert lua_load_off, "luaL_loadbuffer is an export here, so it resolves on its own channel"

    def test_a_stripped_lua_library_still_identifies(self, runtime: str) -> None:
        """The JNI bridge is an export, so identification survives --strip-all."""
        from coconuts.r2 import r2_open_and_analyse

        r2, cocos_symbol, _strings, _symbols = r2_open_and_analyse(
            str(lib_path(runtime, "hidden-stripped")), run_heavy_analysis=False)
        try:
            assert cocos_symbol == BRIDGE
        finally:
            r2.quit()
