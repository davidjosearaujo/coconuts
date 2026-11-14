"""The radare2-backed paths, which only run when radare2 is actually installed.

These exist because the r2 code had never been exercised: with radare2 absent, Tier 0 silently
returns nothing and every one of these paths is skipped, so a defect in them looks exactly like a
missing dependency.
"""

from __future__ import annotations

import shutil
from contextlib import contextmanager
from pathlib import Path

import pytest

from coconuts.r2 import (
    DECRYPT_FAIL_NEEDLES,
    EVAL_STRING_NEEDLES,
    KEY_CALL_INDEX,
    LUA_LOAD_NEEDLES,
    find_key_function,
    find_lua_load_function,
    find_string_xref_function,
    r2_open_and_analyse,
)

from .fixtures.mkelf import BASE, TEXT_OFF, build, build_decrypt_fail, build_lua_load

pytestmark = pytest.mark.skipif(shutil.which("r2") is None, reason="radare2 is not installed")

KEY = b"cocos2d_lua_js"
SIGN = b"LJ"
TEXT = BASE + TEXT_OFF
APP_DELEGATE = "_ZN11AppDelegate29applicationDidFinishLaunchingEv"
LUA_BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxLuaJavaBridge_callLuaFunctionWithString"
JS_BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxJavascriptJavaBridge_evalString"
# The decrypt-failure fixtures put the key call at this index deliberately, rather than reading
# KEY_CALL_INDEX: building them from the value under test would move the goalposts with it, and
# the tests would pass whatever it was changed to.
KEY_CALL = 12


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
        symbol, dump_off, key_off, is_std_string, lua_off = resolve_frida_targets(
            engine_lib(tmp_path))
        assert symbol == LUA_BRIDGE
        assert key_off is not None and not is_std_string
        assert dump_off is None  # no evalString in a Lua engine
        assert lua_off is None   # nor a luaL_loadbuffer symbol in this fixture

    def test_offset_is_relative_to_the_library_base(self, tmp_path: Path) -> None:
        """The agent does base.add(KEY_OFFSET) at runtime, so this must be an offset into the
        image, not an absolute address. Android links shared objects at base vaddr 0, which is
        what makes the symbol's vaddr usable directly."""
        from coconuts.frida_dump import resolve_frida_targets
        _sym, _dump, key_off, _, _lua = resolve_frida_targets(engine_lib(tmp_path))
        # xxtea_decrypt is the first stub, placed right after the main function.
        assert key_off == TEXT + 12 * 4 - BASE

    def test_finds_evalstring_in_a_js_engine(self, tmp_path: Path) -> None:
        from coconuts.frida_dump import resolve_frida_targets
        lib = engine_lib(tmp_path, bridge=JS_BRIDGE,
                         stubs=("_ZN7cocos2d12ScriptEngine10evalStringEPKcl", "xxtea_decrypt"),
                         name="libcocos2djs.so")
        _sym, dump_off, key_off, _, _lua = resolve_frida_targets(lib)
        assert dump_off is not None
        assert key_off is not None and key_off != dump_off


# ---------------------------------------------------------------------------
# The heavy-analysis searches: locating a function by a string it references, and picking the
# call to xxtea_decrypt out of it. Both were previously untested, for want of a library with the
# needle strings and realistic call graphs; fixtures/mkelf.py assembles one now, which is also
# what makes the call order and the xref counts exact.
# ---------------------------------------------------------------------------


@contextmanager
def analysed(tmp_path: Path, name: str = "libcocos2djs.so", **kw):
    """Builds a decrypt-failure library, analyses it the way the tool does, and yields the
    handle, its strings and symbols, and the addresses the fixture was built with."""
    blob, layout = build_decrypt_fail(**kw)
    path = tmp_path / name
    path.write_bytes(blob)
    r2, _bridge, strings, symbols = r2_open_and_analyse(str(path), run_heavy_analysis=True)
    try:
        yield r2, strings, symbols, layout
    finally:
        r2.quit()


class TestAnalysisBounds:
    """Which of r2_open_and_analyse's two analysis paths runs depends on the division helper."""

    def test_bounded_when_the_division_helper_is_present(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            with analysed(tmp_path) as (r2, strings, _syms, layout):
                assert find_string_xref_function(r2, strings, DECRYPT_FAIL_NEEDLES) == layout["fail_fn"]
        assert "without limits" not in caplog.text

    def test_unbounded_and_warned_about_without_it(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            with analysed(tmp_path, with_jdiv=False) as (r2, strings, _syms, layout):
                assert find_string_xref_function(r2, strings, DECRYPT_FAIL_NEEDLES) == layout["fail_fn"]
        assert "No 'jdiv' symbol" in caplog.text


@contextmanager
def lua_analysed(tmp_path: Path, name: str = "libcocos2dlua.so", **kw):
    """Builds a Lua-load library, analyses it the way the tool does, and yields the handle, its
    strings and symbols, and the addresses the fixture was built with."""
    blob, layout = build_lua_load(**kw)
    path = tmp_path / name
    path.write_bytes(blob)
    r2, _bridge, strings, symbols = r2_open_and_analyse(str(path), run_heavy_analysis=True)
    try:
        yield r2, strings, symbols, layout
    finally:
        r2.quit()


class TestFindLuaLoadFunction:
    """A Lua lib has no evalString to anchor on, so the loader is found by the strings
    LuaStack::luaLoadBuffer logs and then by call count: the loader once, the logger per case.

    The fixtures carry no luaL_loadbuffer symbol unless a test asks for one -- a lib that still
    exports it never needs any of this.
    """

    def test_the_loader_is_the_target_called_exactly_once(self, tmp_path: Path) -> None:
        with lua_analysed(tmp_path) as (r2, strings, syms, layout):
            found = find_lua_load_function(r2, strings, syms)
        assert found == layout["loader"]
        assert found != layout["logger"], "the logger is the other call in there"

    @pytest.mark.parametrize("n_log", [2, 4, 7])
    def test_however_many_ways_the_load_can_fail(self, tmp_path: Path, n_log: int) -> None:
        """The count of log calls tracks the Cocos version's switch, so it must not be relied on
        beyond being more than one."""
        with lua_analysed(tmp_path, n_log=n_log) as (r2, strings, syms, layout):
            assert find_lua_load_function(r2, strings, syms) == layout["loader"]

    @pytest.mark.parametrize("needle", LUA_LOAD_NEEDLES)
    def test_every_needle_the_tool_ships_is_matched(self, tmp_path: Path, needle: str) -> None:
        """Each needle is a fragment of a real engine message, and each has to find the function
        on its own: the fixture carries only the one message."""
        message = needle.encode() + b" (chunk)"
        with lua_analysed(tmp_path, needle=message) as (r2, strings, syms, layout):
            assert find_lua_load_function(r2, strings, syms) == layout["loader"]

    def test_ambiguity_is_reported_rather_than_guessed(self, tmp_path: Path) -> None:
        """A second callee called once leaves nothing to tell the loader by, and a wrong guess
        attaches the dump handler to an unrelated function."""
        with lua_analysed(tmp_path, extra_once=1) as (r2, strings, syms, _layout):
            with pytest.raises(RuntimeError, match="Cannot tell the loader from the logger"):
                find_lua_load_function(r2, strings, syms)

    def test_a_loader_called_twice_is_not_picked_over_the_logger(self, tmp_path: Path) -> None:
        """An unoptimised build calls the loader from both branches of the xxtea check. Then no
        target is unique and the search declines rather than hooking the logger."""
        with lua_analysed(tmp_path, n_loader=2) as (r2, strings, syms, _layout):
            with pytest.raises(RuntimeError, match="Cannot tell the loader"):
                find_lua_load_function(r2, strings, syms)

    def test_a_plt_stub_resolves_to_the_real_symbol(self, tmp_path: Path) -> None:
        with lua_analysed(tmp_path, loader_via_plt=True,
                          with_loader_symbol=True) as (r2, strings, syms, layout):
            assert find_lua_load_function(r2, strings, syms) == layout["loader_real"]

    def test_a_plt_stub_with_nothing_behind_it_hooks_the_stub(
            self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            with lua_analysed(tmp_path, loader_via_plt=True,
                              with_loader_symbol=False) as (r2, strings, syms, layout):
                assert find_lua_load_function(r2, strings, syms) == layout["loader"]
        assert "PLT stub" in caplog.text

    def test_a_library_with_no_lua_message_is_reported(self, tmp_path: Path) -> None:
        with lua_analysed(tmp_path, needle=b"nothing to do with loading") as (r2, s, syms, _l):
            with pytest.raises(RuntimeError, match="String not found"):
                find_lua_load_function(r2, s, syms)


class TestFindStringXrefFunction:
    def test_finds_the_function_that_references_the_string(self, tmp_path: Path) -> None:
        with analysed(tmp_path) as (r2, strings, _syms, layout):
            assert find_string_xref_function(r2, strings, DECRYPT_FAIL_NEEDLES) == layout["fail_fn"]

    @pytest.mark.parametrize("needle", DECRYPT_FAIL_NEEDLES + EVAL_STRING_NEEDLES)
    def test_every_needle_the_tool_ships_is_matched(self, tmp_path: Path, needle: str) -> None:
        """Each needle is a substring of a real engine message, so the fixture carries the
        message and the search has to find it from the fragment."""
        message = f"[LUA ERROR] {needle} -- extra text".encode()
        with analysed(tmp_path, needle=message) as (r2, strings, _syms, layout):
            assert find_string_xref_function(r2, strings, [needle]) == layout["fail_fn"]

    def test_decoy_strings_are_not_matched(self, tmp_path: Path) -> None:
        decoys = (b"res/raw/", b"assets/src/main.lua", b"Can't open file for %s")
        with analysed(tmp_path, decoy_strings=decoys) as (r2, strings, _syms, layout):
            assert find_string_xref_function(r2, strings, DECRYPT_FAIL_NEEDLES) == layout["fail_fn"]

    def test_a_missing_string_is_reported(self, tmp_path: Path) -> None:
        with analysed(tmp_path, needle=b"nothing to do with decryption") as (r2, strings, _s, _l):
            with pytest.raises(RuntimeError, match="String not found"):
                find_string_xref_function(r2, strings, DECRYPT_FAIL_NEEDLES)

    def test_a_string_nobody_references_is_reported(self, tmp_path: Path) -> None:
        """The string is in .rodata as a decoy, so it is found but has no xref to follow."""
        with analysed(tmp_path, needle=b"unreferenced",
                      decoy_strings=(b"Can't decrypt code for %s",)) as (r2, strings, _s, _l):
            with pytest.raises(RuntimeError, match="No function references"):
                find_string_xref_function(r2, strings, DECRYPT_FAIL_NEEDLES)


def test_the_key_call_index_is_the_one_the_fixtures_assume() -> None:
    """A change here is a change to an empirical rule: revisit the fixtures below with it."""
    assert KEY_CALL_INDEX == KEY_CALL


class TestFindKeyFunction:
    def test_picks_the_call_at_the_expected_index(self, tmp_path: Path) -> None:
        """The empirical rule: the 13th `bl` is the call to xxtea_decrypt. The fixture is built
        that way, so this pins the mechanism, not whether the index is right for real games."""
        with analysed(tmp_path, key_call_index=KEY_CALL,
                      extra_callers={KEY_CALL: 1}) as (r2, strings, syms, layout):
            assert find_key_function(r2, strings, syms) == layout["callees"][KEY_CALL]

    def test_the_index_wins_over_an_earlier_two_xref_call(self, tmp_path: Path) -> None:
        """The xref count is a tie-breaker for when the index misses, not a replacement for it:
        with both the indexed call and an earlier one referenced twice, the index still decides."""
        with analysed(tmp_path, key_call_index=KEY_CALL,
                      extra_callers={3: 1, KEY_CALL: 1}) as (r2, strings, syms, layout):
            assert find_key_function(r2, strings, syms) == layout["callees"][KEY_CALL]

    def test_a_short_function_falls_back_to_its_last_call(self, tmp_path: Path) -> None:
        """Fewer calls than the index: the last one is taken. No callee here is referenced twice,
        so the xref tie-breaker stays out of it and the choice of call is what is being checked."""
        with analysed(tmp_path, n_calls=5, key_call_index=4) as (r2, strings, syms, layout):
            assert find_key_function(r2, strings, syms) == layout["callees"][4]

    def test_the_two_xref_rule_applies_when_the_index_misses(self, tmp_path: Path) -> None:
        """When the call at the index isn't referenced twice, the first earlier call that is wins.
        Here that picks call 3 over the real key call at 12 -- the rule working as written, and a
        reminder that it can be led astray."""
        with analysed(tmp_path, key_call_index=KEY_CALL,
                      extra_callers={3: 1}) as (r2, strings, syms, layout):
            assert find_key_function(r2, strings, syms) == layout["callees"][3]

    def test_a_plt_stub_is_resolved_through_the_symbol_table(self, tmp_path: Path) -> None:
        """The call lands on a stub that jumps through x16; the address worth hooking is the real
        xxtea_decrypt the stub reaches, which only the symbol table can give."""
        with analysed(tmp_path, key_via_plt=True, key_call_index=KEY_CALL,
                      extra_callers={KEY_CALL: 1}) as (r2, strings, syms, layout):
            assert layout["key_target"] != layout["key_real"]
            assert find_key_function(r2, strings, syms) == layout["key_real"]

    def test_a_plt_stub_with_no_symbol_keeps_the_stub(self, tmp_path: Path) -> None:
        with analysed(tmp_path, key_via_plt=True, with_key_symbol=False, key_call_index=KEY_CALL,
                      extra_callers={KEY_CALL: 1}) as (r2, strings, syms, layout):
            assert find_key_function(r2, strings, syms) == layout["key_target"]

    def test_a_function_with_no_calls_is_reported(self, tmp_path: Path) -> None:
        with analysed(tmp_path, n_calls=0, key_call_index=-1) as (r2, strings, syms, _layout):
            with pytest.raises(RuntimeError, match="No `bl` calls"):
                find_key_function(r2, strings, syms)
