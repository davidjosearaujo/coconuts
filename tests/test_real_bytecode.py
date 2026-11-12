"""Checks the header parser against genuine bytecode rather than headers written by hand.

tests/fixtures/bytecode/ holds one compiled chunk per Lua runtime, stripped and not, produced by
gen_bytecode.py from lupa's bundled interpreters. Hand-built headers only prove the parser agrees
with whoever wrote the test; these prove it agrees with the compilers.

The real decompilers aren't installed by the test suite, so the tests that drive them run only when
$UNLUAC_JAR / $LUAJIT_DECOMPILER point at one.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from coconuts.ciphers import LUAJIT_DECOMPILER, UNLUAC, describe_lua_bytecode
from coconuts.decompile import decompile_dir

BYTECODE = Path(__file__).parent / "fixtures" / "bytecode"

# What each fixture is, as its own compiler wrote it. The PUC 5.1-5.3 files say 64-bit because
# their header records sizeof(size_t) from the host that generated them; 5.4 and 5.5 dropped it.
# No lua51_stripped / lua52_stripped: string.dump ignores its strip argument before 5.3, so those
# would be byte-for-byte copies of the unstripped fixtures. Stripped PUC bytecode is covered by
# 5.3 upwards.
EXPECTED = {
    "lua51.luac": ("PUC Lua 5.1 bytecode (64-bit)", UNLUAC),
    "lua52.luac": ("PUC Lua 5.2 bytecode (64-bit)", UNLUAC),
    "lua53.luac": ("PUC Lua 5.3 bytecode (64-bit)", UNLUAC),
    "lua53_stripped.luac": ("PUC Lua 5.3 bytecode (64-bit)", UNLUAC),
    "lua54.luac": ("PUC Lua 5.4 bytecode", UNLUAC),
    "lua54_stripped.luac": ("PUC Lua 5.4 bytecode", UNLUAC),
    "lua55.luac": ("PUC Lua 5.5 bytecode", UNLUAC),
    "lua55_stripped.luac": ("PUC Lua 5.5 bytecode", UNLUAC),
    "luajit20.luac": ("LuaJIT 2.0 bytecode", LUAJIT_DECOMPILER),
    "luajit20_stripped.luac": ("LuaJIT 2.0 bytecode (stripped)", LUAJIT_DECOMPILER),
    "luajit21.luac": ("LuaJIT 2.1 bytecode (64-bit (GC64))", LUAJIT_DECOMPILER),
    "luajit21_stripped.luac": ("LuaJIT 2.1 bytecode (64-bit (GC64), stripped)", LUAJIT_DECOMPILER),
}


def test_every_fixture_is_covered() -> None:
    assert {p.name for p in BYTECODE.glob("*.luac")} == set(EXPECTED)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_identifies_real_bytecode(name: str) -> None:
    got = describe_lua_bytecode((BYTECODE / name).read_bytes())
    assert got is not None, f"{name} was not recognised as bytecode at all"
    assert (got.label, got.tool) == EXPECTED[name]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_header_is_enough(name: str) -> None:
    """Identification reads only the first bytes, so a truncated read gives the same answer."""
    blob = (BYTECODE / name).read_bytes()
    assert describe_lua_bytecode(blob[:16]) == describe_lua_bytecode(blob)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_stripped_flag_matches_how_it_was_built(name: str) -> None:
    """LuaJIT records stripping in its header; PUC doesn't, so it is never claimed for PUC."""
    label = describe_lua_bytecode((BYTECODE / name).read_bytes()).label
    if name.startswith("luajit"):
        assert ("stripped" in label) == name.endswith("_stripped.luac")
    else:
        assert "stripped" not in label


class TestRealDecompilers:
    """Opt-in: these run the actual decompilers, which the suite never installs."""

    @pytest.fixture
    def dump(self, tmp_path: Path) -> Path:
        out = tmp_path / "out"
        (out / "src").mkdir(parents=True)
        for src in BYTECODE.glob("*.luac"):
            shutil.copy(src, out / "src" / src.name)
        return out

    def test_unluac(self, dump: Path, caplog: pytest.LogCaptureFixture) -> None:
        jar = os.environ.get("UNLUAC_JAR")
        if not jar:
            pytest.skip("set UNLUAC_JAR to run the real unluac")
        with caplog.at_level("INFO"):
            decompile_dir(str(dump), unluac=jar)

        # This unluac handles 5.0-5.3; 5.4 and 5.5 are expected to be refused.
        for stem in ("lua51", "lua52", "lua53"):
            out = dump / f"src/{stem}.dec.lua"
            assert out.exists(), f"{stem} did not decompile"
            assert "function" in out.read_text() and "return" in out.read_text()
        assert "local s = a + b" in (dump / "src/lua51.dec.lua").read_text()

        for stem in ("lua54", "lua55"):
            assert not (dump / f"src/{stem}.dec.lua").exists()
        # The refusal must reach the user as the decompiler's own sentence, not a stack frame.
        assert "unluac can only handle" in caplog.text
        assert "at unluac.Main" not in caplog.text

    def test_unluac_recovers_names_only_when_not_stripped(self, dump: Path) -> None:
        jar = os.environ.get("UNLUAC_JAR")
        if not jar:
            pytest.skip("set UNLUAC_JAR to run the real unluac")
        decompile_dir(str(dump), unluac=jar)
        assert "local s = a + b" in (dump / "src/lua53.dec.lua").read_text()
        stripped = (dump / "src/lua53_stripped.dec.lua").read_text()
        assert "local s" not in stripped      # names are gone
        assert "return" in stripped           # but the structure survives

    def test_luajit_decompiler(self, dump: Path) -> None:
        ljd = os.environ.get("LUAJIT_DECOMPILER")
        if not ljd:
            pytest.skip("set LUAJIT_DECOMPILER to run a real LuaJIT decompiler")
        decompile_dir(str(dump), ljd=ljd)
        for stem in ("luajit20", "luajit21", "luajit21_stripped"):
            out = dump / f"src/{stem}.dec.lua"
            assert out.exists(), f"{stem} did not decompile"
            assert "function" in out.read_text()
        # Unstripped bytecode carries the names; stripped doesn't, and no decompiler invents them.
        assert "a + b" in (dump / "src/luajit21.dec.lua").read_text()
        assert "a + b" not in (dump / "src/luajit21_stripped.dec.lua").read_text()

    def test_puc_and_luajit_are_routed_separately(self, dump: Path) -> None:
        """One run over a folder holding both formats: each chunk goes to the tool that reads it,
        and neither tool is handed a file it would reject."""
        jar, ljd = os.environ.get("UNLUAC_JAR"), os.environ.get("LUAJIT_DECOMPILER")
        if not (jar and ljd):
            pytest.skip("set both UNLUAC_JAR and LUAJIT_DECOMPILER")
        decompile_dir(str(dump), unluac=jar, ljd=ljd)
        assert (dump / "src/lua51.dec.lua").exists()      # PUC -> unluac
        assert (dump / "src/luajit21.dec.lua").exists()   # LuaJIT -> ljd
