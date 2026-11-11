"""The --decompile pass, driven with stand-in decompilers.

unluac and luajit-decompiler-v2 can't be installed from PyPI, so the real ones aren't assumed to be
present. These fakes stand in for the two output conventions the pass has to cope with: a tool that
prints to stdout, and one that writes a file of its own.
"""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from coconuts import decompile as dec
from coconuts.ciphers import LUAJIT_DECOMPILER, UNLUAC

from .conftest import LUA_SOURCE, LUAJIT_CHUNK, PUC_CHUNK

DECOMPILED = "-- decompiled\nlocal M = {}\nreturn M\n"


def _script(tmp_path: Path, name: str, body: str) -> str:
    """Writes a fake decompiler; .py so _as_tool runs it with the current interpreter."""
    path = tmp_path / f"{name}.py"
    path.write_text("import sys, os\n" + textwrap.dedent(body), encoding="utf-8")
    return str(path)


@pytest.fixture
def to_stdout(tmp_path: Path) -> str:
    return _script(tmp_path, "stdout_tool", f"""
        sys.stdout.write({DECOMPILED!r})
    """)


@pytest.fixture
def to_file(tmp_path: Path) -> str:
    """Writes into ./output under its own directory, as some decompilers do, and prints nothing."""
    return _script(tmp_path, "file_tool", f"""
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')
        os.makedirs(out, exist_ok=True)
        name = os.path.basename(sys.argv[1]).replace('.luac', '.lua')
        open(os.path.join(out, name), 'w').write({DECOMPILED!r})
    """)


@pytest.fixture
def failing(tmp_path: Path) -> str:
    return _script(tmp_path, "failing_tool", """
        sys.stderr.write('java.lang.RuntimeException: unhandled opcode 0x4f\\n')
        sys.exit(1)
    """)


@pytest.fixture
def silent(tmp_path: Path) -> str:
    return _script(tmp_path, "silent_tool", """
        sys.exit(0)
    """)


@pytest.fixture
def dumped(tmp_path: Path) -> Path:
    """An output folder as a dump leaves it: both bytecode flavours, source, and a non-script."""
    out = tmp_path / "out"
    (out / "src").mkdir(parents=True)
    (out / "src/main.luac").write_bytes(LUAJIT_CHUNK)
    (out / "src/app.luac").write_bytes(LUAJIT_CHUNK + b"\x01")
    (out / "src/legacy.luac").write_bytes(PUC_CHUNK)
    (out / "src/config.lua").write_bytes(LUA_SOURCE)
    (out / "res.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    return out


class TestToolResolution:
    def test_explicit_python_script(self, to_stdout: str) -> None:
        tool = dec._as_tool("fake", Path(to_stdout))
        assert tool is not None and tool.argv[1] == to_stdout

    def test_directory_resolves_to_main_py(self, tmp_path: Path) -> None:
        home = tmp_path / "luajit-decompiler-v2"
        home.mkdir()
        (home / "main.py").write_text("", encoding="utf-8")
        tool = dec._as_tool("fake", home)
        assert tool is not None and tool.argv[1].endswith("main.py")

    @pytest.mark.parametrize("entry", ["bin/unluac.jar", "luajit-decompiler-v2", "ljd"])
    def test_directory_resolves_a_built_entry_point(self, tmp_path: Path, entry: str,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
        """unluac builds to bin/unluac.jar; luajit-decompiler-v2 is C++ and builds to a binary."""
        monkeypatch.setattr(dec.shutil, "which", lambda _: "/usr/bin/java")
        home = tmp_path / "checkout"
        (home / Path(entry).parent).mkdir(parents=True, exist_ok=True)
        (home / entry).write_text("", encoding="utf-8")
        tool = dec._as_tool("fake", home)
        assert tool is not None and tool.argv[-1].endswith(Path(entry).name)

    def test_windows_exe_goes_through_wine(self, tmp_path: Path,
                                           monkeypatch: pytest.MonkeyPatch) -> None:
        exe = tmp_path / "luajit-decompiler-v2.exe"
        exe.write_bytes(b"MZ")
        monkeypatch.setattr(dec.os, "name", "posix")
        monkeypatch.setattr(dec.shutil, "which", lambda n: "/usr/bin/wine" if n == "wine" else None)
        tool = dec._as_tool("ljd", exe)
        assert tool is not None and tool.argv == ("/usr/bin/wine", str(exe))

    def test_windows_exe_without_wine(self, tmp_path: Path,
                                      monkeypatch: pytest.MonkeyPatch) -> None:
        exe = tmp_path / "luajit-decompiler-v2.exe"
        exe.write_bytes(b"MZ")
        monkeypatch.setattr(dec.os, "name", "posix")
        monkeypatch.setattr(dec.shutil, "which", lambda _: None)
        assert dec._as_tool("ljd", exe) is None


class TestErrorLine:
    def test_java_stack_trace_keeps_the_message(self) -> None:
        trace = ('Exception in thread "main" java.lang.IllegalStateException: '
                 "The input chunk's Lua version is 5.4; unluac can only handle Lua 5.0 - Lua 5.3.\n"
                 "\tat unluac.parse.BHeader.<init>(BHeader.java:63)\n"
                 "\tat unluac.Main.main(Main.java:42)\n")
        assert "unluac can only handle" in dec._error_line(trace)
        assert "at unluac.Main" not in dec._error_line(trace)

    def test_python_traceback_keeps_the_message(self) -> None:
        trace = ("Traceback (most recent call last):\n"
                 '  File "main.py", line 3, in <module>\n'
                 "    raise ValueError('bad prototype')\n"
                 "ValueError: bad prototype\n")
        assert dec._error_line(trace) == "ValueError: bad prototype"

    def test_plain_message(self) -> None:
        assert dec._error_line("could not open input\n") == "could not open input"

    def test_only_indented_output(self) -> None:
        assert dec._error_line("    indented only\n") == "indented only"

    def test_empty(self) -> None:
        assert dec._error_line("") == ""

    def test_long_message_is_truncated(self) -> None:
        assert dec._error_line("x" * 500).endswith("...")
        assert len(dec._error_line("x" * 500)) <= 203

    def test_directory_without_an_entry_point(self, tmp_path: Path) -> None:
        empty = tmp_path / "nothing"
        empty.mkdir()
        assert dec._as_tool("fake", empty) is None

    def test_missing_path(self, tmp_path: Path) -> None:
        assert dec._as_tool("fake", tmp_path / "nope.jar") is None

    def test_jar_without_java(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        jar = tmp_path / "unluac.jar"
        jar.write_bytes(b"PK\x03\x04")
        monkeypatch.setattr(dec.shutil, "which", lambda _: None)
        assert dec._as_tool("unluac", jar) is None

    def test_jar_with_java(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        jar = tmp_path / "unluac.jar"
        jar.write_bytes(b"PK\x03\x04")
        monkeypatch.setattr(dec.shutil, "which", lambda _: "/usr/bin/java")
        tool = dec._as_tool("unluac", jar)
        assert tool is not None and tool.argv == ("/usr/bin/java", "-jar", str(jar))

    def test_environment_variable_is_honoured(self, to_stdout: str,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("UNLUAC_JAR", to_stdout)
        assert UNLUAC in dec.resolve_tools()

    def test_explicit_beats_environment(self, to_stdout: str, failing: str,
                                        monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("UNLUAC_JAR", failing)
        tools = dec.resolve_tools(unluac=to_stdout)
        assert tools[UNLUAC].argv[1] == to_stdout

    def test_nothing_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("UNLUAC_JAR", raising=False)
        monkeypatch.delenv("LUAJIT_DECOMPILER", raising=False)
        monkeypatch.setattr(dec.shutil, "which", lambda _: None)
        assert dec.resolve_tools() == {}


class TestChunkDiscovery:
    def test_finds_only_compiled_chunks(self, dumped: Path) -> None:
        found = dict((p.name, tool) for p, tool in dec._compiled_chunks(dumped))
        assert found == {
            "main.luac": LUAJIT_DECOMPILER,
            "app.luac": LUAJIT_DECOMPILER,
            "legacy.luac": UNLUAC,
        }

    def test_skips_its_own_output(self, dumped: Path) -> None:
        (dumped / "src/old.dec.lua").write_bytes(PUC_CHUNK)  # even if it somehow holds bytecode
        assert all(not p.name.endswith(dec.DEC_SUFFIX) for p, _ in dec._compiled_chunks(dumped))

    def test_unreadable_file_is_skipped(self, dumped: Path) -> None:
        bad = dumped / "src/locked.luac"
        bad.write_bytes(LUAJIT_CHUNK)
        os.chmod(bad, 0o000)
        try:
            names = [p.name for p, _ in dec._compiled_chunks(dumped)]
        finally:
            os.chmod(bad, 0o600)
        assert "locked.luac" not in names


class TestDecompileDir:
    def test_routes_each_flavour_to_its_tool(self, dumped: Path, to_stdout: str,
                                             to_file: str) -> None:
        dec.decompile_dir(str(dumped), unluac=to_stdout, ljd=to_file)
        assert (dumped / "src/legacy.dec.lua").read_text() == DECOMPILED   # PUC -> unluac
        assert (dumped / "src/main.dec.lua").read_text() == DECOMPILED     # LuaJIT -> ljd
        assert (dumped / "src/app.dec.lua").read_text() == DECOMPILED

    def test_bytecode_is_kept(self, dumped: Path, to_stdout: str, to_file: str) -> None:
        dec.decompile_dir(str(dumped), unluac=to_stdout, ljd=to_file)
        assert (dumped / "src/main.luac").read_bytes() == LUAJIT_CHUNK
        assert (dumped / "src/legacy.luac").read_bytes() == PUC_CHUNK

    def test_decrypted_source_is_untouched(self, dumped: Path, to_stdout: str, to_file: str) -> None:
        dec.decompile_dir(str(dumped), unluac=to_stdout, ljd=to_file)
        assert (dumped / "src/config.lua").read_bytes() == LUA_SOURCE

    def test_is_idempotent(self, dumped: Path, to_stdout: str, to_file: str) -> None:
        dec.decompile_dir(str(dumped), unluac=to_stdout, ljd=to_file)
        before = sorted(p.name for p in (dumped / "src").iterdir())
        dec.decompile_dir(str(dumped), unluac=to_stdout, ljd=to_file)
        assert sorted(p.name for p in (dumped / "src").iterdir()) == before

    def test_missing_tool_warns_and_does_the_rest(self, dumped: Path, to_stdout: str,
                                                  monkeypatch: pytest.MonkeyPatch,
                                                  caplog: pytest.LogCaptureFixture) -> None:
        monkeypatch.delenv("LUAJIT_DECOMPILER", raising=False)
        monkeypatch.setattr(dec.shutil, "which", lambda n: None)
        with caplog.at_level("INFO"):
            dec.decompile_dir(str(dumped), unluac=to_stdout)
        assert "2 chunk(s) need luajit-decompiler-v2" in caplog.text
        assert "--ljd" in caplog.text                          # says how to point at it
        assert (dumped / "src/legacy.dec.lua").exists()        # the PUC chunk still ran
        assert not (dumped / "src/main.dec.lua").exists()

    def test_failure_is_reported_not_raised(self, dumped: Path, failing: str,
                                            caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("INFO"):
            dec.decompile_dir(str(dumped), unluac=failing, ljd=failing)
        assert "unhandled opcode" in caplog.text               # the decompiler's own message
        assert "3 chunk(s) could not be decompiled" in caplog.text
        assert (dumped / "src/main.luac").exists()
        assert not (dumped / "src/main.dec.lua").exists()

    def test_concurrent_file_output_is_not_mixed_up(self, dumped: Path, tmp_path: Path) -> None:
        """A file-producing decompiler writes every chunk into one folder of its own. Picking the
        newest .lua there would hand a chunk a sibling's source, and the fakes above all emit the
        same text, so this one makes each output identify its input.

        This catches the timestamp heuristic only some of the time -- it is a race, so it is a
        probabilistic guard. test_output_under_an_unexpected_name_fails_loudly is the deterministic
        one; keep both.
        """
        tool = _script(tmp_path, "per_input_tool", """
            out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')
            os.makedirs(out, exist_ok=True)
            stem = os.path.basename(sys.argv[1]).rsplit('.', 1)[0]
            import time, random
            time.sleep(random.random() / 20)   # let the writes interleave
            open(os.path.join(out, stem + '.lua'), 'w').write('-- source of ' + stem + '\\n')
        """)
        dec.decompile_dir(str(dumped), unluac=tool, ljd=tool)
        for stem in ("main", "app", "legacy"):
            assert (dumped / f"src/{stem}{dec.DEC_SUFFIX}").read_text() == f"-- source of {stem}\n"

    def test_output_under_an_unexpected_name_fails_loudly(self, dumped: Path, tmp_path: Path,
                                                          caplog: pytest.LogCaptureFixture) -> None:
        tool = _script(tmp_path, "odd_name_tool", f"""
            out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')
            os.makedirs(out, exist_ok=True)
            open(os.path.join(out, 'something-else.lua'), 'w').write({DECOMPILED!r})
        """)
        with caplog.at_level("INFO"):
            dec.decompile_dir(str(dumped), unluac=tool, ljd=tool)
        assert "expected main.lua" in caplog.text
        assert not (dumped / "src/main.dec.lua").exists()  # never a file with the wrong contents

    def test_decrypted_source_is_never_mistaken_for_output(self, dumped: Path,
                                                           caplog: pytest.LogCaptureFixture) -> None:
        """A decompiler installed inside (or above) the dump folder must not let a decrypted
        main.lua be picked up as if the tool had produced it."""
        tool = _script(dumped, "silent_tool", "sys.exit(0)")   # lives in the dump folder
        (dumped / "src/main.lua").write_bytes(b"-- the decrypted source, not decompiler output\n")
        with caplog.at_level("INFO"):
            dec.decompile_dir(str(dumped), unluac=tool, ljd=tool)
        assert not (dumped / "src/main.dec.lua").exists()
        assert "expected main.lua" in caplog.text
        assert (dumped / "src/main.lua").read_bytes().startswith(b"-- the decrypted source")

    def test_tool_that_produces_nothing(self, dumped: Path, silent: str,
                                        caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("INFO"):
            dec.decompile_dir(str(dumped), unluac=silent, ljd=silent)
        assert "produced no output" in caplog.text

    def test_timeout(self, dumped: Path, tmp_path: Path,
                     monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
        hang = _script(tmp_path, "hanging_tool", "import time; time.sleep(30)")
        monkeypatch.setattr(dec, "PER_FILE_TIMEOUT", 0.5)
        with caplog.at_level("INFO"):
            dec.decompile_dir(str(dumped), unluac=hang, ljd=hang)
        assert "timed out" in caplog.text

    def test_nothing_to_do(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        (empty / "a.lua").write_bytes(LUA_SOURCE)
        with caplog.at_level("INFO"):
            dec.decompile_dir(str(empty))
        assert "No compiled Lua chunks" in caplog.text

    def test_warns_that_output_can_be_wrong(self, dumped: Path, to_stdout: str,
                                            caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("INFO"):
            dec.decompile_dir(str(dumped), unluac=to_stdout, ljd=to_stdout)
        assert "plausible nonsense" in caplog.text


class TestCli:
    def test_decompile_only_mode(self, dumped: Path, to_stdout: str) -> None:
        from coconuts.__main__ import main
        assert main(["--decompile", "-o", str(dumped), "--unluac", to_stdout,
                     "--ljd", to_stdout]) == 0
        assert (dumped / "src/main.dec.lua").exists()

    def test_decompile_only_on_a_missing_folder(self, tmp_path: Path,
                                                caplog: pytest.LogCaptureFixture) -> None:
        from coconuts.__main__ import main
        with caplog.at_level("ERROR"):
            assert main(["--decompile", "-o", str(tmp_path / "nope")]) == 1
        assert "doesn't exist" in caplog.text

    def test_runs_after_a_dump(self, asset_dir: Path, tmp_path: Path, to_stdout: str) -> None:
        from coconuts.__main__ import main
        out = tmp_path / "out"
        assert main(["--apk", str(asset_dir), "--key", "thekey", "-o", str(out),
                     "--decompile", "--unluac", to_stdout, "--ljd", to_stdout]) == 0
        assert (out / "src/main.dec.lua").read_text() == DECOMPILED
        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK
