"""Post-dump pass (--decompile): run a Lua decompiler over the compiled chunks in the output.

Unlike --pretty, the decompilers can't be bundled: unluac is a Java jar and luajit-decompiler-v2 is
a GitHub project, neither on PyPI. So they're discovered on PATH, taken from an environment
variable, or pointed at with --unluac / --ljd, and the pass reports what's missing instead of
failing. Each chunk is routed by its own header, so a game mixing PUC and LuaJIT chunks is fine.

Decompiled source is written beside the bytecode as <name>.dec.lua. It never replaces the .luac:
decompilation is lossy, and on a game that ships a patched LuaJIT it can produce plausible-looking
nonsense with a zero exit code, which nothing here can detect.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from .ciphers import LUAJIT_DECOMPILER, UNLUAC, describe_lua_bytecode
from .log import SUCCESS, log

DEC_SUFFIX = ".dec.lua"
PER_FILE_TIMEOUT = 120.0  # a decompiler can hang on a malformed or hostile chunk


@dataclass(frozen=True)
class Tool:
    """A resolved decompiler: the argv prefix to run, with the input path appended."""

    name: str
    argv: tuple[str, ...]
    home: Path | None = None  # where it may drop output files of its own


# What a checkout of one of these looks like once it's built. unluac compiles to a jar;
# luajit-decompiler-v2 is C++ and produces a binary whose name is up to whoever built it, so a
# built binary sitting at the top of the checkout is accepted under either project's name.
_ENTRY_POINTS = (
    "unluac.jar", "bin/unluac.jar", "build/unluac.jar",
    "luajit-decompiler-v2.exe", "luajit-decompiler-v2", "ljd.exe", "ljd",
    "main.py",
)


def _as_tool(name: str, path: Path) -> Tool | None:
    """Builds the command for a decompiler given the file or checkout it was pointed at."""
    if path.is_dir():
        for candidate in _ENTRY_POINTS:
            if (path / candidate).is_file():
                path = path / candidate
                break
        else:
            log.warning("%s: nothing runnable in %s (looked for %s). If it's built under another "
                        "name, point at the file itself.", name, path, ", ".join(_ENTRY_POINTS[:4]))
            return None
    if not path.is_file():
        log.warning("%s: %s doesn't exist", name, path)
        return None

    if path.suffix == ".jar":
        java = shutil.which("java")
        if java is None:
            log.warning("%s: %s needs a Java runtime, but java isn't on PATH", name, path)
            return None
        return Tool(name, (java, "-jar", str(path)), path.parent)
    if path.suffix == ".py":
        return Tool(name, (sys.executable, str(path)), path.parent)
    if path.suffix == ".exe" and os.name != "nt":
        # luajit-decompiler-v2 only builds on Windows, so on anything else its release binary has
        # to go through Wine.
        wine = shutil.which("wine")
        if wine is None:
            log.warning("%s: %s is a Windows executable and wine isn't on PATH", name, path)
            return None
        return Tool(name, (wine, str(path)), path.parent)
    return Tool(name, (str(path),), path.parent)


def _resolve(name: str, explicit: str | None, env_var: str, on_path: str) -> Tool | None:
    """Explicit path, then $ENV_VAR, then a wrapper on PATH."""
    for source in (explicit, os.environ.get(env_var)):
        if source:
            return _as_tool(name, Path(source).expanduser())
    found = shutil.which(on_path)
    return _as_tool(name, Path(found)) if found else None


def resolve_tools(unluac: str | None = None, ljd: str | None = None) -> dict[str, Tool]:
    """Resolves the decompilers that are available, keyed by the tool name the headers ask for."""
    tools = {
        UNLUAC: _resolve(UNLUAC, unluac, "UNLUAC_JAR", "unluac"),
        LUAJIT_DECOMPILER: _resolve(LUAJIT_DECOMPILER, ljd, "LUAJIT_DECOMPILER",
                                    "luajit-decompiler-v2"),
    }
    return {name: tool for name, tool in tools.items() if tool is not None}


# How to install what's missing. Neither is pip-installable, so the message has to say where to look.
_INSTALL_HINT = {
    UNLUAC: "unluac is a Java program (github.com/HansWessels/unluac): build it with its build.sh, "
            "then pass --unluac /path/to/unluac.jar (or set $UNLUAC_JAR)",
    LUAJIT_DECOMPILER: "luajit-decompiler-v2 (github.com/marsinator358/luajit-decompiler-v2) is a "
                       "Windows C++ program: use a release .exe (through Wine on Linux) and pass "
                       "--ljd /path/to/luajit-decompiler-v2.exe (or set $LUAJIT_DECOMPILER)",
}


def _error_line(text: str, limit: int = 200) -> str:
    """Pulls the useful line out of a decompiler's error output.

    Java prints the exception message first and the stack frames under it; Python prints the
    message last, below a 'Traceback' header. Frames are indented in both, so dropping indented
    lines and the Python header leaves the message at the front either way.
    """
    useful = [line.rstrip() for line in text.splitlines()
              if line.strip() and not line[0].isspace()
              and not line.startswith("Traceback (most recent call last)")]
    if not useful:
        stripped = text.strip()
        useful = [stripped.splitlines()[-1]] if stripped else [""]
    message = useful[0].strip()
    return message[:limit] + "..." if len(message) > limit else message


def _produced_file(stem: str, *roots: Path | None) -> Path | None:
    """Finds the file a decompiler wrote for `stem`, for tools that produce files instead of stdout.

    Matched by name, never by timestamp: chunks are decompiled concurrently and a file-producing
    decompiler writes them all into one folder of its own, so picking "the newest .lua" would
    sometimes hand a chunk another chunk's source. A tool that names its output something else
    fails loudly here instead of producing a file with the wrong contents.
    """
    want = f"{stem}.lua".lower()
    for root in roots:
        if root is None or not root.is_dir():
            continue
        for path in root.rglob("*.lua"):
            if path.name.lower() == want:
                return path
    return None


def _decompile_one(tool: Tool, src: Path, dst: Path) -> tuple[bool, str]:
    """Runs one chunk through `tool`. Returns (ok, message); never raises."""
    # Some decompilers print to stdout, others drop a file next to themselves. Run in a scratch
    # directory and accept either, rather than depending on one tool's command-line conventions.
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="coconuts-dec-") as work:
            try:
                proc = subprocess.run(
                    [*tool.argv, str(src)],
                    capture_output=True, cwd=work, timeout=PER_FILE_TIMEOUT,
                )
            except subprocess.TimeoutExpired:
                return False, f"timed out after {PER_FILE_TIMEOUT:.0f}s"
            except OSError as e:
                return False, str(e)

            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or b"").decode("utf-8", "replace")
                return False, _error_line(detail) or f"exit code {proc.returncode}"

            if proc.stdout.strip():
                dst.write_bytes(proc.stdout)
            else:
                # Only the scratch cwd and the tool's own output folder: searching the tool's
                # directory itself would match an unrelated <stem>.lua, such as the decrypted
                # source sitting next to the bytecode if the jar lives above the dump folder.
                produced = _produced_file(
                    src.stem, Path(work), tool.home / "output" if tool.home else None)
                if produced is None:
                    return False, f"the decompiler produced no output (expected {src.stem}.lua)"
                dst.write_bytes(produced.read_bytes())
    except OSError as e:
        return False, str(e)

    log.debug("Decompiled %s in %.1fs", src.name, time.monotonic() - started)
    return True, ""


def _compiled_chunks(out_dir: Path) -> list[tuple[Path, str]]:
    """Every compiled Lua chunk under out_dir, paired with the decompiler its header asks for."""
    found = []
    for path in sorted(out_dir.rglob("*")):
        if not path.is_file() or path.name.endswith(DEC_SUFFIX):
            continue
        try:
            with open(path, "rb") as f:
                header = f.read(16)
        except OSError:
            continue
        flavour = describe_lua_bytecode(header)
        if flavour is not None:
            found.append((path, flavour.tool))
    return found


def decompile_dir(out_dir: str, unluac: str | None = None, ljd: str | None = None,
                  jobs: int | None = None) -> None:
    """Decompiles every compiled Lua chunk under out_dir, writing <name>.dec.lua beside each."""
    root = Path(out_dir)
    chunks = _compiled_chunks(root)
    if not chunks:
        log.info("No compiled Lua chunks in %s to decompile.", out_dir)
        return

    tools = resolve_tools(unluac, ljd)
    needed = {tool for _, tool in chunks}
    for name in sorted(needed - set(tools)):
        count = sum(1 for _, t in chunks if t == name)
        log.warning("%d chunk(s) need %s, which wasn't found. %s", count, name, _INSTALL_HINT[name])

    runnable = [(path, tools[name]) for path, name in chunks if name in tools]
    if not runnable:
        return

    total = len(runnable)
    width = len(str(total))
    workers = jobs if jobs else min(8, (os.cpu_count() or 4))
    log.info("Decompiling %d Lua chunk(s) in %s with %s...", total, out_dir,
             ", ".join(sorted({t.name for _, t in runnable})))

    started = time.monotonic()
    done = failed = 0

    def work(item: tuple[Path, Tool]) -> tuple[Path, bool, str]:
        path, tool = item
        try:
            dst = path.with_name(path.stem + DEC_SUFFIX)
            return (path, *_decompile_one(tool, path, dst))
        except Exception as e:  # a decompiler misbehaving must not take the run down
            return path, False, str(e)

    # Process startup dominates (a JVM launch per chunk), so these run concurrently.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for i, (path, ok, msg) in enumerate(pool.map(work, runnable), 1):
            rel = path.relative_to(root)
            if ok:
                done += 1
                log.info("[%*d/%d] %s", width, i, total, rel)
            else:
                failed += 1
                log.warning("[%*d/%d] %s: %s", width, i, total, rel, msg)

    log.log(SUCCESS, "Decompiled %d chunk(s) to *%s in %.1fs.", done, DEC_SUFFIX,
            time.monotonic() - started)
    if failed:
        log.warning("%d chunk(s) could not be decompiled; their .luac is unchanged.", failed)
    if done:
        log.info("Decompiled source can be wrong even when it looks right (a patched opcode table "
                 "produces plausible nonsense); the bytecode is kept beside it.")
