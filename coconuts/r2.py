"""
radare2 analysis (with O(1) symbol & .data.rel.ro vtable fast paths).

Resolves the XXTEA key / evalString / setXXTeaKey functions in a stripped arm64 libcocos.so (and the
xxtea_decrypt / luaL_loadbuffer symbols in libcocos2dlua.so),
and provides the abort guard used to kill a running radare2 subprocess when the other track wins.
"""

from __future__ import annotations

import contextlib
import os
import re
import threading

from .log import flog, slog

# Strings used to locate functions in libcocos / libcocos2djs with radare2
EVAL_STRING_NEEDLES = [
    "evalString script %s, failed",
    "evaluating script %s",
    "(evaluatedOK == JS_FALSE)",  # Cocos2d-JS ScriptingCore::runScript
]
DECRYPT_FAIL_NEEDLES = [
    "t decrypt code for %s",
    "Can't decrypt code for",
]

# Empirical: in the builds this tool was developed against, the 13th `bl` inside the
# "Can't decrypt code for %s" function is the call to xxtea_decrypt. This depends on the
# Cocos version, hence the xref-count fallback in find_key_function().
KEY_CALL_INDEX = 12


@contextlib.contextmanager
def _r2_abort_guard(r2, abort_event: threading.Event | None):
    """Immediately terminates the underlying radare2 subprocess if abort_event is set."""
    if abort_event is None:
        yield
        return
    done = threading.Event()

    def _watcher():
        while not done.is_set():
            if abort_event.is_set():
                proc = getattr(r2, "process", None)
                if proc is not None:
                    with contextlib.suppress(Exception):
                        proc.terminate()
                    with contextlib.suppress(Exception):
                        proc.kill()
                return
            done.wait(0.05)

    t = threading.Thread(target=_watcher, name="r2-abort-guard", daemon=True)
    t.start()
    try:
        yield
    finally:
        done.set()


def find_symbol_vaddr(symbols: list[dict], patterns: list[str]) -> int | None:
    """Finds a defined function vaddr in the symbol table matching any regex pattern."""
    for pat in patterns:
        rx = re.compile(pat)
        for s in symbols:
            vaddr = s.get("vaddr") or 0
            if not vaddr or s.get("is_imported"):
                continue
            if rx.search(s.get("name", "")):
                return vaddr
    return None


def _resolve_relro_set_xxtea_key(r2) -> int | None:
    """
    Fast path from 'Framework: Cocos2d-js' (.data.rel.ro section):
    On stripped arm64 libcocos.so, .data.rel.ro + 0xa0 holds cc::CocosApplication::setXXTeaKey.
    Returns the function's *code* address (a Frida hook target), never the key: the key is the
    function's std::string argument and only exists at runtime.
    """
    sections = r2.cmdj("iSj") or []
    relro = next((s for s in sections if s.get("name") == ".data.rel.ro"), None)
    if not relro or not relro.get("vaddr"):
        return None
    slot_addr = relro["vaddr"] + 0xA0
    vals = r2.cmdj(f"pxqj 8 @ {slot_addr:#x}") or []
    if vals and vals[0] > 0x1000:
        exec_secs = [s for s in sections if "x" in (s.get("perm") or "")]
        if any(s["vaddr"] <= vals[0] < s["vaddr"] + s.get("vsize", 0) for s in exec_secs):
            return vals[0]
    return None


def r2_open_and_analyse(
    lib_path: str,
    run_heavy_analysis: bool = False,
    abort_event: threading.Event | None = None,
):
    import r2pipe

    r2 = r2pipe.open(os.path.abspath(lib_path), flags=["-2"])
    try:
        with _r2_abort_guard(r2, abort_event):
            r2.cmd("e asm.comments=false")
            r2.cmd("e asm.usercomments=true")

            info = (r2.cmdj("ij") or {}).get("bin", {})
            if abort_event and abort_event.is_set():
                return r2, "", [], []
            if info.get("arch") != "arm" or info.get("bits") != 64:
                raise RuntimeError(f"Only arm64 libs are supported (arch={info.get('arch')}, bits={info.get('bits')})")

            symbols = r2.cmdj("isj") or []
            if abort_event and abort_event.is_set():
                return r2, "", [], symbols
            # Cocos2dxJavascriptJavaBridge (JS engines) or Cocos2dxLuaJavaBridge (Lua engines)
            bridge = sorted({m.group(0) for s in symbols
                             for m in [re.search(r"Java_\w*(?:Javascript|Lua)JavaBridge\w*", s.get("name", ""))] if m})
            if not bridge:
                raise RuntimeError("No JavascriptJavaBridge / LuaJavaBridge JNI export found; "
                                   "this doesn't look like a Cocos engine lib")
            if len(bridge) > 1:
                flog.debug("Multiple bridge symbols %s; using %s", bridge, bridge[0])
            cocos_symbol = bridge[0]

            strings = []
            if run_heavy_analysis and not (abort_event and abort_event.is_set()):
                jdiv_addrs = [s["vaddr"] for s in symbols if "jdiv" in s.get("name", "") and s.get("vaddr")]
                flog.info("Running radare2 code analysis (this can take a while)...")
                if jdiv_addrs:
                    anal_end = min(jdiv_addrs)
                    r2.cmd(f"e anal.limits=true; e anal.from=entry0; e anal.to={anal_end:#x}; aap; "
                           f"e anal.in=io.maps.x; aaef")
                else:
                    flog.warning("No 'jdiv' symbol to bound analysis; analysing without limits (slower).")
                    r2.cmd("aap; e anal.in=io.maps.x; aaef")

                if not (abort_event and abort_event.is_set()):
                    strings = r2.cmdj("izzj") or []
                    if isinstance(strings, dict):
                        strings = strings.get("strings", [])

            return r2, cocos_symbol, strings, symbols
    except Exception:
        with contextlib.suppress(Exception):
            r2.quit()
        raise


def _resolve_enclosing_function(r2, code_addr: int) -> int | None:
    """Attempts to define or locate the function containing code_addr when fcn_addr is 0."""
    r2.cmd(f"e anal.limits=false; af @ {code_addr:#x}")
    info = r2.cmdj(f"afij @ {code_addr:#x}") or []
    if info and info[0].get("offset"):
        return info[0]["offset"]
    ops = r2.cmdj(f"pdj -256 @ {code_addr:#x}") or []
    for op in reversed(ops):
        if op.get("fcn_addr"):
            return op["fcn_addr"]
    return code_addr


def find_string_xref_function(r2, strings, needles: str | list[str]) -> int:
    if isinstance(needles, str):
        needles = [needles]

    matched_targets = []
    for needle in needles:
        for s in strings:
            if needle in s.get("string", ""):
                matched_targets.append((needle, s))

    if not matched_targets:
        raise RuntimeError(f"String not found: {needles[0]!r}")

    for _, target in matched_targets:
        vaddr = target["vaddr"]
        xrefs = r2.cmdj(f"axtj @ {vaddr:#x}") or []
        if not xrefs:
            r2.cmd("e anal.limits=false; aae")
            xrefs = r2.cmdj(f"axtj @ {vaddr:#x}") or []
        for x in xrefs:
            if x.get("fcn_addr"):
                return x["fcn_addr"]
            if x.get("from"):
                resolved = _resolve_enclosing_function(r2, x["from"])
                if resolved:
                    return resolved

    raise RuntimeError(f"No function references {needles[0]!r}")


def _xref_count(r2, addr: int) -> int:
    return len(r2.cmdj(f"axtj @ {addr:#x}") or [])


def find_key_function(r2, strings, symbols) -> int:
    fn = find_string_xref_function(r2, strings, DECRYPT_FAIL_NEEDLES)
    ops = (r2.cmdj(f"pdfj @ {fn:#x}") or {}).get("ops", [])
    calls = [op["jump"] for op in ops
             if op.get("jump") and op.get("disasm", "").split(None, 1)[:1] == ["bl"]]
    if not calls:
        raise RuntimeError("No `bl` calls found in the decrypt-failure function")

    fun_key = calls[KEY_CALL_INDEX] if len(calls) > KEY_CALL_INDEX else calls[-1]
    if _xref_count(r2, fun_key) != 2:
        for c in calls[:KEY_CALL_INDEX + 1]:
            if _xref_count(r2, c) == 2:
                fun_key = c
                break

    head = r2.cmd(f"pd 4 @ {fun_key:#x}")
    if "x16" in head or "x17" in head:  # PLT stub -> resolve the real symbol
        sym = next((s for s in symbols if "xxtea_decrypt" in s.get("name", "") and s.get("vaddr")), None)
        if sym:
            fun_key = sym["vaddr"]
        else:
            flog.warning("Key function looks like a PLT stub and no xxtea_decrypt symbol was found; hooking the stub.")
    return fun_key
