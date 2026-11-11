"""
Frida dynamic track (supports XXTEA, setXXTeaKey, LuaStack::setXXTEAKeyAndSign, AES EncryptManager,
and XOR FileUtils::init).

Resolves the hook targets with radare2, loads the Frida hook (frida_hook.js) with the resolved
offsets patched in, spawns the app, and races key/AES capture against the static track.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import queue
import threading
import time

from .aes import aes_roll_from_flags
from .ciphers import describe_key, normalize_key
from .extract import LuaBytecodeReport, jsc_to_js, lua_live_name, safe_join
from .log import SUCCESS, flog
from .r2 import (
    EVAL_STRING_NEEDLES,
    _r2_abort_guard,
    _resolve_relro_set_xxtea_key,
    find_key_function,
    find_string_xref_function,
    find_symbol_vaddr,
    r2_open_and_analyse,
)

_FRIDA_HOOK_JS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frida_hook.js")


class FileWriter:
    """Background writer for live dumps. Must be close()d to flush."""

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.saved = 0
        self._written: set[str] = set()  # distinct output paths, so a rewrite isn't counted twice
        self._lua = LuaBytecodeReport()
        self._q: queue.Queue = queue.Queue()
        self._t = threading.Thread(target=self._run, name="file-writer")
        self._t.start()

    def submit(self, rel_path: str, data: bytes) -> None:
        self._q.put((rel_path, data))

    def close(self) -> None:
        self._q.put(None)
        self._t.join()
        if self.saved:
            flog.log(SUCCESS, "Saved %d live script dump(s) to %s", self.saved, self.base_dir)
            self._lua.log(flog)

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                return
            rel_path, data = item
            try:
                out_path = safe_join(self.base_dir, rel_path)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(data)
                if out_path in self._written:
                    # The agent only re-sends a chunk whose body changed (hot update).
                    flog.debug("Live dump updated: %s", out_path)
                else:
                    self._written.add(out_path)
                    self._lua.add(data)
                    self.saved += 1
                    flog.info("Live dump: %s", out_path)
            except (OSError, ValueError) as e:
                flog.warning("Could not write live dump %r: %s", rel_path, e)


def _load_frida_template() -> str:
    """Reads the Frida hook template (with __PLACEHOLDER__ tokens) shipped alongside this module."""
    with open(_FRIDA_HOOK_JS, encoding="utf-8") as f:
        return f.read()


def build_frida_script(
    cocos_symbol: str,
    dump_off: int | None,
    key_off: int | None,
    key_is_std_string: bool = False,
) -> str:
    return (_load_frida_template()
            .replace("__COCOS_SYMBOL__", json.dumps(cocos_symbol))
            .replace("__DUMP_OFFSET__", f'ptr("{dump_off:#x}")' if dump_off is not None else "null")
            .replace("__KEY_OFFSET__", f'ptr("{key_off:#x}")' if key_off is not None else "null")
            .replace("__KEY_IS_STD_STRING__", "true" if key_is_std_string else "false"))


def resolve_frida_targets(
    lib_path: str,
    abort_event: threading.Event | None = None,
    high_prob_done: threading.Event | None = None,
) -> tuple[str, int | None, int | None, bool]:
    """Resolves JNI symbol, dump_off, and key_off using fast symbol/relro check first."""
    if abort_event and abort_event.is_set():
        return "", None, None, False

    r2, cocos_symbol, _, symbols = r2_open_and_analyse(
        lib_path, run_heavy_analysis=False, abort_event=abort_event
    )
    key_is_std_string = False
    dump_off = None
    key_off = None
    try:
        if not (abort_event and abort_event.is_set()):
            with _r2_abort_guard(r2, abort_event):
                key_off = find_symbol_vaddr(symbols, [r"(^|_)xxtea_decrypt$", r"xxtea_decrypt"])
                if key_off:
                    flog.info("xxtea_decrypt found in the symbol table at %#x", key_off)
                else:
                    relro_off = _resolve_relro_set_xxtea_key(r2)
                    if relro_off:
                        flog.info("setXXTeaKey found via .data.rel.ro+0xa0 at %#x", relro_off)
                        key_off = relro_off
                        key_is_std_string = True

                dump_off = find_symbol_vaddr(symbols, [
                    r"ScriptEngine.*evalString",
                    r"ScriptingCore.*evalString",
                ])
                if dump_off:
                    flog.info("evalString found in the symbol table at %#x", dump_off)
    finally:
        with contextlib.suppress(Exception):
            r2.quit()

    if abort_event and abort_event.is_set():
        return cocos_symbol, dump_off, key_off, key_is_std_string

    # Only run heavy `aap; aaef` if key_off was not found via symbol table or .data.rel.ro.
    # Wait for high-probability static tiers (Tier0..Tier2) first; if Tier 3 continues,
    # race heavy r2 analysis in parallel and kill r2 immediately if abort_event fires.
    if key_off is None:
        if high_prob_done is not None and not (abort_event and abort_event.is_set()):
            high_prob_done.wait()

        if abort_event and abort_event.is_set():
            flog.info("Static track already found the key; skipping radare2 analysis.")
            return cocos_symbol, dump_off, key_off, key_is_std_string

        r2, cocos_symbol, strings, symbols = r2_open_and_analyse(
            lib_path, run_heavy_analysis=True, abort_event=abort_event
        )
        try:
            with _r2_abort_guard(r2, abort_event):
                if not (abort_event and abort_event.is_set()):
                    try:
                        key_off = find_key_function(r2, strings, symbols)
                        flog.info("Key function at %#x", key_off)
                    except Exception as e:
                        if not (abort_event and abort_event.is_set()):
                            flog.warning("Key function not found statically (%s); Frida will try symbol exports.", e)
                            flog.debug("details", exc_info=True)

                if dump_off is None and not (abort_event and abort_event.is_set()):
                    try:
                        dump_off = find_string_xref_function(r2, strings, EVAL_STRING_NEEDLES)
                        flog.info("Dump function at %#x", dump_off)
                    except Exception as e:
                        if not (abort_event and abort_event.is_set()):
                            flog.warning("Dump function not found statically (%s); continuing with key-only/export hooks.", e)
                            flog.debug("details", exc_info=True)
        finally:
            with contextlib.suppress(Exception):
                r2.quit()

        if abort_event and abort_event.is_set():
            flog.info("Static track found the key; stopping.")

    return cocos_symbol, dump_off, key_off, key_is_std_string


def run_frida_race(
    device,
    package: str,
    script_src: str,
    writer: FileWriter,
    timeout: float,
    live_seconds: float,
    abort_event: threading.Event,
    dynamic_won: threading.Event | None = None,
    aes_box: dict | None = None,
) -> bytes | None:
    """Runs Frida dynamic interception, aborting early if `abort_event` (static track) wins.

    Returns the captured XXTEA key (or None). A captured EncryptManager AES key/iv is stored in
    `aes_box` (keys 'key', 'iv', 'flags') and also counts as winning the race.
    """
    key_box: dict[str, bytes] = {}
    key_event = threading.Event()
    gone_event = threading.Event()

    def on_message(message, data):
        mtype = message.get("type")
        if mtype == "error":
            flog.error("Script error: %s", message.get("stack") or message.get("description"))
            return
        if mtype != "send":
            return
        p = message.get("payload") or {}
        kind = p.get("type")
        if kind == "key":
            if key_event.is_set():
                return
            try:
                key = normalize_key(bytes.fromhex(p["key"]))
            except (KeyError, ValueError):
                flog.warning("Malformed key message: %r", p)
                return
            key_box["key"] = key
            flog.log(SUCCESS, "Key captured: %s", describe_key(key))
            if p.get("sign"):
                with contextlib.suppress(ValueError):
                    flog.info("Signature passed with the key: %r", bytes.fromhex(p["sign"]))
            if dynamic_won is not None:
                dynamic_won.set()
            key_event.set()
        elif kind == "aeskey":
            if aes_box is None or aes_box or key_event.is_set():
                return
            try:
                aes_box["key"] = bytes.fromhex(p["key"])
                aes_box["iv"] = bytes.fromhex(p.get("iv") or "")
                aes_box["flags"] = int(p.get("flags") or 0)
            except (KeyError, ValueError):
                flog.warning("Malformed AES key message: %r", p)
                aes_box.clear()
                return
            roll = aes_roll_from_flags(aes_box["flags"])
            flog.log(SUCCESS, "AES key captured: %s iv=%s (roll=%d)",
                     describe_key(aes_box["key"]), aes_box["iv"].hex() or "<default>", roll)
            if dynamic_won is not None:
                dynamic_won.set()
            key_event.set()
        elif kind == "file":
            path = p.get("path") or ""
            if not path:
                return
            body = data if data is not None else (p.get("text") or "").encode("utf-8", errors="replace")
            writer.submit(lua_live_name(path, body) if p.get("lang") == "lua" else jsc_to_js(path), body)
        elif kind == "log":
            level = {"debug": logging.DEBUG, "warning": logging.WARNING}.get(p.get("level"), logging.INFO)
            flog.log(level, "%s", p.get("msg"))

    flog.info("Spawning %s on %s", package, device.name)
    pid = device.spawn([package])
    session = device.attach(pid)
    session.on("detached", lambda *a: gone_event.set())
    try:
        script = session.create_script(script_src)
        script.on("message", on_message)
        script.load()
    except Exception:
        with contextlib.suppress(Exception):
            device.kill(pid)
        with contextlib.suppress(Exception):
            session.detach()
        raise

    try:
        device.resume(pid)
        flog.info("Waiting up to %.0fs for the key...", timeout)
        try:
            deadline = time.monotonic() + timeout
            while not key_event.is_set() and not gone_event.is_set() and not abort_event.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                key_event.wait(min(0.2, remaining))

            if abort_event.is_set() and not key_event.is_set():
                flog.info("Static track found the key first; stopping Frida.")
                return None

            if not key_event.is_set():
                if gone_event.is_set():
                    flog.warning("App exited or crashed before the key was captured.")
                else:
                    flog.warning("No key captured within %.0fs.", timeout)

            if live_seconds > 0 and not gone_event.is_set() and not abort_event.is_set():
                flog.info("Collecting live dumps for %.0fs more (Ctrl-C to stop early)...", live_seconds)
                gone_event.wait(live_seconds)
        except KeyboardInterrupt:
            flog.info("Interrupted: stopping live capture, continuing with offline extraction.")
    finally:
        with contextlib.suppress(Exception):
            session.detach()
        if abort_event.is_set():
            with contextlib.suppress(Exception):
                device.kill(pid)
    return key_box.get("key")
