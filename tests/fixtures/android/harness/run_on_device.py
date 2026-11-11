#!/usr/bin/env python3
"""
Runs coconuts' real Frida agent (coconuts/frida_hook.js via build_frida_script) against the
on-device harness and reports what the Lua loader hook captured.

dump_off/key_off are passed as None on purpose: that forces the agent to resolve
luaL_loadbuffer(x) the way it must in a Lua lib radare2 can't pre-resolve, i.e. through
findExportByName, then enumerateExports, then enumerateSymbols.

Usage: run_on_device.py <runtime> <variant> [more variants...]
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO))

import frida  # noqa: E402

from coconuts.frida_dump import build_frida_script  # noqa: E402

SERIAL = os.environ.get("COCONUTS_SERIAL", "")        # adb serial; "" = the only device
FRIDA_HOST = os.environ.get("COCONUTS_FRIDA_HOST", "127.0.0.1:27500")
REMOTE = os.environ.get("COCONUTS_REMOTE", "/data/local/tmp/coconuts_harness")
BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxLuaJavaBridge_retainLuaFunction"
ATTACH_DELAY = 10   # the driver waits this long before dlopen, to be attached to in time
# HARNESS_* variables are passed through to the engine (HARNESS_ZERO_LEN_KEY makes it set the key
# with zero lengths, the way a fork relying on NUL-terminated strings would).
ENGINE_ENV = {k: v for k, v in os.environ.items() if k.startswith("HARNESS_")}


ADB = ["adb"] + (["-s", SERIAL] if SERIAL else [])


def adb(*args: str) -> str:
    return subprocess.run([*ADB, *args], capture_output=True, text=True, timeout=30).stdout


def run_variant(runtime: str, variant: str) -> dict:
    remote_dir = f"{REMOTE}/{runtime}/{variant}"
    script_src = build_frida_script(BRIDGE, dump_off=None, key_off=None, key_is_std_string=False)

    # Wait for any earlier driver to actually be gone before starting one. Attaching to a stale
    # process means the agent arrives after the key was already set, and sees only the later
    # xxtea_decrypt call -- a key with no signature, for no reason to do with the agent.
    adb("shell", "pkill -9 -f tmp/coconuts_harness")
    for _ in range(50):
        if not adb("shell", "pidof driver").split():
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("a previous driver process is still running")

    # The driver waits before dlopen()ing the engine lib, so the agent is live when the library
    # is mapped: the do_dlopen hook is what has to catch it, exactly as in a real game.
    proc = subprocess.Popen(
        [*ADB, "shell", "".join(f"{k}={v} " for k, v in ENGINE_ENV.items())
         + f"{REMOTE}/driver {remote_dir}/libcocos2dlua.so {ATTACH_DELAY}"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    pid = None
    for _ in range(50):
        time.sleep(0.1)
        got = adb("shell", "pidof driver").split()
        if got:
            if len(got) > 1:
                raise RuntimeError(f"several driver processes are running: {got}")
            pid = int(got[0])
            break
    if pid is None:
        raise RuntimeError("driver process never appeared")

    dev = frida.get_device_manager().add_remote_device(FRIDA_HOST)
    session = dev.attach(pid)
    script = session.create_script(script_src)

    files: list[dict] = []
    keys: list[dict] = []
    logs: list[tuple[str, str]] = []

    def on_message(msg, data):
        if msg["type"] == "error":
            logs.append(("error", msg.get("description", str(msg))))
            return
        p = msg["payload"]
        kind = p.get("type")
        if kind == "log":
            logs.append((p["level"], p["msg"]))
        elif kind == "file":
            body = data if data is not None else (p.get("text") or "").encode()
            files.append({"path": p["path"], "len": len(body), "lang": p.get("lang", ""),
                          "sha": hashlib.sha256(body).hexdigest()[:12], "head": body[:20]})
        elif kind in ("key", "aeskey"):
            keys.append(p)

    script.on("message", on_message)
    script.load()

    # Let the driver get through its dlopen + every chunk load.
    try:
        out = proc.communicate(timeout=ATTACH_DELAY + 20)[0] or ""
    except subprocess.TimeoutExpired:
        proc.kill()
        out = proc.communicate()[0] or ""

    time.sleep(0.5)
    try:
        session.detach()
    except Exception:
        pass
    adb("shell", "pkill -9 -f tmp/coconuts_harness")

    return {"runtime": runtime, "variant": variant, "files": files, "keys": keys,
            "logs": logs, "stdout": out}


def report(r: dict) -> None:
    print(f"\n{'=' * 78}\n=== {r['runtime']}/{r['variant']}\n{'=' * 78}")
    print("--- agent log ---")
    for level, msg in r["logs"]:
        print(f"  [{level}] {msg}")
    print(f"--- captured keys ({len(r['keys'])}) ---")
    for k in r["keys"]:
        print(f"  {k}")
    print(f"--- dumped chunks ({len(r['files'])}) ---")
    for f in sorted(r["files"], key=lambda x: x["path"]):
        print(f"  {f['path']!r:52} len={f['len']:4d} lang={f['lang'] or '-':4} "
              f"sha={f['sha']} head={f['head']!r}")
    for line in r["stdout"].splitlines():
        if "vtable slot" in line or "zero lengths" in line or "not exported" in line:
            print(f"--- engine: {line.strip()}")
    engine = [ln for ln in r["stdout"].splitlines() if "loaded" in ln or "FAILED" in ln
              or "done:" in ln]
    print(f"--- engine loaded {len(engine)} line(s); "
          f"{'ok' if any('done:' in ln and '0 failed' in ln for ln in engine) else 'CHECK'} ---")
    if attached_late(r):
        print("--- the agent attached after the engine had already loaded its chunks; "
              "nothing to conclude from this run, so re-run it ---")


def attached_late(r: dict) -> bool:
    """True when the engine loaded chunks but the agent saw none of them.

    The agent is attached to a process that then dlopen()s the library, so a slow attach can
    arrive after the chunks are already loaded. That looks exactly like a broken hook and is not
    one, so it is called out rather than reported as a result.
    """
    loaded = any("done:" in ln and " 0 loaded" not in ln for ln in r["stdout"].splitlines())
    hooked = any("hooked luaL_loadbuffer" in m for _l, m in r["logs"])
    return loaded and hooked and not r["files"]


def main() -> int:
    runtime = sys.argv[1]
    variants = sys.argv[2:] or ["default-unstripped", "default-stripped",
                                "hidden-unstripped", "hidden-stripped"]
    results = [run_variant(runtime, v) for v in variants]
    for r in results:
        report(r)

    print(f"\n{'=' * 78}\n=== summary: {runtime}\n{'=' * 78}")
    print(f"  {'variant':22} {'chunks':>6} {'keys':>5}  hook resolution")
    for r in results:
        hooked = [m for _l, m in r["logs"] if "hooked luaL_loadbuffer" in m]
        warned = [m for _l, m in r["logs"] if "live script dumps disabled" in m]
        state = hooked[0].split(" @ ")[0].replace("hooked ", "") if hooked else (
            "NOT FOUND (warned)" if warned else "no hook, no warning")
        if attached_late(r):
            state += "  [attached late: re-run]"
        print(f"  {r['variant']:22} {len(r['files']):>6} {len(r['keys']):>5}  {state}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
