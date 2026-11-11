"""Regenerates tests/fixtures/bytecode/ with genuine Lua bytecode.

The checked-in fixtures were produced by this script on x86_64 Linux, which is why the PUC 5.1-5.3
ones report 64-bit (their header carries sizeof(size_t)). Regenerating on a 32-bit host would
change those labels, so the fixtures are committed rather than built during the test run.

    pip install lupa && python tests/fixtures/gen_bytecode.py tests/fixtures/bytecode

lupa bundles PUC Lua 5.1-5.5 and LuaJIT 2.0/2.1, so no Lua toolchain has to be installed.
"""

import os
import sys

SRC = b"local M = {}\nfunction M.add(a, b) local s = a + b return s end\nreturn M\n"
RUNTIMES = ("lua51", "lua52", "lua53", "lua54", "lua55", "luajit20", "luajit21")


def main(out: str) -> int:
    os.makedirs(out, exist_ok=True)
    for name in RUNTIMES:
        try:
            mod = __import__("lupa." + name, fromlist=[name])
            rt = mod.LuaRuntime(encoding=None)  # raw bytes in and out, not UTF-8
        except Exception as e:
            print(f"{name:10} runtime unavailable: {e}")
            continue
        dump = rt.eval(b"string.dump")
        loader = rt.eval(b"loadstring") or rt.eval(b"load")  # 5.1 has no load() for strings
        for strip in (False, True):
            try:
                blob = bytes(dump(loader(SRC), True) if strip else dump(loader(SRC)))
            except Exception as e:
                print(f"{name:10} strip={strip!s:5} dump failed: {e}")
                continue
            path = os.path.join(out, f"{name}{'_stripped' if strip else ''}.luac")
            with open(path, "wb") as f:
                f.write(blob)
            print(f"{name:10} strip={strip!s:5} {len(blob):5}B  header={blob[:6].hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "bytecode"))
