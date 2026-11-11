# Android Lua engine fixtures

Real `libcocos2dlua.so` libraries for arm64 Android, used to verify the Frida Lua loader hook
(`coconuts/frida_hook.js`) against a real device instead of only against the Node stub in
`tests/fake_frida.js`.

Each library is built from real runtime sources — Lua 5.1.5, Lua 5.3.6 and LuaJIT 2.1 — linked
together with `harness/luastack.cpp`, which is a transcription of the parts of
`cocos2d::LuaStack` that coconuts hooks, taken from cocos2d-x v3
`cocos/scripting/lua-bindings/manual/CCLuaStack.cpp`:

- `setXXTEAKeyAndSign(const char *key, int keyLen, const char *sign, int signLen)`
- `luaLoadBuffer(lua_State *, const char *chunk, int chunkSize, const char *chunkName)`, which
  xxtea-decrypts a chunk carrying the signature and then calls `luaL_loadbuffer` with the
  **plaintext**, which is what makes live dumping possible at all
- `executeString(const char *codes)` → `luaL_loadstring`, where the chunk name is the source

The chunks it loads (`harness/gen_chunks.py`, baked into each runtime's `chunks.h`) are
encrypted with `tests/conftest.py`'s own `xxtea_encrypt`, with the same `KEY_TEXT`/`SIGN` as the
pytest suite. The C decrypt in `harness/xxtea_min.c` therefore has to agree with the Python one
or real Lua would refuse to compile the result — the libraries loading at all is itself a check
that the two implementations match.

## The matrix

Four symbol shapes per runtime, because whether the agent can hook a given game comes down to
how its engine library was built:

| variant              | `.dynsym` | `.symtab` | how the agent must find the loader |
| -------------------- | --------- | --------- | ---------------------------------- |
| `default-unstripped` | yes       | yes       | `findExportByName`                 |
| `default-stripped`   | yes       | no        | `findExportByName` (exports survive `--strip-all`) |
| `hidden-unstripped`  | no        | yes       | `enumerateSymbols` only            |
| `hidden-stripped`    | no        | no        | not findable; must degrade with a warning |

Which symbols exist depends on the runtime, and this is dictated by the runtimes' own headers:

| runtime | `luaL_loadbuffer` | `luaL_loadbufferx` | why |
| ------- | ----------------- | ------------------ | --- |
| Lua 5.1.5 | yes | no  | `luaL_loadbufferx` did not exist yet (`lauxlib.h:78`) |
| Lua 5.3.6 | no  | yes | `luaL_loadbuffer` is a macro (`lauxlib.h:139`) |
| LuaJIT 2.1 | yes | yes | both are real functions (`lj_load.c:153,162`) |

The JNI bridge export (`Java_org_cocos2dx_lib_Cocos2dxLuaJavaBridge_retainLuaFunction`) is
declared `visibility("default")` in every variant, so it survives stripping — this is how
`r2.py` recognises a library as a Cocos engine lib, and without it even the
identification step would fail.

`tests/test_android_fixtures.py` asserts all of the above still holds, and runs coconuts'
radare2 path over these libraries.

## What the device run established

Run on a Pixel 7, Android 14, arm64, against all three runtimes × all four variants. Three
agent defects came out of it, all now fixed and covered by the Node suite:

1. **Bounded `readCString` returned garbage.** `readCString(size)` on Frida 17 reads `size`
   bytes whatever the string's length is, and the NUL does not survive decoding, so the result
   cannot be trimmed back either. Every chunk name came back as ~1000 characters of trailing
   heap, failed `LUA_CHUNK_NAME`, and **nothing was dumped and nothing was logged**. The stub
   used to stop at the NUL in both modes, which is why the suite never saw it.
2. **The loader hook attached to a lambda.** Android 14's `linker64` carries two symbols
   containing `do_dlopen`, and the closure inside the function comes first. Attaching to it
   succeeded and it was never called, leaving no working loader hook; the public entry points
   are now hooked as well, since a successful attach is no proof of being on the call path.
3. **LuaJIT dumped nothing.** `luaL_loadbuffer` and `luaL_loadbufferx` are one translation unit
   in `lj_load.c`, so at `-O2` the callee is inlined into the wrapper: on the device both were
   separate complete 148-byte functions with no branch between them. `LuaStack::luaLoadBuffer`
   calls `luaL_loadbuffer`, so hooking only `luaL_loadbufferx` saw nothing while still
   reporting a healthy hook. Both are hooked now, and the content dedup collapses the duplicate
   in builds where they really do chain.

Chunk names, from `CCLuaStack.cpp` and confirmed on the device:

| source | form | example |
| ------ | ---- | ------- |
| `executeScriptFile` | `FileUtils::fullPathForFilename()`, **no `@` prefix** | `assets/src/main.lua` |
| `loadChunksFromZIP` | zip entry minus extension, `/` and `\` → `.` | `app.views.MainScene` |
| hot update | absolute path in the writable dir | `/data/user/0/<pkg>/files/src/hot.lua` |
| `executeString` | the source itself (rejected by `LUA_CHUNK_NAME`) | `print('hot path')` |

It also settled three smaller questions:

- **Bytecode loaded with the length left unknown.** LuaJIT's `lib_package.c` loads embedded
  bytecode as `luaL_loadbuffer(L, bcdata, ~(size_t)0, name)`, because a dump carries its own end.
  The agent's sanity bound used to reject that and drop the chunk; it now walks the dump to
  recover the length. The LuaJIT engine here generates such a chunk on the device (so the
  bytecode matches the build exactly) and it comes back at its full 35 bytes.
- **The key setter's vtable slot.** `cocos2d::Ref` has one virtual member and `LuaStack` declares
  30 more, which puts `setXXTEAKeyAndSign` at slot 29 (`+0xe8` with 64-bit pointers) after the two
  destructor entries. `harness/luastack.h` transcribes that virtual list from the real header, so
  the engine can report the slot clang actually gave it — it prints
  `setXXTEAKeyAndSign is vtable slot 29 (+0xe8 with 64-bit pointers)` in the default-visibility
  variants, and says the setter isn't exported in the hidden ones. A vtable-walking fallback is
  not implemented; see TODO.md for why the numbers alone aren't reason enough.
- **The key hook's C-string fallback.** With `HARNESS_ZERO_LEN_KEY=1` the engine passes the key
  and signature lengths as 0, the way a fork relying on NUL-terminated strings would, and both are
  still recovered. That path was broken on a device until the `readCString` fix above.

One limitation stands, harmless but worth knowing: at `-O2` the runtimes inline `luaL_loadbuffer`
into `luaL_loadstring` (Lua 5.1) and `luaL_loadbufferx` into `luaL_loadbuffer` (LuaJIT), so which
calls a hook observes depends on the optimisation level the engine was built with.

## Rebuilding

Needs the Android NDK (`$NDK`, or the path baked into the scripts) and the runtime sources.
Output goes next to the harness, overwriting the fixtures in place (`driver` is one binary shared by every runtime); `$OUT_DIR` redirects it. The scripts share their toolchain and variant logic through `harness/common.sh`.
The builds are reproducible — a rebuild of the Lua 5.3 fixtures came out byte-identical.

```sh
# PUC Lua: build the host interpreter first, so luac can produce the bytecode test case
cd lua-5.3.6 && make linux && cd -
harness/build.sh lua53 /path/to/lua-5.3.6/src

# LuaJIT: cross-compile it first, then link the harness against libluajit.a
cd LuaJIT && make HOST_CC="cc -m64" CROSS="$TC/aarch64-linux-android21-" CC=clang \
    TARGET_AR="$TC/llvm-ar rcus" TARGET_STRIP="$TC/llvm-strip" \
    TARGET_SYS=Linux TARGET_FLAGS="-fPIC" && cd -
harness/build_luajit.sh /path/to/LuaJIT
```

## Running on a device

`harness/run_on_device.py` renders the real agent through `build_frida_script()` — with both
offsets `None`, so the agent has to resolve the loader itself — attaches to the driver and
reports every chunk, key and log message it got.

The driver is a plain native binary rather than an app, which needs a frida-server that will
attach to one: a stock `frida-server` matching the host `frida` package, run as root. A
device's pre-installed (often patched) server may refuse, and a version mismatch between host
and server fails at attach while `frida-ps` still works.

```sh
adb push frida-server-<version>-android-arm64 /data/local/tmp/fs && adb shell chmod 755 /data/local/tmp/fs
adb shell "nohup /data/local/tmp/fs -l 127.0.0.1:27500 >/dev/null 2>&1 &"
adb forward tcp:27500 tcp:27500

adb shell mkdir -p /data/local/tmp/coconuts_harness/lua53/default-unstripped
adb push driver /data/local/tmp/coconuts_harness/
adb push lua53/default-unstripped/libcocos2dlua.so \
    /data/local/tmp/coconuts_harness/lua53/default-unstripped/
adb shell chmod -R 755 /data/local/tmp/coconuts_harness

python harness/run_on_device.py lua53              # all four variants
python harness/run_on_device.py luajit default-unstripped
```

`COCONUTS_SERIAL`, `COCONUTS_FRIDA_HOST` and `COCONUTS_REMOTE` override the adb serial, the
frida-server address and the on-device directory, and any `HARNESS_*` variable is passed through
to the engine. One `driver` serves every runtime, so it lives at the root of the on-device
directory rather than beside each library.

The driver waits before it `dlopen()`s the library so the agent can attach first. If the attach is
slow anyway, the agent arrives after the chunks are already loaded and reports no dumps at all,
which looks exactly like a broken hook; the runner notices that case and says to re-run instead.
