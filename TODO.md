# TODO

Open work, mostly for the Lua support added on the `lua-support` branch.

## Lua: verify against real games

- [ ] **Run on a real Cocos2d-x Lua APK.** The Frida side is no longer synthetic: the loader and
  key hooks are verified on a Pixel 7 against real arm64 engine libraries built from real Lua /
  LuaJIT sources (`tests/fixtures/android/`). What is still untested is a *shipped* game — the
  APK-side paths (`--static-only`, `--key`, the full static + Frida race, assets collected from a
  real `assets/` tree) and whatever a real build does differently from Cocos's upstream source.
- [ ] **Frida: `LuaStack::setXXTEAKeyAndSign` overloads.** The layout
  `(this, const char *key, int keyLen, const char *sign, int signLen)` is the one in cocos2d-x v3,
  3.17.2 and 4.x `CCLuaStack.cpp`, and the hook reads it correctly on real arm64 hardware (recovered
  key and signature from every fixture where the symbol was findable). Forks or older engines with
  other overloads are unchecked, and the C-string fallback is only covered by the Node stub.
- [ ] **Frida: vtable fallback when the key setter is stripped.** `LuaStack::setXXTEAKeyAndSign`
  appears to sit at virtual slot 29 (`vtable + 0x74` on 32-bit, `+ 0xe8` on arm64 — the same index
  on both, which is what makes it believable). Reaching it via `LuaEngine::getInstance` /
  `getLuaStack` would cover a lib where those survive stripping but the setter doesn't. The slot
  index is version-specific and a wrong guess silently hooks some other method, so gate it on the
  captured arguments looking like a key before trusting them.
- [ ] **Frida: LuaJIT's `lib_package` bytecode path is skipped.** `lib_package.c` loads embedded
  bytecode as `luaL_loadbuffer(L, bcdata, ~(size_t)0, name)`, the length deliberately unknown
  because LuaJIT bytecode is self-delimiting. `MAX_CHUNK_LEN` rejects it, so the chunk is dropped
  (verified on a device: no crash, no dump). Harmless for Cocos games, whose scripts go through
  `LuaStack`, but it would need the bytecode header parsed to recover the length.

## Lua: missing features

- [ ] **Script bundles: the encrypted ones under an unusual name.** Bundles are unpacked now (plain
  zips, zips encrypted whole, and entries encrypted inside either), and an encrypted one with any
  extension is found by the script signature. What that can't do is find one when nothing teaches
  the signature: no `--sign`, and fewer than two scripts found by name to detect it from. The
  Frida race's static worker also stops at "No .jsc / .luac / .lua files found" before the
  signature scan gets a chance, so such a game needs `--static-only` with `--sign`.
- [ ] **radare2 fallback for stripped Lua libraries.** `DECRYPT_FAIL_NEEDLES` and `EVAL_STRING_NEEDLES`
  in `r2.py` are JS-only strings, so the heavy analysis can't locate `xxtea_decrypt` or the loader in a
  stripped `libcocos2dlua.so`. Find Lua-side strings to anchor on. The symbol search is JS-only too:
  `resolve_frida_targets` only matches `ScriptEngine`/`ScriptingCore` `evalString` for `dump_off`,
  never `luaL_loadbufferx`. Not urgent — the agent resolves the Lua loader itself from the export and
  symbol tables — but a stripped lib needs the offset precomputed, like the JS path already does.

## General

- [ ] **Tests for what isn't covered yet.** `find_key_function` and `find_string_xref_function`
  in `r2.py`, which need a library carrying the needle strings and realistic call graphs, and
  `decompile.py` against the real decompilers rather than stand-ins (it skips them unless
  `$UNLUAC_JAR` / `$LUAJIT_DECOMPILER` are set).
