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
  3.17.2 and 4.x `CCLuaStack.cpp`, and the hook reads it correctly on real arm64 hardware, both
  with real lengths and with the lengths passed as 0, where it falls back to reading NUL-terminated
  strings (`HARNESS_ZERO_LEN_KEY=1` in the fixture harness). What is still unchecked is a fork
  declaring a different overload; there is none in upstream Cocos.
- [ ] **Frida: vtable fallback when the key setter is stripped.** The slot index is no longer a
  guess: `cocos2d::Ref` declares exactly one virtual member (its destructor), and `LuaStack`
  declares 30 more in a fixed order, which puts `setXXTEAKeyAndSign` at **slot 29** — `+0x74` with
  32-bit pointers, `+0xe8` with 64-bit ones, after the two destructor entries the Itanium ABI
  emits. Derived from cocos2d-x v3/4.x `CCLuaStack.h` and confirmed by clang on arm64: the fixture
  libraries transcribe that virtual list and the engine reports the slot it actually landed in
  (`setXXTEAKeyAndSign is vtable slot 29 (+0xe8 ...)`).
  Still not implemented, for two reasons worth weighing first. The symbols needed to reach the
  vtable (`LuaEngine::getInstance` / `getLuaStack`) are exported under the same visibility rules as
  the setter itself, so they tend to be present or absent together — in the fixture matrix the
  hidden variants lose all of them at once, which is the case this was meant to rescue. And a wrong
  index does not merely miss the key: it attaches a trampoline to whatever virtual method is at
  that slot, which may be `pushInt` in the game's hot path, with a callback that reads key bytes
  out of unrelated arguments. Gating on the arguments looking like a key keeps a bad key from being
  reported but does not undo the hook. If it is built, hooking the *return* of `getLuaStack` and
  reading the vtable from the instance it hands back avoids calling `getInstance` from the agent,
  which would otherwise construct the engine earlier than the game expects.

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
