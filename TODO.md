# TODO

Open work, mostly for the Lua support added on the `lua-support` branch.

## Lua: verify against real games

- [ ] **Run on a real Cocos2d-x Lua APK.** The Frida side is no longer synthetic: the loader and
  key hooks are verified on a Pixel 7 against real arm64 engine libraries built from real Lua /
  LuaJIT sources (`tests/fixtures/android/`). What is still untested is a *shipped* game — the
  APK-side paths (`--static-only`, `--key`, the full static + Frida race, assets collected from a
  real `assets/` tree) and whatever a real build does differently from Cocos's upstream source.
- [ ] **Frida: `LuaStack::setXXTEAKeyAndSign` hook.** The assumed layout
  `(this, const char *key, int keyLen, const char *sign, int signLen)` is the one in cocos2d-x v3
  and 3.17.2 `CCLuaStack.cpp`, and the hook reads it correctly on real arm64 hardware: against the
  `tests/fixtures/android/` libraries on a Pixel 7 it recovered both key and signature from every
  runtime and variant where the symbol was findable. What is still unchecked is Cocos2d-x **4.x**
  and any overloads, and the C-string fallback is still only covered by the Node stub — note that
  the fallback was in fact broken on a device until the `readCString` fix, since it read the key
  with a byte count too.
- [ ] **Frida: vtable fallback when the key setter is stripped.** `LuaStack::setXXTEAKeyAndSign`
  appears to sit at virtual slot 29 (`vtable + 0x74` on 32-bit, `+ 0xe8` on arm64 — the same index
  on both, which is what makes it believable). Reaching it via `LuaEngine::getInstance` /
  `getLuaStack` would cover a lib where those survive stripping but the setter doesn't. The slot
  index is version-specific and a wrong guess silently hooks some other method, so gate it on the
  captured arguments looking like a key before trusting them.
- [ ] **Frida: hot-updated Lua scripts.** Confirmed: a chunk name can be an absolute path, and
  the agent dumps it under the output folder as `data/user/0/<pkg>/files/src/hot.lua` (verified on
  a device with exactly that name). Still worth stripping the writable-dir prefix so a hot-updated
  script lands beside its packaged counterpart instead of in a `data/user/0/...` subtree.
- [ ] **Frida: LuaJIT's `lib_package` bytecode path is skipped.** `lib_package.c` loads embedded
  bytecode as `luaL_loadbuffer(L, bcdata, ~(size_t)0, name)`, the length deliberately unknown
  because LuaJIT bytecode is self-delimiting. `MAX_CHUNK_LEN` rejects it, so the chunk is dropped
  (verified on a device: no crash, no dump). Harmless for Cocos games, whose scripts go through
  `LuaStack`, but it would need the bytecode header parsed to recover the length.

## Lua: missing features

- [ ] **Zipped script bundles.** Many Lua games ship their scripts as one encrypted zip (often
  `game.zip` / `src.zip`, under any extension), loaded with `LuaStack::loadChunksFromZIP`. Collect
  those assets, decrypt them with the same key and signature, and unpack the entries into the output
  folder (the entries can themselves be plain or encrypted).
- [ ] **radare2 fallback for stripped Lua libraries.** `DECRYPT_FAIL_NEEDLES` and `EVAL_STRING_NEEDLES`
  in `r2.py` are JS-only strings, so the heavy analysis can't locate `xxtea_decrypt` or the loader in a
  stripped `libcocos2dlua.so`. Find Lua-side strings to anchor on. The symbol search is JS-only too:
  `resolve_frida_targets` only matches `ScriptEngine`/`ScriptingCore` `evalString` for `dump_off`,
  never `luaL_loadbufferx`. Not urgent — the agent resolves the Lua loader itself from the export and
  symbol tables — but a stripped lib needs the offset precomputed, like the JS path already does.
- [ ] **luajit-decompiler-v2 itself has never been run.** It's a Windows C++ program (`windows.h`,
  backslash includes, requires unsigned `char`) and doesn't compile on Linux. The LuaJIT half of
  `--decompile` is verified against ljd instead, which is pure Python; v2's own README says its
  output goes to `output/<name>.lua` beside the exe, which is what the pass expects, and `--ljd`
  runs an `.exe` through Wine. Worth confirming on Windows if anyone wants v2's better output.
- [ ] **XOR known-plaintext attack for Lua.** It only knows JS headers. Add Lua plaintexts if a Lua
  engine with XOR encryption turns up.

## General

- [ ] **AES mode buffers every asset in memory.** `collect_asset_entries` reads all of `assets/`
  into a dict before decrypting, because EncryptManager wraps every asset type, not just scripts.
  That is fine for a script-only APK and not for a game with hundreds of MB of textures. Stream
  each entry through the decrypt-and-write step instead of collecting first.
- [ ] **Tests for what isn't covered yet.** The rest of `statickeys.py` (the tiers themselves and
  the XOR known-plaintext attack), `aes.py` / the EncryptManager path, `manifest.py`
  (engine-library pick, ABI ranking), and `adb.py`. `decompile.py` is covered with stand-in
  decompilers, never the real ones. `r2.py` and Tier 0 now have tests that run when radare2 is
  installed, and `test_android_fixtures.py` runs `r2_open_and_analyse` / `resolve_frida_targets`
  over real compiled arm64 libraries rather than hand-built ELFs; `find_key_function` and
  `find_string_xref_function` still aren't covered, since they need a library carrying the needle
  strings and realistic call graphs.
