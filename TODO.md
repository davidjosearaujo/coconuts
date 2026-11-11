# TODO

Open work, mostly for the Lua support added on the `lua-support` branch.

## Lua: verify against real games

- [ ] **Run on a real Cocos2d-x Lua APK.** So far everything was tested with synthetic files only.
  Check `--static-only`, `--key`, and the full static + Frida race.
- [ ] **Frida: `LuaStack::setXXTEAKeyAndSign` hook.** It assumes
  `(this, const char *key, int keyLen, const char *sign, int signLen)`, falling back to C strings when
  the length slot isn't plausible. Check the real argument layout across Cocos2d-x versions (3.x, 4.x)
  and any overloads. A published arm64 hook agrees with this layout (key at arg1/len arg2, sign at
  arg3/len arg4), so the assumption looks right; still unverified on a real device.
- [ ] **Frida: vtable fallback when the key setter is stripped.** `LuaStack::setXXTEAKeyAndSign`
  appears to sit at virtual slot 29 (`vtable + 0x74` on 32-bit, `+ 0xe8` on arm64 — the same index
  on both, which is what makes it believable). Reaching it via `LuaEngine::getInstance` /
  `getLuaStack` would cover a lib where those survive stripping but the setter doesn't. The slot
  index is version-specific and a wrong guess silently hooks some other method, so gate it on the
  captured arguments looking like a key before trusting them.
- [ ] **Frida: `luaL_loadbufferx` / `luaL_loadbuffer` hook.** Check that the symbols can be found (exported
  or in the symbol table), that the hook sees decrypted chunks, and what the chunk names look like
  on Android (`@src/...`, `assets/...`, module names from zip bundles).
- [ ] **Frida: hot-updated Lua scripts.** Their chunk names are probably absolute paths in the app's
  writable directory (`/data/data/<pkg>/files/...`), which currently end up nested under the output
  folder. Strip that prefix once the real format is known.
- [x] **Agent syntax check with `node --check`.** Done, and the agent now also runs against a Frida
  stub in Node (fake module/export tables, a flat memory space) covering installation, key capture,
  chunk dedup, degenerate hook arguments and the loader fallbacks. Worth committing as a test.

## Lua: missing features

- [ ] **Zipped script bundles.** Many Lua games ship their scripts as one encrypted zip (often
  `game.zip` / `src.zip`, under any extension), loaded with `LuaStack::loadChunksFromZIP`. Collect
  those assets, decrypt them with the same key and signature, and unpack the entries into the output
  folder (the entries can themselves be plain or encrypted).
- [ ] **Use the captured signature.** The Lua Frida hook logs the signature passed with the key, but
  decryption still relies on auto-detection. Use it as the signature when `--sign` isn't given.
- [ ] **radare2 fallback for stripped Lua libraries.** `DECRYPT_FAIL_NEEDLES` and `EVAL_STRING_NEEDLES`
  in `r2.py` are JS-only strings, so the heavy analysis can't locate `xxtea_decrypt` or the loader in a
  stripped `libcocos2dlua.so`. Find Lua-side strings to anchor on. The symbol search is JS-only too:
  `resolve_frida_targets` only matches `ScriptEngine`/`ScriptingCore` `evalString` for `dump_off`,
  never `luaL_loadbufferx`. Not urgent — the agent resolves the Lua loader itself from the export and
  symbol tables — but a stripped lib needs the offset precomputed, like the JS path already does.
- [ ] **Bytecode decompilation (optional).** Decrypted `.luac` bytecode is written as-is. The flavour
  is now detected and reported (`describe_lua_bytecode` in `ciphers.py`), so what's left is an
  optional step that shells out to unluac (PUC Lua) or luajit-decompiler-v2 (LuaJIT) when installed.
  Expect LuaJIT in practice: `cocos luacompile` goes through it on Android, and emits separate
  32-bit and 64-bit (GC64) bytecode, so one APK can ship two incompatible variants of a script.
  Two known failure modes to handle rather than crash on: stripped debug info (normal here — control
  flow still recovers, names don't), and a LuaJIT with a patched opcode table, which some games ship
  precisely to break stock decompilers and which can only be fixed by recovering the table from the
  game's own `libcocos2dlua.so`.
- [ ] **XOR known-plaintext attack for Lua.** It only knows JS headers. Add Lua plaintexts if a Lua
  engine with XOR encryption turns up.

## General

- [x] **Automated tests.** `tests/` now has a pytest suite over the ciphers, bytecode identification
  and the offline extraction paths (synthetic assets, as a directory and as an APK-shaped zip), plus
  the Frida agent driven against a stubbed Frida runtime under Node.
- [ ] **Tests for what isn't covered yet.** `statickeys.py` (the tiered search and the XOR
  known-plaintext attack), `aes.py` / the EncryptManager path, `manifest.py` (engine-library pick,
  ABI ranking), and `adb.py`. `r2.py` needs radare2, so it probably stays manual.
