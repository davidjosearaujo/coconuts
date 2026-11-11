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
- [ ] **Use the signature the Frida hook captures.** The static path now reads the key and
  signature together from the `setXXTEAKeyAndSign` call site (`arm64.py`) and uses both, but the
  Frida hook still only logs the signature it sees: the dynamic track returns a key alone, so a
  Frida win still falls back to guessing the signature from a common prefix. Plumb it through
  `frida_dump` the way the static pair is plumbed through `extract_offline`.
- [ ] **radare2 fallback for stripped Lua libraries.** `DECRYPT_FAIL_NEEDLES` and `EVAL_STRING_NEEDLES`
  in `r2.py` are JS-only strings, so the heavy analysis can't locate `xxtea_decrypt` or the loader in a
  stripped `libcocos2dlua.so`. Find Lua-side strings to anchor on. The symbol search is JS-only too:
  `resolve_frida_targets` only matches `ScriptEngine`/`ScriptingCore` `evalString` for `dump_off`,
  never `luaL_loadbufferx`. Not urgent — the agent resolves the Lua loader itself from the export and
  symbol tables — but a stripped lib needs the offset precomputed, like the JS path already does.
- [x] **Bytecode decompilation (optional).** `--decompile` routes each chunk to unluac or
  luajit-decompiler-v2 by its header and writes `<name>.dec.lua` beside the bytecode. Verified
  end to end against a real unluac build over real bytecode from every PUC and LuaJIT runtime.
- [ ] **luajit-decompiler-v2 has never been run.** It's a Windows C++ program (`windows.h`,
  backslash includes, requires unsigned `char`) and doesn't compile on Linux, so the LuaJIT half of
  `--decompile` is still untested. Its README says output goes to `output/<name>.lua` beside the
  exe, which is what the pass expects, and `--ljd` runs an `.exe` through Wine. Confirm on Windows
  or under Wine, and check whether `-?` offers an output-path flag worth passing.
- [ ] **XOR known-plaintext attack for Lua.** It only knows JS headers. Add Lua plaintexts if a Lua
  engine with XOR encryption turns up.

## General

- [x] **Automated tests.** `tests/` now has a pytest suite over the ciphers, bytecode identification
  and the offline extraction paths (synthetic assets, as a directory and as an APK-shaped zip), plus
  the Frida agent driven against a stubbed Frida runtime under Node.
- [ ] **Tests for what isn't covered yet.** The rest of `statickeys.py` (the tiers themselves and
  the XOR known-plaintext attack), `aes.py` / the EncryptManager path, `manifest.py`
  (engine-library pick, ABI ranking), and `adb.py`. `decompile.py` is covered with stand-in
  decompilers, never the real ones. `r2.py` and Tier 0 now have tests that run when radare2 is
  installed; `find_key_function` and `find_string_xref_function` still don't, since they need a
  library carrying the needle strings and realistic call graphs.
