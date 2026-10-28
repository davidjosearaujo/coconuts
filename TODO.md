# TODO

Open work, mostly for the Lua support added on the `lua-support` branch.

## Lua: verify against real games

- [ ] **Run on a real Cocos2d-x Lua APK.** So far everything was tested with synthetic files only.
  Check `--static-only`, `--key`, and the full static + Frida race.
- [ ] **Frida: `LuaStack::setXXTEAKeyAndSign` hook.** It assumes
  `(this, const char *key, int keyLen, const char *sign, int signLen)`, falling back to C strings when
  the length slot isn't plausible. Check the real argument layout across Cocos2d-x versions (3.x, 4.x)
  and any overloads.
- [ ] **Frida: `luaL_loadbufferx` / `luaL_loadbuffer` hook.** Check that the symbols can be found (exported
  or in the symbol table), that the hook sees decrypted chunks, and what the chunk names look like
  on Android (`@src/...`, `assets/...`, module names from zip bundles).
- [ ] **Frida: hot-updated Lua scripts.** Their chunk names are probably absolute paths in the app's
  writable directory (`/data/data/<pkg>/files/...`), which currently end up nested under the output
  folder. Strip that prefix once the real format is known.
- [ ] **Agent syntax check with `node --check`.** It was only parsed with a Python JS parser, since
  Node wasn't available.

## Lua: missing features

- [ ] **Zipped script bundles.** Many Lua games ship their scripts as one encrypted zip (often
  `game.zip` / `src.zip`, under any extension), loaded with `LuaStack::loadChunksFromZIP`. Collect
  those assets, decrypt them with the same key and signature, and unpack the entries into the output
  folder (the entries can themselves be plain or encrypted).
- [ ] **Use the captured signature.** The Lua Frida hook logs the signature passed with the key, but
  decryption still relies on auto-detection. Use it as the signature when `--sign` isn't given.
- [ ] **radare2 fallback for stripped Lua libraries.** `DECRYPT_FAIL_NEEDLES` and `EVAL_STRING_NEEDLES`
  in `r2.py` are JS-only strings, so the heavy analysis can't locate `xxtea_decrypt` or the loader in a
  stripped `libcocos2dlua.so`. Find Lua-side strings to anchor on.
- [ ] **Bytecode decompilation (optional).** Decrypted `.luac` bytecode is written as-is. An optional
  step could call unluac (PUC Lua) or luajit-decompiler-v2 (LuaJIT) when they're installed.
- [ ] **XOR known-plaintext attack for Lua.** It only knows JS headers. Add Lua plaintexts if a Lua
  engine with XOR encryption turns up.

## General

- [ ] **Automated tests.** Turn the synthetic fixtures (XXTEA-encrypted JS and Lua scripts, unencrypted
  Lua, a fake engine library, a zipped fake APK) into a pytest suite.
