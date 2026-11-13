# TODO

Open work, mostly for the Lua support added on the `lua-support` branch.

## Lua: verify against real games

- [ ] **Run on a real *encrypted* Cocos2d-x Lua APK.** A shipped game has now been run end to end
  (Happy Teen Patti 1005, arm64 LuaJIT 2.1 GC64, on a Pixel 7 / Android 13): the loader hook
  resolved both `luaL_loadbuffer` entry points through `do_dlopen` and dumped 508 chunks
  **byte-identical to the offline extraction of the same APK**, the key hook captured the game's
  XXTEA key, and the race, `--static-only`, `--key` and `--decompile`'s routing all behaved. It
  cost two fixes, both in the changelog: a real bundle's entries are module names with no
  extension, and a game can ship one bundle per ABI.
  That game ships its scripts unencrypted, so the key-dependent half is still unverified on a real
  build: `recover_key_and_sign_static`'s tiers against a shipped `libcocos2dlua.so`,
  `verify_captured_key` against real encrypted scripts, and a signature learned from a real game's
  assets rather than a fixture's. The key this game did hand over decrypts none of its assets
  (they aren't signed), so it proves the hook, not the pipeline behind it.
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
  Narrower than it was: a *plain* zip under any name is now identified by what its entries hold,
  whatever they are called, so only a bundle encrypted as a whole under an unusual name still
  needs the signature supplied.
- [ ] **A pair of encrypted bundles, one per ABI, still collapses to one arch.** Two plain zips
  holding the same module names compiled for different word sizes now keep both copies, each under
  its bundle's path. Encrypted ones (`game32.bin` / `game64.bin`) don't: each is decrypted and
  written on its own in the main asset loop, so `_write_bundle` never learns that another bundle
  carries the same names, and the second copy hits `write_output`'s "already there" check and is
  skipped — one arch written, no warning (verified). The clash check wants to sit where entry names
  become output paths, which both bundle paths funnel through, rather than in the plain-zip
  flattener alone; `_write_bundle` would have to be given the bundle's own path to namespace with.
  Worth doing with the deduplication of `SKIPPED`, which now means both "a live dump already won"
  and "another bundle got there first".
- [ ] **radare2 fallback for stripped Lua libraries.** `DECRYPT_FAIL_NEEDLES` and `EVAL_STRING_NEEDLES`
  in `r2.py` are JS-only strings, so the heavy analysis can't locate `xxtea_decrypt` or the loader in a
  stripped `libcocos2dlua.so`. Find Lua-side strings to anchor on. The symbol search is JS-only too:
  `resolve_frida_targets` only matches `ScriptEngine`/`ScriptingCore` `evalString` for `dump_off`,
  never `luaL_loadbufferx`. Not urgent — the agent resolves the Lua loader itself from the export and
  symbol tables — but a stripped lib needs the offset precomputed, like the JS path already does.

## General

- [ ] **Tests for what isn't covered yet.** `pretty.py` (the jsbeautifier pass) and `log.py` have
  none at all. In `__main__.py`, `main()` is driven end to end for the offline cases
  (`tests/test_decompile.py::TestCli`, including `--apk --key --decompile`), but the static/Frida
  race is not: it wants a fake Frida track and a fake static track racing under a deterministic
  clock, so that which track wins, the abort of the loser, and the key verification that follows
  are all decided by the test rather than by timing.
