# Changelog

All notable changes to coconuts are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Verified against real games

**Happy Teen Patti 1005** (arm64, LuaJIT 2.1 GC64) on a Pixel 7 / Android 13.
The Frida side came through intact: the loader hook resolved `luaL_loadbuffer`
and `luaL_loadbufferx` from the export table through `do_dlopen`, and **all 508
chunks it dumped are byte-identical to the ones extracted from the APK offline**
— chunk capture, the unknown-length walk and the module-name output all agreeing
with ground truth. The key hook captured an XXTEA key even though this game's
scripts aren't encrypted, so that key belongs to its other assets.

**An encrypted Cocos2d-x Lua game** (`com.ksrgland.goat`, `libcocos2dlua.so`,
40 MB, NDK r21e, 4265 `.luac` under signature `LAKYSIGN`) covered the half the
first game couldn't, spawned on the same Pixel 7. End to end:

- `choose_signature` learns `LAKYSIGN` from the game's own assets, no `--sign`.
- The key hook captured the game's XXTEA key at runtime, and
  `verify_captured_key` confirmed it against real encrypted scripts before it was
  trusted.
- The offline pass then decrypted **4078 of 4079** encrypted assets, 1758 live
  dumps arrived alongside, and nothing was left in `raw_scripts/`.
- Decrypting the APK independently with the captured key and diffing against the
  live dumps: **4265 of 4265 byte-identical, none differing.** What the tool
  produces offline is exactly what the running game loaded.

It also showed a game the static search cannot solve, and shouldn't pretend to:
`setXXTEAKeyAndSign` is exported, but `LAKYSIGN` appears nowhere in the engine
library, nor in any of the APK's 2422 `.so`/`.dex`/`.lua`/`.json`/`.xml` entries.
The key is assembled at runtime, so both static tiers return `None` in seconds
rather than guessing or hanging — which is why the Frida track exists.

Four defects came out of the two games, all fixed below.

### Fixed

- **Translated Lua source was taken for ciphertext, and hid a whole game's
  signature.** `str.isprintable()` is false for every space but ASCII's and for
  the format characters that come with translated text, so a localisation table
  full of no-break spaces (6157 of them in one real game), zero-width spaces,
  ideographic spaces or a stray BOM was classed as encrypted. 71 of one game's
  600 sampled scripts landed on the wrong side. Because those files share no
  prefix with the genuinely encrypted ones, the signature every encrypted script
  carried stopped being detectable at all: `detect_signature_prefix` returned
  `b''` and nothing could be decrypted even given the right key. Unicode
  whitespace and format characters now count as text; control characters, which
  is what ciphertext decodes to when it decodes at all, still do not.
- **One odd file could hide a signature every other script carried.**
  `detect_signature_prefix` took the prefix common to *every* sample, so a single
  file carrying no signature — an unencrypted chunk, a localisation table —
  reduced it to nothing, and without the signature even the right key decrypts
  nothing. The prefix now comes from the samples that agree, with a clear
  majority required so a few coincidentally alike resources can't invent one, and
  samples that are recognisably some other format are set aside first rather than
  the whole search giving up because the one it looked at first was a plain chunk.

- **A real bundle's entries were all dropped, reporting no scripts at all.**
  `loadChunksFromZIP` registers each entry under its own name with the extension
  stripped, so a real bundle holds module names (`app.config.ConstantsConfig`)
  with no extension, and collection kept only entries ending in `.jsc` / `.luac`
  / `.lua`. Every entry of the game's 508-script `game64.zip` therefore failed
  the filter, the zip was taken for a resource pack, and both the offline run and
  the race's static worker ended at "No .jsc / .luac / .lua files found" on a
  game whose scripts aren't even encrypted. Entries are now recognised by content
  as well as by name, and one recognised entry makes the whole zip a bundle — so
  entries encrypted inside it, which start with a signature rather than anything
  recognisable, come along too. A zip with no script in it is still a resource
  pack, and only its entries' first four bytes are ever read.
- **A game shipping one plain bundle per ABI silently lost one arch.**
  `game32.zip` and `game64.zip` hold the same module names compiled for a
  different word size, and whichever bundle was read second had all of its entries
  dropped as duplicates: the run then wrote 32-bit bytecode for a 64-bit device
  without saying so. Each copy is now kept under its own bundle's path
  (`res/game64/app.MyApp.luac`) when the bytes differ, identical copies are still
  written once, and the flavour report names both. Bundles encrypted *as a whole*
  (`game32.bin` / `game64.bin`) now keep both copies too: they are only a pair
  once both have been decrypted, so they are collected during the decrypt pass and
  written after it, where the clash can be seen. One rule resolves the names for
  every bundle, plain or encrypted, and an entry whose name is already taken by
  different bytes — by a live dump, or by a bundle the other pass flattened — is
  kept under its own bundle instead of disappearing into "already there".
- `output_name` puts a `.luac` on a decrypted Lua chunk whose name says nothing,
  the way it already named SpiderMonkey bytecode `.mozjs.jsc`, and
  `is_plain_script` judges a file by what it holds rather than what it is called.
  Every entry of a bundle now comes along, chunks and resources alike, and judging
  those by name called a bundle's source modules and resources ciphertext: a
  bundle mixing compiled chunks with `.lua` source or a JSON resource failed the
  whole run with "No working key found" and dumped them to `raw_scripts/`, on a
  game with no encryption anywhere.

### Added

- **The signature can be worked out from the assets themselves.** When nothing
  teaches it — no `--sign`, nothing read out of the engine library, and fewer
  than two scripts found by name to detect a shared prefix from — a bundle
  encrypted as a whole under a name like `res/game.bin` used to be unfindable,
  because what gives it away is the signature and the signature was the thing
  missing. The scan is gated rather than a sweep: only assets whose first bytes
  match no format we recognise get a vote, and only a bounded number of those are
  read in full. A folder of textures can't elect its magic as the signature, the
  pass costs a 64-byte head per asset instead of a full pass over the APK, and a
  wrong guess costs a failed key check and nothing more.
- **The key setter can be reached through the LuaStack vtable when it is
  stripped.** `setXXTEAKeyAndSign` sits at vtable slot 29 (`+0xe8` with 64-bit
  pointers), and a real game strips it while still exporting
  `LuaEngine::getLuaStack` — the configuration this rescues. The agent hooks the
  *return* of `getLuaStack` and reads the slot out of the instance the game hands
  back, so `getInstance` is never called from the agent and the engine isn't
  constructed earlier than the game expects. A wrong slot would attach a
  trampoline to whatever virtual method is there, possibly in the game's hot
  path, so the vtable must live in the library, the slot must point into it, and
  the range must not be known to be non-executable; anything else is refused and
  nothing is attached. It is a fallback only, used when the symbol is absent.
- **radare2 can find the Lua loader in a library that hides it.** The heavy
  analysis only ever looked for `ScriptEngine`/`ScriptingCore evalString`, which a
  Lua engine does not have, so a lib with `luaL_loadbuffer` stripped from its
  symbol table left the agent nothing to hook. `find_lua_load_function` anchors on
  the `[LUA ERROR] load "%s", error: …` messages, which sit inside
  `LuaStack::luaLoadBuffer` — the one function that calls the loader — and then
  picks the loader out by call count: the logger is called once per way the load
  can fail, the loader exactly once. Measured against a shipped game, where
  `luaLoadBuffer` is 184 bytes and makes five calls, one to `luaL_loadbuffer` and
  four to `cocos2d::log`. Where that asymmetry doesn't hold the search declines
  rather than hooking the logger by mistake.
- The resolved Lua loader travels on its own channel (`__LUA_LOAD_OFFSET__`)
  rather than as `dump_off`. `dump_off` feeds the `evalString` handler, which
  reads a different argument layout, so passing the loader through it would have
  attached the wrong handler to it. It is a fallback only: where the symbols exist
  they name both entry points and the agent still hooks each.

## [2.1.0] - 2026-11-12

### Added

- **LuaJIT bytecode loaded with an unknown length is dumped.** LuaJIT's own
  `lib_package.c` loads embedded bytecode as `luaL_loadbuffer(L, bcdata,
  ~(size_t)0, name)`, because a dump carries its own end. The agent's sanity
  bound rejected that length and dropped the chunk; it now walks the dump
  (`lj_bcread.c`'s format: magic, version, ULEB128 flags, optional chunk name,
  then length-prefixed prototypes ending at a zero byte) to recover the length.
  Verified on a device against real LuaJIT bytecode, where the chunk the
  harness generates comes back at exactly its 35 bytes.
- **Lua script bundles are unpacked.** Many Lua games ship their scripts as
  one zip that `loadChunksFromZIP` registers as modules. A plain `.zip` now
  has its scripts read straight out of it, and one encrypted as a whole is
  decrypted and then unpacked. Entries that are themselves encrypted are
  decrypted too, so a plain zip of encrypted scripts still feeds the key
  search. An encrypted bundle with any other extension (`game.bin`) is found by
  the script signature, which has to be known: from `--sign`, or learned from
  scripts found by name. Only a zip holding scripts is unpacked; Creator's
  "zip compress" output is still saved as `.zip`.
- **The XOR known-plaintext attack knows compiled Lua.** It used to know only
  Cocos2d-js headers. PUC Lua 5.1 to 5.4 headers are checked against real
  bytecode, and LuaJIT's five-byte header recovers single-byte keys. How long a
  key it can see is bounded by how much plaintext it knows (README).
- `--decompile` has now been verified against the real luajit-decompiler-v2
  (the `Mar_24_2024` release `.exe`, run through Wine): all four LuaJIT 2.0 and
  2.1 fixtures, stripped and not, decompile and land where coconuts looks for
  them. Documented in the README.
- `r2.py`'s two heavy-analysis searches are tested at last: `find_string_xref_function`,
  against every needle the tool ships, and `find_key_function`, including the
  index rule, the two-xref tie-breaker, the short-function fallback and PLT
  resolution through the symbol table. They needed a library with the needle
  strings and realistic call graphs, which `fixtures/mkelf.py` now assembles —
  by hand, so the call order and the xref counts are exact rather than
  whatever a compiler decided. Each assertion was checked against a mutated
  `r2.py` to confirm it fails when the rule it describes changes.
- `--decompile` is now verified against both real decompilers: unluac (built
  from source with a JDK) for PUC Lua and luajit-decompiler-v2 under Wine for
  LuaJIT. Both reproduce the original source from unstripped bytecode. Set
  `$UNLUAC_JAR` and `$LUAJIT_DECOMPILER` to run those tests; they skip
  otherwise.
- Tests for the previously uncovered `aes.py`, `manifest.py` and `adb.py`, and
  for the string tiers and key search in `statickeys.py`. The builders for the
  two input shapes coconuts accepts (an APK zip, an unpacked directory) are
  shared from `conftest.py` instead of rewritten per test file.

### Changed

- `extract_offline` walks its inputs once. Script collection and the
  signature scan each built their own asset index, so an APK's central
  directory was parsed twice per run; they share one now, and
  `collect_script_entries` / `collect_signed_assets` take that index rather
  than reopening the inputs themselves.
- The `lua51_stripped` and `lua52_stripped` bytecode fixtures are gone. They
  were byte-for-byte copies of the unstripped ones: `string.dump` only grew its
  strip argument in 5.3, and earlier versions ignore the extra parameter rather
  than failing. The generator now says so instead of writing a duplicate, and
  stripped PUC bytecode is covered by 5.3 upwards.
- **Hot-updated Lua scripts land beside their packaged counterparts.** Their
  chunk names are absolute paths in the app's writable directory, which used to
  nest them under the output folder as `data/user/0/<package>/files/...`. That
  prefix is now dropped (`/data/user/N/`, `/data/data/`, and the
  external-storage equivalents).
- **AES mode streams its assets.** Every asset was read into memory before
  any was decrypted, which fails on a game with hundreds of megabytes of
  textures. Only the scripts, which the key is checked against, are held now;
  everything else is read, decrypted and written one file at a time.
- A decrypted zip that is already named `.zip` is no longer written as
  `.zip.zip`.

### Fixed

Three defects in the Frida agent, all found by running it on a Pixel 7
(Android 14, arm64) against real `libcocos2dlua.so` libraries built from Lua
5.1.5, Lua 5.3.6 and LuaJIT 2.1 sources. Each one silently disabled live script
dumping while the agent still reported healthy hooks.

- **Chunk names were read with a byte count, so nothing was ever dumped.**
  `readCString(size)` on Frida 17 reads `size` bytes regardless of the string's
  own length, and the NUL does not survive decoding, so the result cannot be
  trimmed back either: every chunk name arrived with around a thousand
  characters of trailing heap attached and was rejected by the name filter. The
  same read was used for `evalString` paths, `dlopen` library names and the
  key hook's C-string fallback. Names are now read up to the NUL and
  length-checked afterwards.
- **The loader hook attached to a lambda inside `do_dlopen`.** Android 14's
  `linker64` carries two symbols containing `do_dlopen` and lists the closure
  first, so the agent hooked that, reported success, and was never called — on
  a Pixel 7 this left no working loader hook at all. The mangled function is
  now preferred, and the public `android_dlopen_ext` / `dlopen` entry points
  are hooked as well, since attaching successfully is no proof of being on the
  call path.
- **LuaJIT engines dumped nothing.** `luaL_loadbuffer` and `luaL_loadbufferx`
  share a translation unit in LuaJIT, so at `-O2` the callee is inlined into
  the wrapper and the two are independent functions. `LuaStack::luaLoadBuffer`
  calls `luaL_loadbuffer`, so hooking only `luaL_loadbufferx` saw no chunks at
  all. Every loader symbol present is now hooked; where the two genuinely chain
  the existing content dedup drops the duplicate.

### Added

- `tests/fixtures/android/`: twelve real arm64 engine libraries (three Lua
  runtimes × four symbol shapes), the harness that builds them, and a script
  that drives the real agent against them on a device. `tests/fake_frida.js`
  now reproduces Frida's actual `readCString` semantics, and
  `tests/test_android_fixtures.py` also runs coconuts' radare2 path over real
  compiled libraries instead of only hand-built ELFs.

## [2.0.1] - 2026-11-11

### Fixed

- The signature the Frida hook sees with the XXTEA key is now kept and used.
  Before, it was logged but dropped, so a Frida-captured key was always paired
  with a signature guessed from a shared prefix. The captured signature is now
  tried first when the key is verified, falling back to the guess if it doesn't
  decrypt, and it is also used for the offline extraction that follows. `--sign`
  still wins over both.

## [2.0.0] - 2026-11-11

Cocos2d-x **Lua** support: `.luac` / `.lua` scripts alongside `.jsc`, the XXTEA
key and its signature read straight out of the engine library, and optional
decompilation of the bytecode that comes out.

### Breaking

- Scripts that no key decrypts are saved to `raw_scripts/` instead of
  `raw_jsc/`, and the messages around them say "script(s)" rather than ".jsc".
  Anything scripted against the old path needs updating.

### Added

- **Lua games.** `.luac` and `.lua` scripts are decrypted with the same Cocos
  XXTEA as `.jsc`. Decrypted Lua source is written as `.lua`, compiled chunks
  stay `.luac`, and scripts shipped unencrypted are copied as-is without
  needing a key. `libcocos2dlua.so` is recognised as an engine library, with
  `Cocos2dxLuaJavaBridge` as its JNI marker, and `main.lua` is an extra anchor
  for the static key search.
- **Key and signature read from the call site.** Lua games pass both to
  `LuaStack::setXXTEAKeyAndSign` from `applicationDidFinishLaunching`, and that
  call compiles to a recognisable arm64 shape, so both are decoded from the
  instructions -- what you would otherwise do by hand in Ghidra. The string
  tiers could only ever find the key: they collect every literal in that
  function and trial-decrypt them, so the signature still had to be guessed
  from a prefix shared by the encrypted files. Needs no radare2, and matches on
  the argument shape rather than the vtable offset, which varies by Cocos
  version. The pair is verified by trial decryption, so a wrong match simply
  falls back to the string tiers.
- **Compiled chunks are identified** from their header: PUC Lua 5.1-5.5 or
  LuaJIT 2.0/2.1, with bitness, endianness and whether debug info was stripped.
  A run reports what it wrote and which decompiler opens it.
- **`--decompile`** runs a decompiler over the output and writes
  `<name>.dec.lua` beside each chunk, keeping the `.luac`. Each chunk is routed
  by its own header, so a game mixing both formats works. The decompilers are
  GitHub projects rather than PyPI packages and none is bundled: point at them
  with `--unluac` / `--ljd` or `$UNLUAC_JAR` / `$LUAJIT_DECOMPILER`. A missing
  one is reported and the other still runs. The LuaJIT slot is not tied to one
  program -- any decompiler works that takes the input path last and either
  prints to stdout or leaves `<stem>.lua` behind. With no `PACKAGE` and no
  `--apk`, `--decompile` works over an existing output folder instead of
  dumping, so a run can be retried after installing a decompiler.
- **Frida** hooks `LuaStack::setXXTEAKeyAndSign` for the key, logging the
  signature passed with it, and `luaL_loadbufferx` / `luaL_loadbuffer` for live
  dumps of every chunk the game loads.
- **A test suite** in `tests/` (`pip install -e '.[dev]'`): ciphers, chunk
  identification and the offline paths over synthetic assets; the header parser
  against real bytecode from every PUC Lua and LuaJIT runtime; the Frida agent
  rendered through `build_frida_script()` and driven against a stubbed Frida
  runtime under Node. The radare2 and real-decompiler tests run when those
  tools are present and skip when they aren't.

### Changed

- **Frida agent.** Each symbol table is read once per library instead of up to
  nine times, all of it inside the linker's `dlopen` on the game's main thread.
  The `evalString` and `luaL_loadbuffer` hooks are resolved independently, so a
  Lua library whose `evalString` offset was pre-resolved by radare2 no longer
  loses its Lua dump hook. Repeated loads of the same chunk are dropped in the
  agent rather than re-sent over USB, while a changed body at the same path
  still gets through.
- **The agent no longer throws**, out of a hook or out of installation. A
  stripped linker falls back to `android_dlopen_ext` / `dlopen` and then to
  polling instead of aborting the agent -- which previously also skipped the
  scan for an already-loaded library, leaving a run with no hooks at all. A
  library whose JNI bridge symbol is missing is matched by name when hooks
  actually attach.
- "Saved N live script dump(s)" counts distinct files rather than writes.
- A failed write is reported instead of aborting the run.
- The engine library is scanned once per run rather than once per caller,
  script collection and signature precedence each live in one place instead of
  three, and the output directory is resolved once rather than once per file.

### Fixed

- **Tier 0 missed every string an arm64 build references**, which is nearly all
  of them. A string address is formed as `adrp` (4 KB page) + `add` (offset),
  and only the `adrp` carries radare2's `ptr`, so following it read whatever
  sat at the page boundary -- for the first page, the ELF header, which then
  entered the candidate list as a key. radare2 resolves the pair only after a
  full `aaa`, far too slow for this pass, so the halves are joined from what
  the cheap single-function analysis already reports.
- Binary data could be collected as a candidate key: `psz` escapes
  non-printable bytes, and the resulting `\x7fELF...` text passes
  `str.isprintable()`.

### Known limitations

- None of the Lua support has run against a real game yet; it is tested
  against synthetic assets, assembled arm64 libraries and real compiled Lua
  chunks. The Frida hooks in particular are unverified on a device.
- Script bundles shipped as one encrypted zip (`LuaStack::loadChunksFromZIP`,
  usually `game.zip` or `src.zip`) aren't collected yet.

## [1.1.0] - 2026-10-28

### Added
- `--pretty`: after the dump, reformat every `.js` file in the output folder
  in place with jsbeautifier, with a progress line per file. jsbeautifier is
  now a dependency.
- With `--apk`, `LIB` and `PACKAGE` are optional: the package name is read
  from the APK's binary `AndroidManifest.xml`, and the engine library
  (`lib/arm64-v8a/lib<name>.so`, named by `android.app.lib_name` when it isn't
  `libcocos.so` / `libcocos2djs.so`) is extracted from the APK.
- `--lib`, `--package` and `-o/--output` name the positionals explicitly; a
  lone positional is sorted by shape (`.so` path, dotted name, or output dir).

### Changed
- The engine library is streamed out of the APK instead of being read into
  memory whole.

### Fixed
- A broken link in the README.

## [1.0.0] - 2026-10-23

Initial release, a tool that recovers the script encryption key of Cocos2d-x /
Cocos Creator Android games and dumps their decrypted JavaScript.

### Added
- **Dual-track key recovery**: a static search of the arm64 engine library
  (`libcocos.so` / `libcocos2djs.so`) races a Frida hook on the running game;
  the first verified key wins and the other track is stopped.
- **Static key search**: an instant known-plaintext attack for repeating-key
  XOR, then ranked XXTEA candidates from the library: string literals in the
  key-setting functions (radare2), strings near Cocos boot anchors, common
  generated-key shapes, and every other printable token. Each candidate is
  test-decrypted against the smallest `.jsc` files before it's accepted.
- **Frida capture**: hook targets resolved with radare2 (symbols first, the
  `.data.rel.ro` slot on stripped builds, full analysis as a last resort);
  hooks on `xxtea_decrypt` / `setXXTeaKey` / `jsb_set_xxtea_key` capture the
  XXTEA key, and `EncryptManager::setEncryptEnabled` the AES key, IV and
  signature roll.
- **Live script dumps**: every script the engine evaluates (`evalString`) is
  written out, including hot-updated scripts that never appear in the APK.
- **Offline decryption** of Cocos XXTEA `.jsc` (with signature-prefix
  auto-detection), repeating-key XOR, and x-studio / axmol `EncryptManager`
  AES-256-CBC (every asset). Gzip and zip payloads are unpacked, SpiderMonkey
  bytecode is kept as `.mozjs.jsc`, and the raw `.jsc` files are saved when no
  key works.
- **Device handling**: adb device selection and APK pulling (config splits
  skipped by default), or local APKs and folders with `--apk`.
- **Packaging**: installable with `pipx`, exposing the `coconuts` command (also
  `python3 -m coconuts`).
- **Docs**: a README covering how it works, setup on macOS and on Linux/x86
  PCs, usage, output, troubleshooting and limitations; the MIT license and the
  coconut logo.

[Unreleased]: https://codeberg.org/davidjosearaujo/coconuts/compare/v2.1.0...HEAD
[2.1.0]: https://codeberg.org/davidjosearaujo/coconuts/compare/v2.0.1...v2.1.0
[2.0.1]: https://codeberg.org/davidjosearaujo/coconuts/compare/v2.0.0...v2.0.1
[2.0.0]: https://codeberg.org/davidjosearaujo/coconuts/compare/v1.1.0...v2.0.0
[1.1.0]: https://codeberg.org/davidjosearaujo/coconuts/compare/v1.0.0...v1.1.0
[1.0.0]: https://codeberg.org/davidjosearaujo/coconuts/releases/tag/v1.0.0
