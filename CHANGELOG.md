# Changelog

All notable changes to coconuts are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Cocos2d-x Lua games: `.luac` (and `.lua`) scripts are decrypted with the
  same Cocos XXTEA as `.jsc`. Lua source is written as `.lua`; compiled Lua /
  LuaJIT bytecode stays `.luac`. Scripts shipped unencrypted are copied as-is
  without needing a key. Not yet tested against a real Lua game.
- `libcocos2dlua.so` is recognised as an engine library (default name when
  reading it from the APK, and `Cocos2dxLuaJavaBridge` as its JNI marker).
- Static key search: `main.lua` is an extra Tier 1 anchor.
- Frida: hooks `LuaStack::setXXTEAKeyAndSign` for the key (and logs the
  signature), and `luaL_loadbufferx` / `luaL_loadbuffer` for live Lua dumps.
- Compiled Lua chunks are identified from their header — PUC Lua 5.1–5.4 vs
  LuaJIT 2.0/2.1, with bitness, endianness and whether debug info was stripped
  — and a run reports the flavours it wrote along with the decompiler that
  opens them (`unluac` or `luajit-decompiler-v2`).

### Changed
- When no key works, the untouched scripts go to `raw_scripts/` instead of
  `raw_jsc/`, and log messages say "script(s)" instead of ".jsc".
- Frida agent: each symbol table is read once per library instead of up to
  nine times, all of it inside the linker's `dlopen` on the game's main
  thread. The `evalString` and `luaL_loadbuffer` hooks are now resolved
  independently, so a Lua library whose `evalString` offset was pre-resolved
  by radare2 no longer loses its Lua dump hook. Repeated loads of the same
  chunk are dropped in the agent rather than re-sent over USB, and a changed
  body at the same path still gets through.
- Frida agent: nothing throws out of a hook or out of installation any more.
  A stripped linker falls back to `android_dlopen_ext` / `dlopen` and then to
  polling, instead of aborting the agent (which previously also skipped the
  already-loaded-library scan); a library whose JNI bridge symbol is missing
  is still matched by name when hooks actually attach.
- "Saved N live script dump(s)" counts distinct files, not writes.
- The three offline write loops share one `write_output` helper, which also
  reports a failed write instead of letting it abort the run.

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

[Unreleased]: https://codeberg.org/davidjosearaujo/coconuts/compare/v1.1.0...HEAD
[1.1.0]: https://codeberg.org/davidjosearaujo/coconuts/compare/v1.0.0...v1.1.0
[1.0.0]: https://codeberg.org/davidjosearaujo/coconuts/releases/tag/v1.0.0
