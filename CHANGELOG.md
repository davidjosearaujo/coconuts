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

### Changed
- When no key works, the untouched scripts go to `raw_scripts/` instead of
  `raw_jsc/`, and log messages say "script(s)" instead of ".jsc".

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
