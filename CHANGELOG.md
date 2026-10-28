# Changelog

All notable changes to coconuts are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--pretty`: after the dump, reformat every `.js` file in the output folder
  in place with jsbeautifier, with a progress line per file. jsbeautifier is
  now a dependency.

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

[Unreleased]: https://codeberg.org/davidjosearaujo/coconuts/compare/v1.0.0...HEAD
[1.0.0]: https://codeberg.org/davidjosearaujo/coconuts/releases/tag/v1.0.0
