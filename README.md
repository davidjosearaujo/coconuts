# coconuts

Dump and decrypt Cocos2d-x / Cocos Creator scripts and assets from an Android app.

`cocos-dumper.py` runs two tracks in parallel and uses whichever wins:

- **Static** — recovers the XXTEA key from strings in `libcocos.so` / `libcocos2djs.so` (radare2).
- **Dynamic** — spawns the app under Frida, hooks the engine to capture the key (and AES key/IV)
  at runtime and dump live (including hot-updated) scripts.

It then decrypts the assets offline. Supported schemes: Cocos **XXTEA**, repeating-key **XOR**, and
x-studio **EncryptManager AES-256-CBC**.

## Install

```sh
pipx install git+https://github.com/<you>/coconuts        # or: pipx install .
# or, for development:
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
```

`pipx` handles the Python dependencies. Three things it can't install, because they aren't Python
packages:

- **radare2** — needed for the static key search (`brew install radare2`). `r2pipe` is only the binding.
- **adb** — Android platform-tools; found on `PATH`, via `$ANDROID_HOME` / `$ANDROID_SDK_ROOT`, or the
  default SDK location. Not needed with `--apk`.
- **frida-server** — must be running as root on the device/emulator (dynamic track only).

Requires Python 3.9+ and an **arm64** target library.

## Usage

```sh
# Parallel static + Frida capture, then offline decryption of the APK assets
python3 cocos-dumper.py ./libcocos.so com.example.game ./out

# Keep collecting live (incl. hot-updated) scripts for 60s after the key is found
python3 cocos-dumper.py ./libcocos.so com.example.game ./out --live-seconds 60

# No Frida: recover the key from the lib's strings against a local APK or raw .jsc folder
python3 cocos-dumper.py ./libcocos.so com.example.game ./out --static-only --apk ./base.apk

# EncryptManager AES-CBC assets with a known key+iv
python3 cocos-dumper.py ./libcocos.so com.example.game ./out --apk ./base.apk \
    --aes-key <hex> --aes-iv <hex>
```

Run `python3 cocos-dumper.py --help` for all options.

## Status

Developed and tested against arm64 targets on Apple-silicon Macs with arm64 emulators.
