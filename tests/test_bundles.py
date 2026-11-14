"""Script bundles: the zip Lua games register with LuaStack::loadChunksFromZIP.

A bundle can be a plain zip, a zip encrypted as a whole, or either of those holding entries that
are encrypted themselves; it can be called game.zip or game.bin. Each case is built both as a
directory tree and as an APK-shaped zip, since the two are read by different code.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coconuts.extract import collect_scripts, extract_offline

from .conftest import (
    LUA_SOURCE,
    LUAJIT_CHUNK,
    PUC_CHUNK,
    SIGN,
    asset_source,
    encrypt_asset,
    make_zip,
)


def run(tmp_path: Path, kind: str, assets: dict[str, bytes], key: bytes | None,
        **kw) -> tuple[Path, int]:
    out = tmp_path / "out"
    return out, extract_offline([asset_source(tmp_path, kind, assets)], key, None, str(out), **kw)


class TestPlainBundle:
    def test_scripts_are_unpacked_without_a_key(self, tmp_path: Path, kind: str) -> None:
        bundle = make_zip({"src/main.lua": LUA_SOURCE, "src/app/MyApp.luac": PUC_CHUNK})
        out, written = run(tmp_path, kind, {"game.zip": bundle}, None)
        assert written == 2
        assert (out / "src/main.lua").read_bytes() == LUA_SOURCE
        assert (out / "src/app/MyApp.luac").read_bytes() == PUC_CHUNK
        assert not (out / "game.zip").exists()

    def test_encrypted_entries_are_decrypted(self, tmp_path: Path, kind: str, key: bytes) -> None:
        bundle = make_zip({"src/main.luac": encrypt_asset(LUAJIT_CHUNK),
                           "src/plain.lua": LUA_SOURCE})
        out, written = run(tmp_path, kind, {"game.zip": bundle}, key, forced_sign=SIGN)
        assert written == 2
        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "src/plain.lua").read_bytes() == LUA_SOURCE

    def test_entries_count_as_samples_for_the_key(self, tmp_path: Path, kind: str) -> None:
        """A wrong key must not be accepted just because the only encrypted files are in a zip."""
        from coconuts.ciphers import normalize_key
        bundle = make_zip({"src/main.luac": encrypt_asset(LUAJIT_CHUNK)})
        out, written = run(tmp_path, kind, {"game.zip": bundle}, normalize_key(b"wrong"))
        assert written == 0
        assert not (out / "src/main.lua").exists()

    def test_a_resource_pack_is_left_alone(self, tmp_path: Path, kind: str) -> None:
        pack = make_zip({"img/logo.png": b"\x89PNG", "data/levels.json": b"{}"})
        out, written = run(tmp_path, kind, {"textures.zip": pack}, None)
        assert written == 0
        assert not out.exists() or not list(out.rglob("*")), "nothing should be written"

    def test_a_script_beside_a_bundle_wins_over_its_copy(self, tmp_path: Path, kind: str) -> None:
        bundle = make_zip({"src/main.lua": b"-- from the bundle"})
        assets = {"game.zip": bundle, "src/main.lua": LUA_SOURCE}
        entries = collect_scripts([asset_source(tmp_path, kind, assets)])
        assert entries["src/main.lua"] == LUA_SOURCE

    def test_traversal_in_an_entry_name_is_refused(self, tmp_path: Path, kind: str) -> None:
        bundle = make_zip({"../../evil.lua": LUA_SOURCE, "ok.lua": LUA_SOURCE})
        out, written = run(tmp_path, kind, {"game.zip": bundle}, None)
        assert (out / "ok.lua").exists()
        assert not (tmp_path / "evil.lua").exists()
        assert not (tmp_path.parent / "evil.lua").exists()


class TestModuleNameEntries:
    """loadChunksFromZIP registers each entry under its name with the extension stripped, so a
    real bundle's entries are module names ('app.config.ConstantsConfig') carrying no extension.

    Shape taken from a shipped game (Cocos2d-x Lua, LuaJIT 2.1): 508 such entries in game64.zip,
    which the extension-only collector used to drop whole, reporting no scripts at all.
    """

    def test_an_extensionless_entry_is_found_by_its_content(self, tmp_path: Path, kind: str) -> None:
        bundle = make_zip({"app.config.ConstantsConfig": LUAJIT_CHUNK,
                           "app.views.MainScene": PUC_CHUNK})
        out, written = run(tmp_path, kind, {"game64.zip": bundle}, None)
        assert written == 2
        # The extension is put back from what the entry holds, so it lands where a live Frida
        # dump of the same chunk would (lua_live_name gives the same name).
        assert (out / "app.config.ConstantsConfig.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "app.views.MainScene.luac").read_bytes() == PUC_CHUNK

    def test_an_encrypted_extensionless_entry_is_decrypted(self, tmp_path: Path, kind: str,
                                                           key: bytes) -> None:
        bundle = make_zip({"app.MyApp": encrypt_asset(LUAJIT_CHUNK), "app.plain": PUC_CHUNK})
        out, written = run(tmp_path, kind, {"game.zip": bundle}, key, forced_sign=SIGN)
        assert written == 2
        assert (out / "app.MyApp.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "app.plain.luac").read_bytes() == PUC_CHUNK

    def test_inside_a_bundle_that_is_itself_encrypted(self, tmp_path: Path, kind: str,
                                                      key: bytes) -> None:
        bundle = encrypt_asset(make_zip({"app.MyApp": LUAJIT_CHUNK, "res.config": b'{"a": 1}'}))
        out, written = run(tmp_path, kind, {"src.zip": bundle}, key, forced_sign=SIGN)
        assert (out / "app.MyApp.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "res.config").read_bytes() == b'{"a": 1}'  # a resource keeps its own name

    def test_a_bundle_mixing_chunks_resources_and_source_needs_no_key(self, tmp_path: Path,
                                                                      kind: str) -> None:
        """Every entry of a bundle comes along, so what is not a chunk must not look encrypted.

        Judged by name, the source module and the resource here have no extension to go on, are
        taken for ciphertext, and fail the whole run for want of a key that doesn't exist.
        """
        bundle = make_zip({"app.MyApp": LUAJIT_CHUNK, "app.Source": LUA_SOURCE,
                           "res.config": b'{"a": 1}'})
        out, written = run(tmp_path, kind, {"game.zip": bundle}, None)
        assert written == 3
        assert (out / "app.MyApp.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "app.Source").read_bytes() == LUA_SOURCE
        assert (out / "res.config").read_bytes() == b'{"a": 1}'
        assert not (out / "raw_scripts").exists()

    def test_a_resource_pack_of_extensionless_files_is_still_dropped(self, tmp_path: Path,
                                                                     kind: str) -> None:
        """Content is what identifies an entry, so a pack of unnamed resources must not qualify."""
        pack = make_zip({"india_game": b"\x89PNG\r\n\x1a\n" + b"\x00" * 64,
                         "skeleton.atlas": b'{"skeleton":{"hash":"P/S"}}'})
        out, written = run(tmp_path, kind, {"res.zip": pack}, None)
        assert written == 0
        assert not out.exists() or not list(out.rglob("*")), "nothing should be written"


class TestOneBundlePerAbi:
    """A game shipping game32.zip and game64.zip has the same module names in both, compiled for
    a different word size. Dropping either silently would hand over the wrong arch's bytecode."""

    # LUAJIT_CHUNK is the GC64 one (flags STRIP|FR2); the 32-bit build clears FR2.
    CHUNK32 = b"\x1bLJ\x02\x02" + b"\x00" * 40

    def test_both_copies_are_kept_under_their_bundle(self, tmp_path: Path, kind: str) -> None:
        assets = {"res/game32.zip": make_zip({"app.MyApp": self.CHUNK32}),
                  "res/game64.zip": make_zip({"app.MyApp": LUAJIT_CHUNK})}
        out, written = run(tmp_path, kind, assets, None)
        assert written == 2
        assert (out / "res/game32/app.MyApp.luac").read_bytes() == self.CHUNK32
        assert (out / "res/game64/app.MyApp.luac").read_bytes() == LUAJIT_CHUNK

    def test_same_named_bundles_in_two_directories_dont_collide(self, tmp_path: Path,
                                                                kind: str) -> None:
        """The whole bundle path namespaces the copies, not just its basename."""
        assets = {"a/game.zip": make_zip({"app.MyApp": LUAJIT_CHUNK}),
                  "b/game.zip": make_zip({"app.MyApp": LUAJIT_CHUNK + b"\x01"})}
        out, written = run(tmp_path, kind, assets, None)
        assert written == 2
        assert (out / "a/game/app.MyApp.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "b/game/app.MyApp.luac").read_bytes() == LUAJIT_CHUNK + b"\x01"

    def test_identical_copies_are_written_once_under_the_plain_name(self, tmp_path: Path,
                                                                    kind: str) -> None:
        assets = {"res/game32.zip": make_zip({"app.MyApp": LUAJIT_CHUNK}),
                  "res/game64.zip": make_zip({"app.MyApp": LUAJIT_CHUNK})}
        out, written = run(tmp_path, kind, assets, None)
        assert written == 1
        assert (out / "app.MyApp.luac").read_bytes() == LUAJIT_CHUNK
        assert not list(out.glob("game*"))

    def test_an_encrypted_pair_keeps_both_copies(self, tmp_path: Path, kind: str,
                                                 key: bytes) -> None:
        """Bundles encrypted as a whole are a pair only once both have been decrypted, so they
        are written after that pass rather than as each one is decrypted."""
        assets = {"res/game32.bin": encrypt_asset(make_zip({"app.MyApp": self.CHUNK32})),
                  "res/game64.bin": encrypt_asset(make_zip({"app.MyApp": LUAJIT_CHUNK}))}
        out, written = run(tmp_path, kind, assets, key, forced_sign=SIGN)
        assert written == 2
        assert (out / "res/game32/app.MyApp.luac").read_bytes() == self.CHUNK32
        assert (out / "res/game64/app.MyApp.luac").read_bytes() == LUAJIT_CHUNK

    def test_two_bundles_whose_names_differ_only_by_extension(self, tmp_path: Path, kind: str,
                                                              key: bytes) -> None:
        """game.bin beside game.dat: the extension is all that tells them apart, so dropping it
        to namespace with would put both copies back in one place."""
        assets = {"res/game.bin": encrypt_asset(make_zip({"app.MyApp": self.CHUNK32})),
                  "res/game.dat": encrypt_asset(make_zip({"app.MyApp": LUAJIT_CHUNK}))}
        out, written = run(tmp_path, kind, assets, key, forced_sign=SIGN)
        assert written == 2
        assert (out / "res/game.bin/app.MyApp.luac").read_bytes() == self.CHUNK32
        assert (out / "res/game.dat/app.MyApp.luac").read_bytes() == LUAJIT_CHUNK

    def test_a_plain_bundle_beside_an_encrypted_one(self, tmp_path: Path, kind: str,
                                                    key: bytes) -> None:
        """The two are flattened by different passes -- plain as the scripts are collected,
        encrypted once the key is known -- so neither sees the other's module names. The copy
        that arrives second must still land somewhere."""
        assets = {"res/plain.zip": make_zip({"app.MyApp": self.CHUNK32}),
                  "res/game.bin": encrypt_asset(make_zip({"app.MyApp": LUAJIT_CHUNK}))}
        out, written = run(tmp_path, kind, assets, key, forced_sign=SIGN)
        assert written == 2
        assert (out / "app.MyApp.luac").read_bytes() == self.CHUNK32
        assert (out / "res/game/app.MyApp.luac").read_bytes() == LUAJIT_CHUNK

    def test_a_live_dump_keeps_the_name_and_the_bundle_copy_is_not_lost(
            self, tmp_path: Path, kind: str, key: bytes) -> None:
        """A live dump is the arch the game actually ran, so it keeps the plain name; the
        bundle's other copy goes under the bundle rather than into "already there"."""
        out = tmp_path / "out"
        (out / "res").mkdir(parents=True)
        (out / "app.MyApp.luac").write_bytes(LUAJIT_CHUNK)   # as if dumped live
        assets = {"res/game32.bin": encrypt_asset(make_zip({"app.MyApp": self.CHUNK32}))}
        _, written = run(tmp_path, kind, assets, key, forced_sign=SIGN)
        assert written == 1
        assert (out / "app.MyApp.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "res/game32/app.MyApp.luac").read_bytes() == self.CHUNK32


class TestSignatureFromTheAssets:
    """When nothing teaches the signature -- no --sign, and too few scripts found by name to
    detect one from -- it is worked out from the assets themselves. Gated, so only assets whose
    first bytes match no format we recognise get a vote."""

    PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(64))
    JSON = b'{"levels": [1, 2, 3], "name": "world one"}' + b" " * 32

    def test_an_encrypted_bundle_under_an_unusual_name_is_found(
            self, tmp_path: Path, kind: str, key: bytes) -> None:
        """res/game.bin is a zip of scripts encrypted whole: no script extension anywhere, so
        collection by name finds nothing and there is no prefix to learn from."""
        assets = {"res/game.bin": encrypt_asset(make_zip({"app.MyApp": LUAJIT_CHUNK})),
                  "res/data.bin": encrypt_asset(make_zip({"app.Other": PUC_CHUNK})),
                  "res/logo.png": self.PNG,
                  "res/levels.json": self.JSON}
        out, written = run(tmp_path, kind, assets, key)      # no --sign
        assert written == 2
        assert (out / "app.MyApp.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "app.Other.luac").read_bytes() == PUC_CHUNK

    def test_the_signature_is_reported(self, tmp_path: Path, kind: str, key: bytes,
                                       caplog: pytest.LogCaptureFixture) -> None:
        assets = {"res/a.bin": encrypt_asset(make_zip({"app.A": LUAJIT_CHUNK})),
                  "res/b.bin": encrypt_asset(make_zip({"app.B": PUC_CHUNK}))}
        with caplog.at_level("INFO"):
            run(tmp_path, kind, assets, key)
        assert "worked out from" in caplog.text

    def test_resources_alone_do_not_invent_a_signature(self, tmp_path: Path, kind: str,
                                                       caplog: pytest.LogCaptureFixture) -> None:
        """A game of textures and JSON must come out as 'no scripts', not as a signature
        elected by whatever its resources happen to share."""
        assets = {"res/a.png": self.PNG, "res/b.png": self.PNG + b"x",
                  "res/c.json": self.JSON, "res/d.json": self.JSON + b" "}
        with caplog.at_level("WARNING"):
            _out, written = run(tmp_path, kind, assets, None)
        assert written == 0
        assert "No .jsc / .luac / .lua files found" in caplog.text

    def test_a_game_found_by_name_does_not_need_the_scan(
            self, tmp_path: Path, kind: str, key: bytes,
            caplog: pytest.LogCaptureFixture) -> None:
        """Two scripts by name already teach the prefix, so the asset scan stays out of it."""
        assets = {"src/a.luac": encrypt_asset(LUAJIT_CHUNK),
                  "src/b.luac": encrypt_asset(PUC_CHUNK),
                  "res/logo.png": self.PNG}
        with caplog.at_level("INFO"):
            _out, written = run(tmp_path, kind, assets, key)
        assert written == 2
        assert "worked out from" not in caplog.text


class TestInputReads:
    def test_the_inputs_are_read_once(self, tmp_path: Path, kind: str, key: bytes,
                                      monkeypatch: pytest.MonkeyPatch) -> None:
        """Script collection and the signature scan share one pass over the inputs, so an APK's
        central directory is parsed once rather than once per step."""
        import zipfile

        assets = {"src/main.luac": encrypt_asset(LUAJIT_CHUNK),
                  "res/game.bin": encrypt_asset(make_zip({"src/b.lua": LUA_SOURCE}))}
        source = asset_source(tmp_path, kind, assets)

        opened: list[str] = []
        real = zipfile.ZipFile

        class Counting(real):
            def __init__(self, file, *a, **kw):
                if isinstance(file, str) and file == source:
                    opened.append(file)
                super().__init__(file, *a, **kw)

        monkeypatch.setattr(zipfile, "ZipFile", Counting)
        extract_offline([source], key, None, str(tmp_path / "out"), forced_sign=SIGN)
        expected = 1 if kind == "apk" else 0   # a directory is walked, never opened as a zip
        assert len(opened) == expected, f"the input was read {len(opened)} times"


class TestEncryptedBundle:
    # With a single encrypted file there is nothing to learn the signature from, so these tests
    # pass it the way the engine library would supply it.

    def bundle(self) -> bytes:
        return encrypt_asset(make_zip({
            "src/main.luac": encrypt_asset(LUAJIT_CHUNK),  # encrypted twice over
            "src/app.lua": LUA_SOURCE,
            "res/config.json": b'{"a": 1}',
        }))

    def test_is_decrypted_and_unpacked(self, tmp_path: Path, kind: str, key: bytes) -> None:
        out, written = run(tmp_path, kind, {"src.zip": self.bundle()}, key, forced_sign=SIGN)
        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK
        assert (out / "src/app.lua").read_bytes() == LUA_SOURCE
        assert (out / "res/config.json").read_bytes() == b'{"a": 1}'
        assert not list(out.rglob("*.zip"))
        assert written == 3

    def test_is_found_under_any_extension_by_its_signature(self, tmp_path: Path, kind: str,
                                                           key: bytes) -> None:
        # The scripts found by name teach the signature; the bundle is then found by it.
        assets = {"res/game.bin": self.bundle(),
                  "src/a.luac": encrypt_asset(PUC_CHUNK), "src/b.luac": encrypt_asset(PUC_CHUNK + b"1"),
                  "res/logo.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 64}
        out, written = run(tmp_path, kind, assets, key)
        assert (out / "src/app.lua").read_bytes() == LUA_SOURCE
        assert (out / "src/a.luac").exists()
        assert not (out / "res/logo.png").exists()

    def test_a_given_signature_finds_a_bundle_with_nothing_else_to_go_on(
            self, tmp_path: Path, kind: str, key: bytes) -> None:
        out, written = run(tmp_path, kind, {"res/game.bin": self.bundle()}, key, forced_sign=SIGN)
        assert (out / "src/app.lua").read_bytes() == LUA_SOURCE

    def test_a_zip_of_something_else_is_kept_as_a_zip(self, tmp_path: Path, kind: str, key: bytes) -> None:
        """Creator's "zip compress" wraps one .js in a zip; unpacking it would lose the file's name."""
        wrapped = encrypt_asset(make_zip({"index.js": b"console.log(1);"}))
        out, written = run(tmp_path, kind, {"src/bundle.jsc": wrapped}, key, forced_sign=SIGN)
        assert written == 1
        assert (out / "src/bundle.js.zip").exists()
        assert not (out / "index.js").exists()

    def test_a_corrupt_bundle_is_kept_as_a_zip(self, tmp_path: Path, kind: str, key: bytes) -> None:
        """Decrypts fine but isn't a readable zip: nothing is lost, it is written as it came."""
        broken = encrypt_asset(b"PK\x03\x04" + b"\x00" * 40)
        out, written = run(tmp_path, kind, {"src.zip": broken}, key, forced_sign=SIGN)
        assert written == 1
        assert (out / "src.zip").exists()
