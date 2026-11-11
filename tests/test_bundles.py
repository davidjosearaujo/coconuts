"""Script bundles: the zip Lua games register with LuaStack::loadChunksFromZIP.

A bundle can be a plain zip, a zip encrypted as a whole, or either of those holding entries that
are encrypted themselves; it can be called game.zip or game.bin. Each case is built both as a
directory tree and as an APK-shaped zip, since the two are read by different code.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from coconuts.extract import collect_scripts, extract_offline

from .conftest import KEY_TEXT, LUA_SOURCE, LUAJIT_CHUNK, PUC_CHUNK, SIGN, encrypt_asset


def make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, blob in members.items():
            zf.writestr(name, blob)
    return buf.getvalue()


def build(tmp_path: Path, kind: str, assets: dict[str, bytes]) -> str:
    """The assets as an extracted tree ('dir') or as an APK-shaped zip ('apk')."""
    if kind == "dir":
        root = tmp_path / "game"
        for rel, blob in assets.items():
            (root / "assets" / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / "assets" / rel).write_bytes(blob)
        return str(root)
    path = tmp_path / "game.apk"
    with zipfile.ZipFile(path, "w") as zf:
        for rel, blob in assets.items():
            zf.writestr(f"assets/{rel}", blob)
    return str(path)


@pytest.fixture(params=["dir", "apk"])
def kind(request: pytest.FixtureRequest) -> str:
    return request.param


def run(tmp_path: Path, kind: str, assets: dict[str, bytes], key: bytes, **kw) -> tuple[Path, int]:
    out = tmp_path / "out"
    return out, extract_offline([build(tmp_path, kind, assets)], key, None, str(out), **kw)


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
        assert not out.exists() or not any(out.rglob("*.png"))

    def test_a_script_beside_a_bundle_wins_over_its_copy(self, tmp_path: Path, kind: str) -> None:
        bundle = make_zip({"src/main.lua": b"-- from the bundle"})
        assets = {"game.zip": bundle, "src/main.lua": LUA_SOURCE}
        entries = collect_scripts([build(tmp_path, kind, assets)])
        assert entries["src/main.lua"] == LUA_SOURCE

    def test_traversal_in_an_entry_name_is_refused(self, tmp_path: Path, kind: str) -> None:
        bundle = make_zip({"../../evil.lua": LUA_SOURCE, "ok.lua": LUA_SOURCE})
        out, written = run(tmp_path, kind, {"game.zip": bundle}, None)
        assert (out / "ok.lua").exists()
        assert not (tmp_path / "evil.lua").exists()
        assert not (tmp_path.parent / "evil.lua").exists()


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


def test_the_key_used_is_the_suite_key(key: bytes) -> None:
    from coconuts.ciphers import normalize_key
    assert key == normalize_key(KEY_TEXT)
