"""Reading the package name and the engine library out of an APK, without any Android tooling.

AndroidManifest.xml ships as binary XML, so the tests build the real chunk layout (string pool,
resource map, start-element chunks) rather than mocking the parser.
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from coconuts.manifest import (
    _lib_candidates,
    extract_engine_lib,
    parse_axml,
    read_apk_metadata,
)

NO_STRING = 0xFFFFFFFF
RES_ID_NAME, RES_ID_VALUE = 0x01010003, 0x01010024
TYPE_STRING = 0x03


def _pool(strings: list[str], utf8: bool) -> bytes:
    blobs = []
    for s in strings:
        if utf8:
            raw = s.encode("utf-8")
            blobs.append(bytes([len(s), len(raw)]) + raw + b"\0")
        else:
            blobs.append(struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\0\0")
    offsets, pos = [], 0
    for b in blobs:
        offsets.append(pos)
        pos += len(b)
    data = b"".join(blobs)
    data += b"\0" * (-len(data) % 4)
    strings_start = 28 + 4 * len(strings)
    size = strings_start + len(data)
    head = struct.pack("<HHI", 0x0001, 28, size)
    head += struct.pack("<IIIII", len(strings), 0, (1 << 8) if utf8 else 0, strings_start, 0)
    return head + b"".join(struct.pack("<I", o) for o in offsets) + data


def _element(name_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
    """attrs are (namespace index or NO_STRING, name index, string index)."""
    body = struct.pack("<II", NO_STRING, name_idx)
    body += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
    for ns, name, value in attrs:
        body += struct.pack("<IIIHBBI", ns, name, value, 8, 0, TYPE_STRING, value)
    return struct.pack("<HHIII", 0x0102, 16, 16 + len(body), 1, NO_STRING) + body


def build_axml(package: str | None, metas: list[tuple[str, str]], *, utf8: bool = True,
               blank_attr_names: bool = False) -> bytes:
    """A manifest with <manifest package=...> and <meta-data android:name/android:value> children.

    blank_attr_names reproduces aapt2: the attribute names are empty strings and the attributes are
    identified only through the resource map.
    """
    strings = ["" if blank_attr_names else "name", "" if blank_attr_names else "value", "package",
               "manifest", "meta-data", "http://schemas.android.com/apk/res/android"]
    ns = 5
    def intern(s: str) -> int:
        strings.append(s)
        return len(strings) - 1

    elements = []
    if package is not None:
        elements.append(_element(3, [(NO_STRING, 2, intern(package))]))
    for key, value in metas:
        elements.append(_element(4, [(ns, 0, intern(key)), (ns, 1, intern(value))]))

    resource_map = struct.pack("<HHI", 0x0180, 8, 8 + 12) + struct.pack("<III", RES_ID_NAME, RES_ID_VALUE, 0)
    chunks = _pool(strings, utf8) + resource_map + b"".join(elements)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(chunks)) + chunks


class TestParseAxml:
    @pytest.mark.parametrize("utf8", [True, False], ids=["utf8-pool", "utf16-pool"])
    def test_package_and_lib_name(self, utf8: bool) -> None:
        data = build_axml("com.example.game", [("android.app.lib_name", "cocos2dlua")], utf8=utf8)
        assert parse_axml(data) == ("com.example.game", "cocos2dlua")

    def test_aapt2_blank_attribute_names_are_matched_by_resource_id(self) -> None:
        data = build_axml("com.example.game", [("android.app.lib_name", "cocos2djs")],
                          blank_attr_names=True)
        assert parse_axml(data) == ("com.example.game", "cocos2djs")

    def test_no_lib_name_meta_data(self) -> None:
        assert parse_axml(build_axml("com.example.game", [])) == ("com.example.game", None)

    def test_other_meta_data_is_ignored(self) -> None:
        data = build_axml("p.q", [("com.google.android.gms.version", "12451000"),
                                  ("android.app.lib_name", "cocos2djs")])
        assert parse_axml(data) == ("p.q", "cocos2djs")

    def test_non_ascii_package_text(self) -> None:
        assert parse_axml(build_axml("com.exämple.gäme", []))[0] == "com.exämple.gäme"

    @pytest.mark.parametrize("data", [b"", b"short", b"\x00" * 64, b"PK\x03\x04" + b"\0" * 40],
                             ids=["empty", "short", "zeros", "zip"])
    def test_garbage_gives_nothing_rather_than_raising(self, data: bytes) -> None:
        assert parse_axml(data) == (None, None)

    def test_every_truncation_is_survived(self) -> None:
        data = build_axml("com.example.game", [("android.app.lib_name", "cocos2dlua")])
        for cut in range(0, len(data), 7):
            parse_axml(data[:cut])  # must not raise


class TestLibCandidates:
    @pytest.mark.parametrize("name,first", [
        ("cocos2djs", "libcocos2djs.so"), ("libgame.so", "libgame.so"),
        ("libgame", "libgame.so"), ("game", "libgame.so"), ("/x/y/game", "libgame.so"),
    ])
    def test_manifest_name_is_normalised_and_tried_first(self, name: str, first: str) -> None:
        assert _lib_candidates(name)[0] == first

    def test_defaults_follow_without_duplicates(self) -> None:
        cands = _lib_candidates("cocos2djs")
        assert cands == ["libcocos2djs.so", "libcocos.so", "libcocos2dlua.so"]
        assert _lib_candidates(None) == ["libcocos.so", "libcocos2djs.so", "libcocos2dlua.so"]


def make_apk(path: Path, members: dict[str, bytes]) -> str:
    with zipfile.ZipFile(path, "w") as zf:
        for name, blob in members.items():
            zf.writestr(name, blob)
    return str(path)


class TestReadApkMetadata:
    def test_from_an_apk(self, tmp_path: Path) -> None:
        apk = make_apk(tmp_path / "a.apk", {"AndroidManifest.xml": build_axml(
            "com.example.game", [("android.app.lib_name", "cocos2dlua")])})
        assert read_apk_metadata([apk]) == ("com.example.game", "cocos2dlua")

    def test_from_an_unpacked_directory(self, tmp_path: Path) -> None:
        (tmp_path / "AndroidManifest.xml").write_bytes(build_axml("p.q", []))
        assert read_apk_metadata([str(tmp_path)]) == ("p.q", None)

    def test_first_input_that_yields_something_wins(self, tmp_path: Path) -> None:
        empty = make_apk(tmp_path / "split.apk", {"classes.dex": b"dex"})
        real = make_apk(tmp_path / "base.apk", {"AndroidManifest.xml": build_axml("p.q", [])})
        assert read_apk_metadata([empty, real]) == ("p.q", None)

    def test_nothing_readable(self, tmp_path: Path) -> None:
        (tmp_path / "junk.apk").write_bytes(b"not a zip")
        assert read_apk_metadata([str(tmp_path / "junk.apk"), str(tmp_path / "missing.apk")]) == (None, None)


class TestExtractEngineLib:
    def libs(self, **abis: str) -> dict[str, bytes]:
        return {f"lib/{abi.replace('_', '-')}/libcocos2dlua.so": body.encode() for abi, body in abis.items()}

    def test_arm64_beats_the_other_abis(self, tmp_path: Path) -> None:
        apk = make_apk(tmp_path / "a.apk", self.libs(x86="x86", armeabi_v7a="v7", arm64_v8a="arm64"))
        out = extract_engine_lib([apk], None, str(tmp_path))
        assert out is not None and Path(out).read_bytes() == b"arm64"

    def test_the_manifest_named_library_beats_a_default_one(self, tmp_path: Path) -> None:
        apk = make_apk(tmp_path / "a.apk", {"lib/arm64-v8a/libcocos2djs.so": b"js",
                                            "lib/arm64-v8a/libgame.so": b"named"})
        out = extract_engine_lib([apk], "game", str(tmp_path))
        assert out is not None and Path(out).read_bytes() == b"named"

    def test_abi_outranks_name(self, tmp_path: Path) -> None:
        apk = make_apk(tmp_path / "a.apk", {"lib/x86/libgame.so": b"x86-named",
                                            "lib/arm64-v8a/libcocos.so": b"arm64-default"})
        out = extract_engine_lib([apk], "game", str(tmp_path))
        assert out is not None and Path(out).read_bytes() == b"arm64-default"

    def test_found_across_split_apks(self, tmp_path: Path) -> None:
        base = make_apk(tmp_path / "base.apk", {"AndroidManifest.xml": b"x"})
        split = make_apk(tmp_path / "split_config.arm64_v8a.apk", self.libs(arm64_v8a="from split"))
        out = extract_engine_lib([base, split], None, str(tmp_path))
        assert out is not None and Path(out).read_bytes() == b"from split"

    def test_from_an_unpacked_directory(self, tmp_path: Path) -> None:
        root = tmp_path / "unpacked"
        (root / "lib/arm64-v8a").mkdir(parents=True)
        (root / "lib/arm64-v8a/libcocos2dlua.so").write_bytes(b"dir")
        dest = tmp_path / "dest"
        dest.mkdir()
        out = extract_engine_lib([str(root)], None, str(dest))
        assert out is not None and Path(out).read_bytes() == b"dir"

    def test_unrelated_and_misplaced_libraries_are_ignored(self, tmp_path: Path) -> None:
        apk = make_apk(tmp_path / "a.apk", {"lib/arm64-v8a/libother.so": b"o",
                                            "assets/lib/arm64-v8a/libcocos.so": b"misplaced",
                                            "lib/libcocos.so": b"no abi dir"})
        assert extract_engine_lib([apk], None, str(tmp_path)) is None

    def test_an_unknown_abi_still_beats_nothing(self, tmp_path: Path) -> None:
        apk = make_apk(tmp_path / "a.apk", {"lib/riscv64/libcocos.so": b"odd"})
        out = extract_engine_lib([apk], None, str(tmp_path))
        assert out is not None and Path(out).read_bytes() == b"odd"
