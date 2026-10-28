"""Read what we need out of an APK without extra tools: the package name and the native engine
library.

Android ships ``AndroidManifest.xml`` inside the APK as compiled binary XML (AXML), not text, so we
parse just enough of that format to pull out two things:

- the ``package`` attribute of ``<manifest>`` (so ``PACKAGE`` can be omitted on the command line), and
- the ``android.app.lib_name`` ``<meta-data>`` value, which names the engine library when it isn't the
  usual ``libcocos.so`` / ``libcocos2djs.so`` / ``libcocos2dlua.so`` (so ``LIB`` can be omitted too).

With the library's base name in hand we fish the matching ``lib/<abi>/lib<name>.so`` out of the APK zip
and write it to a temp file for the static key search to read.
"""

from __future__ import annotations

import os
import shutil
import struct
import zipfile

from .log import log

# AXML chunk types we care about (frameworks/base ResourceTypes.h)
_RES_STRING_POOL = 0x0001
_RES_XML_RESOURCE_MAP = 0x0180
_RES_XML_START_ELEMENT = 0x0102

_UTF8_FLAG = 1 << 8

# Framework resource IDs for android:name / android:value. aapt2 often blanks the attribute name
# strings and identifies these only by resource id via the XML resource map, so we match on both.
_ATTR_ID_NAME = 0x01010003
_ATTR_ID_VALUE = 0x01010024

# arm64 first: the static track and Frida both expect the 64-bit engine library.
_ABI_PRIORITY = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")

# Tried when the manifest doesn't name the library (older Cocos builds omit android.app.lib_name).
_DEFAULT_LIB_NAMES = ("libcocos.so", "libcocos2djs.so", "libcocos2dlua.so")


def _pool_get(strings: list[str], idx: int) -> str:
    """String-pool lookup that returns '' for out-of-range refs (incl. the 0xFFFFFFFF 'none')."""
    return strings[idx] if 0 <= idx < len(strings) else ""


def _read_pool(buf: bytes, chunk_off: int, chunk_size: int) -> list[str]:
    string_count, _style_count, flags, strings_start = struct.unpack_from("<IIII", buf, chunk_off + 8)
    is_utf8 = bool(flags & _UTF8_FLAG)
    offsets_base = chunk_off + 28  # 8 (header) + 5 * 4 (pool header fields)
    data_base = chunk_off + strings_start

    strings: list[str] = []
    for i in range(string_count):
        (rel,) = struct.unpack_from("<I", buf, offsets_base + i * 4)
        pos = data_base + rel
        if pos >= chunk_off + chunk_size:
            strings.append("")
            continue
        if is_utf8:
            pos = _skip_len8(buf, pos)  # char count (unused)
            pos, nbytes = _read_len8(buf, pos)  # byte count
            strings.append(buf[pos:pos + nbytes].decode("utf-8", "replace"))
        else:
            pos, nchars = _read_len16(buf, pos)
            strings.append(buf[pos:pos + nchars * 2].decode("utf-16-le", "replace"))
    return strings


def _skip_len8(buf: bytes, pos: int) -> int:
    val = buf[pos]
    return pos + (2 if val & 0x80 else 1)


def _read_len8(buf: bytes, pos: int) -> tuple[int, int]:
    val = buf[pos]
    if val & 0x80:
        return pos + 2, ((val & 0x7F) << 8) | buf[pos + 1]
    return pos + 1, val


def _read_len16(buf: bytes, pos: int) -> tuple[int, int]:
    (val,) = struct.unpack_from("<H", buf, pos)
    if val & 0x8000:
        (lo,) = struct.unpack_from("<H", buf, pos + 2)
        return pos + 4, ((val & 0x7FFF) << 16) | lo
    return pos + 2, val


def parse_axml(data: bytes) -> tuple[str | None, str | None]:
    """Parse a binary AndroidManifest.xml; return ``(package, lib_name)``, either possibly None.

    ``lib_name`` is the raw ``android.app.lib_name`` value (e.g. ``"cocos2djs"``), not a filename.
    Returns ``(None, None)`` on anything unexpected rather than raising — callers fall back to defaults.
    """
    try:
        if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:  # RES_XML_TYPE
            return None, None

        pool: list[str] = []
        resource_map: list[int] = []
        package: str | None = None
        lib_name: str | None = None

        off = struct.unpack_from("<H", data, 2)[0]  # skip the XML chunk's own header
        total = len(data)
        while off + 8 <= total:
            ctype, _hsize, csize = struct.unpack_from("<HHI", data, off)
            if csize < 8 or off + csize > total:
                break

            if ctype == _RES_STRING_POOL:
                pool = _read_pool(data, off, csize)
            elif ctype == _RES_XML_RESOURCE_MAP:
                count = (csize - 8) // 4
                resource_map = list(struct.unpack_from("<%dI" % count, data, off + 8))
            elif ctype == _RES_XML_START_ELEMENT and pool:
                # The element name sits at ext+4; read it first and skip attribute parsing for the
                # many elements (<activity>, <service>, …) we don't care about.
                name = _pool_get(pool, struct.unpack_from("<I", data, off + 20)[0])
                if name == "manifest":
                    package = _parse_attributes(data, off, pool, resource_map).get("package") or package
                elif name == "meta-data":
                    attrs = _parse_attributes(data, off, pool, resource_map)
                    if attrs.get("name") == "android.app.lib_name" and attrs.get("value"):
                        lib_name = attrs["value"]
            off += csize

        return package, lib_name
    except (struct.error, IndexError, UnicodeDecodeError):
        return None, None


def _parse_attributes(buf: bytes, off: int, pool: list[str], resource_map: list[int]) -> dict[str, str]:
    """Pull the attributes we need (package / name / value) out of a START_ELEMENT chunk.

    ResXMLTree_node is header(8) + lineNumber(4) + comment(4) = 16 bytes, then ResXMLTree_attrExt.
    """
    ext = off + 16
    attr_start, _attr_size, attr_count = struct.unpack_from("<HHH", buf, ext + 8)

    attrs: dict[str, str] = {}
    a = ext + attr_start
    for _ in range(attr_count):
        a_ns, a_name_idx, raw_value_idx, _vsize, _res0, data_type, data_val = struct.unpack_from(
            "<IIIHBBI", buf, a
        )
        a += 20  # sizeof(ResXMLTree_attribute)
        a_name = _pool_get(pool, a_name_idx)
        res_id = resource_map[a_name_idx] if 0 <= a_name_idx < len(resource_map) else 0

        # TYPE_STRING (0x03) values point back into the string pool; others we read as the raw int.
        if data_type == 0x03:
            value = _pool_get(pool, data_val)
        elif raw_value_idx != 0xFFFFFFFF:
            value = _pool_get(pool, raw_value_idx)
        else:
            value = str(data_val)

        # android:name / android:value are matched by resource id too, since aapt2 often blanks their
        # attribute-name strings. The unnamespaced "package" lives on <manifest>.
        if a_ns == 0xFFFFFFFF and a_name == "package":
            attrs["package"] = value
        elif a_name == "name" or res_id == _ATTR_ID_NAME:
            attrs["name"] = value
        elif a_name == "value" or res_id == _ATTR_ID_VALUE:
            attrs["value"] = value
    return attrs


def _list_members(path: str) -> list[str]:
    """Member paths inside one APK/zip or unpacked directory (so ``--apk`` works either way)."""
    if os.path.isdir(path):
        members = []
        for root, _dirs, files in os.walk(path):
            for fname in files:
                members.append(os.path.relpath(os.path.join(root, fname), path).replace("\\", "/"))
        return members
    try:
        with zipfile.ZipFile(path) as zf:
            return zf.namelist()
    except (OSError, zipfile.BadZipFile) as e:
        log.debug("Can't read %s as an APK: %s", path, e)
        return []


def _read_member(path: str, member: str) -> bytes | None:
    """Read one (small) member whole; None if the source or member can't be read."""
    try:
        if os.path.isdir(path):
            with open(os.path.join(path, member.replace("/", os.sep)), "rb") as f:
                return f.read()
        with zipfile.ZipFile(path) as zf, zf.open(member) as f:
            return f.read()
    except (OSError, KeyError, zipfile.BadZipFile):
        return None


def _copy_member(path: str, member: str, dst_path: str) -> bool:
    """Stream one member to ``dst_path`` in chunks (no full-file buffering); False on failure."""
    try:
        with open(dst_path, "wb") as dst:
            if os.path.isdir(path):
                with open(os.path.join(path, member.replace("/", os.sep)), "rb") as src:
                    shutil.copyfileobj(src, dst)
            else:
                with zipfile.ZipFile(path) as zf, zf.open(member) as src:
                    shutil.copyfileobj(src, dst)
        return True
    except (OSError, KeyError, zipfile.BadZipFile) as e:
        log.debug("Failed to extract %s from %s: %s", member, path, e)
        return False


def read_apk_metadata(apk_paths: list[str]) -> tuple[str | None, str | None]:
    """Return ``(package, lib_name)`` from the first APK/dir whose manifest yields either."""
    for path in apk_paths:
        data = _read_member(path, "AndroidManifest.xml")
        if data is None:
            continue
        package, lib_name = parse_axml(data)
        if package or lib_name:
            return package, lib_name
    return None, None


def _lib_candidates(lib_name: str | None) -> list[str]:
    names: list[str] = []
    if lib_name:
        base = os.path.basename(lib_name)  # a bare name, but normalise defensively
        candidate = base if base.startswith("lib") else f"lib{base}"
        candidate = candidate if candidate.endswith(".so") else f"{candidate}.so"
        names.append(candidate)
    for default in _DEFAULT_LIB_NAMES:
        if default not in names:
            names.append(default)
    return names


def extract_engine_lib(apk_paths: list[str], lib_name: str | None, dest_dir: str) -> str | None:
    """Find the engine ``.so`` inside the APK(s) and write it to ``dest_dir``; return its path.

    Prefers the arm64 ABI and the library named by ``android.app.lib_name``, then the usual Cocos
    names. Returns None if no matching library is bundled (e.g. it's in an ABI split that wasn't
    passed, or ``--apk`` pointed at a bare folder of scripts).
    """
    candidates = _lib_candidates(lib_name)
    # Pick the winner by name alone (arm64 + the manifest-named lib first), then stream only that one
    # member out — so a big .so is never buffered whole and the losing candidates are never read.
    best: tuple[tuple[int, int], str, str] | None = None  # (rank, source path, member)
    for path in apk_paths:
        for name in _list_members(path):
            parts = name.split("/")
            if len(parts) != 3 or parts[0] != "lib":
                continue
            abi, soname = parts[1], parts[2]
            if soname not in candidates:
                continue
            abi_rank = _ABI_PRIORITY.index(abi) if abi in _ABI_PRIORITY else len(_ABI_PRIORITY)
            rank = (abi_rank, candidates.index(soname))
            if best is None or rank < best[0]:
                best = (rank, path, name)

    if best is None:
        return None

    _rank, path, member = best
    out_path = os.path.join(dest_dir, member.split("/")[-1])
    if not _copy_member(path, member, out_path):
        return None
    log.info("Using engine library %s from the APK.", member)
    return out_path
