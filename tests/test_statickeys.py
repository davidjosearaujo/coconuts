"""Unit tests for the static key search helpers that don't need radare2 or a library."""

from __future__ import annotations

from pathlib import Path

import pytest

from coconuts.statickeys import _add_string_at

from .conftest import LUAJIT_CHUNK, SIGN, encrypt_asset


class FakeR2:
    """Stands in for r2pipe: `psz` prints a NUL-terminated string, escaping binary bytes."""

    def __init__(self, at: dict[int, str]):
        self.at = at
        self.asked: list[int] = []

    def cmd(self, command: str) -> str:
        addr = int(command.split("@")[1].strip(), 16)
        self.asked.append(addr)
        return self.at.get(addr, "") + "\n"


def collect(at: dict[int, str], addr: int) -> list[str]:
    out: dict[str, None] = {}
    _add_string_at(FakeR2(at), out, addr)
    return list(out)


class TestAddStringAt:
    def test_keeps_a_plausible_key(self) -> None:
        assert collect({0x2000: "cocos2d_lua_js"}, 0x2000) == ["cocos2d_lua_js"]

    def test_rejects_escaped_binary(self) -> None:
        """`psz` renders non-printable bytes as literal \\xNN text, which str.isprintable() then
        happily accepts -- that is how the ELF header used to end up in the candidate list."""
        assert collect({0x2000: "\\x7fELF\\x02\\x01\\x01"}, 0x2000) == []

    @pytest.mark.parametrize("text", ["ab", "x" * 33, ""])
    def test_rejects_implausible_lengths(self, text: str) -> None:
        assert collect({0x2000: text}, 0x2000) == []

    def test_rejects_low_addresses(self) -> None:
        at = {0x400: "cocos2d_lua_js"}
        r2 = FakeR2(at)
        out: dict[str, None] = {}
        _add_string_at(r2, out, 0x400)
        assert out == {} and r2.asked == []  # not even read

    def test_rejects_excluded_strings(self) -> None:
        assert collect({0x2000: "applicationDidFinishLaunching"}, 0x2000) == []

    def test_a_failing_read_is_not_fatal(self) -> None:
        class Boom:
            def cmd(self, _command: str) -> str:
                raise RuntimeError("r2 died")

        out: dict[str, None] = {}
        _add_string_at(Boom(), out, 0x2000)
        assert out == {}


class TestXorKnownPlaintext:
    """The known-plaintext XOR attack, over real compiled Lua and the Cocos2d-js bundle header."""

    FIXTURES = Path(__file__).parent / "fixtures" / "bytecode"

    # The longest key each header can expose is set by the length of the plaintext it knows: it
    # must see the key repeat at least twice. LuaJIT's five-byte header only manages one byte.
    @pytest.mark.parametrize("name,key", [
        ("lua51", b"abcde"),
        ("lua51_stripped", b"abcde"),
        ("lua52", b"abcdefgh"),
        ("lua53", b"abcdefghijklmn"),
        ("lua53_stripped", b"abcdefghijklmn"),
        ("lua54", b"abcdefghijklmn"),
        ("luajit20", b"k"),
        ("luajit21", b"k"),
        ("luajit21_stripped", b"k"),
    ])
    def test_recovers_the_key_from_real_bytecode(self, name: str, key: bytes) -> None:
        from coconuts.ciphers import xor_decrypt
        from coconuts.statickeys import recover_xor_key_kp

        plain = (self.FIXTURES / f"{name}.luac").read_bytes()
        assert recover_xor_key_kp({"src/main.luac": xor_decrypt(plain, key)}) == key

    def test_with_a_signature_in_front(self) -> None:
        from coconuts.ciphers import xor_decrypt
        from coconuts.statickeys import recover_xor_key_kp

        plain = (self.FIXTURES / "lua53.luac").read_bytes()
        blob = b"SIGN" + xor_decrypt(plain, b"secret")
        assert recover_xor_key_kp({"a.luac": blob}, sign=b"SIGN") == b"secret"

    def test_a_key_longer_than_the_header_allows_is_not_guessed(self) -> None:
        from coconuts.ciphers import xor_decrypt
        from coconuts.statickeys import recover_xor_key_kp

        plain = (self.FIXTURES / "lua51.luac").read_bytes()  # a 12-byte header: keys up to 5
        assert recover_xor_key_kp({"a.luac": xor_decrypt(plain, b"abcdefg")}) is None

    def test_cocos2d_js_still_works(self) -> None:
        from coconuts.ciphers import xor_decrypt
        from coconuts.statickeys import KNOWN_PLAINTEXT_HEADERS, recover_xor_key_kp

        body = KNOWN_PLAINTEXT_HEADERS[0] + b"var x = 1;}}}})();" * 4
        assert recover_xor_key_kp({"src/jsb-builtin.jsc": xor_decrypt(body, b"js-key-12345")}) == b"js-key-12345"

    def test_xxtea_encrypted_scripts_are_not_mistaken_for_xor(self) -> None:
        from coconuts.statickeys import recover_xor_key_kp

        entries = {f"src/{i}.luac": encrypt_asset(LUAJIT_CHUNK + bytes([i])) for i in range(5)}
        assert recover_xor_key_kp(entries, sign=SIGN) is None


# ---------------------------------------------------------------------------
# The string tiers and the key search built on them. The two readers that need external help
# (radare2 for Tier 0b, the arm64 scan for Tier 0a) are stubbed out, so these run everywhere and
# exercise only the byte-level search.
# ---------------------------------------------------------------------------

import threading  # noqa: E402

from coconuts import statickeys  # noqa: E402
from coconuts.arm64 import KeyAndSign  # noqa: E402
from coconuts.ciphers import normalize_key  # noqa: E402
from coconuts.statickeys import (  # noqa: E402
    _key_samples,
    find_possible_keys,
    recover_key_and_sign_static,
    recover_key_static,
)

REAL_KEY = "Xk3-realkey-9Zq"  # 15 characters, not a pattern a regex tier would pick up by itself


@pytest.fixture
def no_external_readers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(statickeys, "extract_r2_priority_keys", lambda *a, **k: [])
    monkeypatch.setattr(statickeys, "find_key_and_sign", lambda *a, **k: [])


def lib(tmp_path: Path, *chunks: bytes) -> str:
    """A fake engine library: the chunks separated by the NULs real .rodata strings have."""
    path = tmp_path / "libcocos2dlua.so"
    path.write_bytes(b"\0".join(chunks) + b"\0")
    return str(path)


@pytest.mark.usefixtures("no_external_readers")
class TestFindPossibleKeys:
    def test_a_key_beside_a_boot_string_is_found(self, tmp_path: Path) -> None:
        path = lib(tmp_path, b"padding", REAL_KEY.encode(), b"main.lua", b"more")
        assert REAL_KEY in find_possible_keys(path)

    def test_the_tiers_come_out_in_priority_order(self, tmp_path: Path) -> None:
        near = b"near-boot-key"
        regex_only = b"0123abcd-4567-ab"            # Tier 2 shape: 8-4-2 groups
        general = b"only_a_general_token"
        filler = b"\0".join([b"x" * 600])           # pushes the later tokens out of the boot window
        path = lib(tmp_path, near, b"main.lua", filler, regex_only, filler, general)
        keys = find_possible_keys(path)
        assert keys.index("near-boot-key") < keys.index("0123abcd-4567-ab") < keys.index("only_a_general_token")

    def test_the_signature_is_an_extra_anchor(self, tmp_path: Path) -> None:
        """Without the anchor both tokens are only general-tier finds, in file order; with it the
        key sitting beside the signature is promoted ahead of the one that comes first."""
        filler = b"x" * 600
        path = lib(tmp_path, b"decoy_general", filler, b"sigkey_nearby", b"MYSIGN", filler)
        plain = find_possible_keys(path)
        anchored = find_possible_keys(path, sig_prefix=b"MYSIGN")
        assert plain.index("decoy_general") < plain.index("sigkey_nearby")
        assert anchored.index("sigkey_nearby") < anchored.index("decoy_general")

    def test_tier_stats_count_the_high_probability_candidates(self, tmp_path: Path) -> None:
        stats: dict[str, int] = {}
        find_possible_keys(lib(tmp_path, b"near-boot-key", b"main.lua"), tier_stats=stats)
        assert stats["high_prob_count"] >= 1

    def test_known_non_keys_are_excluded(self, tmp_path: Path) -> None:
        path = lib(tmp_path, b"main.lua", b"code-source-info", b"applicationDidFinishLaunching")
        keys = find_possible_keys(path)
        assert "code-source-info" not in keys and "applicationDidFinishLaunching" not in keys

    def test_the_general_tier_rejects_paths_and_format_strings(self, tmp_path: Path) -> None:
        filler = b"x" * 600
        path = lib(tmp_path, b"main.lua", filler, b"a/path/like", b"fmt%dstring", b"call(arg)", b"fine_token")
        keys = find_possible_keys(path)
        assert "fine_token" in keys
        assert not {"a/path/like", "fmt%dstring", "call(arg)"} & set(keys)

    def test_binary_noise_is_not_a_candidate(self, tmp_path: Path) -> None:
        path = lib(tmp_path, b"main.lua", b"\xff\xfe\x80binary\x81", b"clean-key-1")
        keys = find_possible_keys(path)
        assert "clean-key-1" in keys
        assert all(k.isascii() and k.isprintable() for k in keys)

    def test_no_duplicates(self, tmp_path: Path) -> None:
        path = lib(tmp_path, b"dupe-key-1", b"main.lua", b"dupe-key-1", b"0.0.0.0", b"dupe-key-1")
        keys = find_possible_keys(path)
        assert keys.count("dupe-key-1") == 1

    def test_already_aborted(self, tmp_path: Path) -> None:
        event = threading.Event()
        event.set()
        assert find_possible_keys(lib(tmp_path, b"main.lua", b"some-key"), abort_event=event) == []

    def test_the_arm64_scan_result_comes_first(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(statickeys, "find_key_and_sign",
                            lambda *a, **k: [KeyAndSign(b"exact-from-asm", b"SIGN", "0x1000")])
        keys = find_possible_keys(lib(tmp_path, b"near-key", b"main.lua"))
        assert keys[0] == "exact-from-asm"

    def test_priority_keys_from_radare2_come_next(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(statickeys, "extract_r2_priority_keys", lambda *a, **k: ["from-r2-literal"])
        keys = find_possible_keys(lib(tmp_path, b"near-key", b"main.lua"))
        assert keys[0] == "from-r2-literal"


@pytest.mark.usefixtures("no_external_readers")
class TestRecoverKeyStatic:
    def entries(self, key: str = REAL_KEY, sign: bytes = SIGN) -> dict[str, bytes]:
        k = normalize_key(key.encode())
        return {f"src/{i}.luac": encrypt_asset(LUAJIT_CHUNK + bytes([i]) * 40, key=k, sign=sign)
                for i in range(4)}

    def test_finds_the_key_among_the_candidates(self, tmp_path: Path) -> None:
        path = lib(tmp_path, b"decoy-one", REAL_KEY.encode(), b"main.lua", b"decoy-two")
        assert recover_key_static(path, self.entries(), sign=SIGN) == normalize_key(REAL_KEY.encode())

    def test_returns_none_when_no_candidate_decrypts(self, tmp_path: Path) -> None:
        path = lib(tmp_path, b"decoy-one", b"main.lua", b"decoy-two")
        assert recover_key_static(path, self.entries(), sign=SIGN) is None

    def test_the_wrong_signature_does_not_decrypt(self, tmp_path: Path) -> None:
        path = lib(tmp_path, REAL_KEY.encode(), b"main.lua")
        assert recover_key_static(path, self.entries(), sign=b"OTHER") is None

    def test_no_entries(self, tmp_path: Path) -> None:
        assert recover_key_static(lib(tmp_path, b"main.lua"), {}, sign=SIGN) is None

    def test_signals_when_the_high_probability_tiers_are_done(self, tmp_path: Path) -> None:
        done = threading.Event()
        path = lib(tmp_path, REAL_KEY.encode(), b"main.lua")
        recover_key_static(path, self.entries(), sign=SIGN, high_prob_done=done)
        assert done.is_set()

    def test_signals_even_when_it_finds_nothing(self, tmp_path: Path) -> None:
        done = threading.Event()
        recover_key_static(lib(tmp_path, b"main.lua", b"nope"), self.entries(), sign=SIGN, high_prob_done=done)
        assert done.is_set()

    def test_stops_when_told_to(self, tmp_path: Path) -> None:
        abort, done = threading.Event(), threading.Event()
        abort.set()
        path = lib(tmp_path, REAL_KEY.encode(), b"main.lua")
        assert recover_key_static(path, self.entries(), sign=SIGN, abort_event=abort, high_prob_done=done) is None
        assert done.is_set()  # whoever waits on it must not be left hanging


class TestRecoverKeyAndSignStatic:
    def entries(self) -> dict[str, bytes]:
        k = normalize_key(REAL_KEY.encode())
        return {f"src/{i}.luac": encrypt_asset(LUAJIT_CHUNK + bytes([i]) * 40, key=k) for i in range(3)}

    def pairs(self, monkeypatch: pytest.MonkeyPatch, *pairs: KeyAndSign) -> None:
        monkeypatch.setattr(statickeys, "find_key_and_sign", lambda *a, **k: list(pairs))

    def test_the_pair_that_decrypts_is_returned_with_its_signature(self, monkeypatch) -> None:
        self.pairs(monkeypatch, KeyAndSign(b"wrong-key", SIGN, "0x1"),
                   KeyAndSign(REAL_KEY.encode(), SIGN, "0x2"))
        assert recover_key_and_sign_static("lib.so", self.entries()) == (normalize_key(REAL_KEY.encode()), SIGN)

    def test_a_right_key_with_the_wrong_signature_is_rejected(self, monkeypatch) -> None:
        self.pairs(monkeypatch, KeyAndSign(REAL_KEY.encode(), b"NOPE", "0x1"))
        assert recover_key_and_sign_static("lib.so", self.entries()) is None

    def test_no_entries_to_check_against(self, monkeypatch) -> None:
        self.pairs(monkeypatch, KeyAndSign(REAL_KEY.encode(), SIGN, "0x1"))
        assert recover_key_and_sign_static("lib.so", {}) is None

    def test_no_library(self, monkeypatch) -> None:
        self.pairs(monkeypatch, KeyAndSign(REAL_KEY.encode(), SIGN, "0x1"))
        assert recover_key_and_sign_static("", self.entries()) is None

    def test_no_pairs_found(self, monkeypatch) -> None:
        self.pairs(monkeypatch)
        assert recover_key_and_sign_static("lib.so", self.entries()) is None


class TestKeySamples:
    def test_the_smallest_files_of_a_useful_size(self) -> None:
        entries = {"tiny": b"x" * 8, "a": b"x" * 100, "b": b"x" * 70, "c": b"x" * 200, "d": b"x" * 300}
        assert [len(s) for s in _key_samples(entries)] == [70, 100, 200]

    def test_falls_back_to_tiny_files_when_that_is_all_there_is(self) -> None:
        assert [len(s) for s in _key_samples({"a": b"x" * 8, "b": b"x" * 4})] == [4, 8]
