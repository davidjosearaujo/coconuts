"""Unit tests for the static key search helpers that don't need radare2 or a library."""

from __future__ import annotations

import pytest

from coconuts.statickeys import _add_string_at


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
