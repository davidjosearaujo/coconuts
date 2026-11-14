"""The console formatter and the colour decision.

Every line the tool prints goes through ConsoleFormatter, so its tag table is the whole of the
output's vocabulary: '[+]' for a result, '[!]' for a warning, and the track name for the two
loggers that race ('static:' and 'frida:').
"""

from __future__ import annotations

import logging

import pytest

from coconuts.log import SUCCESS, ConsoleFormatter, flog, log, slog, use_color


def record(level: int, msg: str, name: str = "coconuts", args=()) -> logging.LogRecord:
    return logging.LogRecord(name, level, __file__, 1, msg, args, None)


def plain(level: int, msg: str, name: str = "coconuts", args=()) -> str:
    return ConsoleFormatter(color=False).format(record(level, msg, name, args))


class TestLoggers:
    def test_the_track_loggers_are_children_of_the_tool_logger(self) -> None:
        """Configuring the parent has to configure both tracks, since only the parent gets a
        handler attached."""
        assert log.name == "coconuts"
        assert slog.name == "coconuts.static" and slog.parent is log
        assert flog.name == "coconuts.frida" and flog.parent is log

    def test_success_sits_between_info_and_warning(self) -> None:
        """It has to be visible by default (above INFO) without being a warning."""
        assert logging.INFO < SUCCESS < logging.WARNING
        assert logging.getLevelName(SUCCESS) == "SUCCESS"


class TestTags:
    @pytest.mark.parametrize("level,tag", [
        (logging.DEBUG, "[.]"),
        (logging.INFO, "[*]"),
        (SUCCESS, "[+]"),
        (logging.WARNING, "[!]"),
        (logging.ERROR, "[-]"),
        (logging.CRITICAL, "[-]"),
    ])
    def test_each_level_gets_its_tag(self, level: int, tag: str) -> None:
        assert plain(level, "hello") == f"{tag} hello"

    def test_a_level_between_two_named_ones_takes_the_lower_tag(self) -> None:
        """logging allows any integer level; 21 is still informational, not a result."""
        assert plain(logging.INFO + 1, "hello").startswith("[*]")

    def test_a_level_below_debug_still_prints(self) -> None:
        assert plain(1, "hello").startswith("[.]")

    def test_the_message_is_formatted_with_its_arguments(self) -> None:
        assert plain(logging.INFO, "found %d in %s", args=(3, "assets")) == \
            "[*] found 3 in assets"


class TestTrackPrefix:
    def test_a_child_logger_names_its_track(self) -> None:
        assert plain(logging.INFO, "waiting", name="coconuts.frida") == "[*] frida: waiting"
        assert plain(SUCCESS, "key found", name="coconuts.static") == "[+] static: key found"

    def test_the_parent_logger_names_nothing(self) -> None:
        assert plain(logging.INFO, "waiting") == "[*] waiting"

    def test_an_unrelated_logger_is_not_given_a_prefix(self) -> None:
        """A record from frida's own logger, say, must not be relabelled as one of our tracks."""
        assert plain(logging.INFO, "hi", name="urllib3.connectionpool") == "[*] hi"

    def test_a_deeper_child_keeps_its_whole_path(self) -> None:
        assert plain(logging.INFO, "hi", name="coconuts.frida.rpc") == "[*] frida.rpc: hi"


class TestContinuationLines:
    def test_further_lines_are_indented_under_the_message(self) -> None:
        """A Frida stack or a traceback has to read as one message, not as new log lines."""
        out = plain(logging.ERROR, "failed:\nline two\nline three")
        assert out == "[-] failed:\n    line two\n    line three"

    def test_a_single_line_is_untouched(self) -> None:
        assert "\n" not in plain(logging.INFO, "one line")


class TestColor:
    def test_nothing_is_painted_when_colour_is_off(self) -> None:
        assert "\033[" not in plain(SUCCESS, "key found", name="coconuts.frida")

    def test_the_tag_and_the_message_are_painted_when_it_is_on(self) -> None:
        out = ConsoleFormatter(color=True).format(record(SUCCESS, "key found"))
        assert out.startswith("\033[1;32m[+]\033[0m")
        assert "\033[32mkey found\033[0m" in out

    def test_info_paints_the_tag_but_not_the_message(self) -> None:
        """The INFO style carries no message colour, so the body must be left bare rather than
        wrapped in an empty escape."""
        out = ConsoleFormatter(color=True).format(record(logging.INFO, "hello"))
        assert out == "\033[36m[*]\033[0m hello"

    def test_the_track_name_is_dimmed(self) -> None:
        out = ConsoleFormatter(color=True).format(record(logging.INFO, "hi", "coconuts.frida"))
        assert "\033[2mfrida:\033[0m" in out


class TestUseColor:
    @pytest.fixture(autouse=True)
    def _a_terminal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")
        monkeypatch.setattr("sys.stderr.isatty", lambda: True, raising=False)

    def test_on_for_a_terminal(self) -> None:
        assert use_color(disabled=False) is True

    def test_off_when_asked_to_be_off(self) -> None:
        assert use_color(disabled=True) is False

    def test_off_when_no_color_is_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        assert use_color(disabled=False) is False

    def test_off_for_a_dumb_terminal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TERM", "dumb")
        assert use_color(disabled=False) is False

    def test_off_when_the_output_is_redirected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Escapes in a piped log are noise, so a non-tty turns them off."""
        monkeypatch.setattr("sys.stderr.isatty", lambda: False, raising=False)
        assert use_color(disabled=False) is False
