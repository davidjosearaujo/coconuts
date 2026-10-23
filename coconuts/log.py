"""Logging setup: the shared loggers, the SUCCESS level, and the console formatter."""

from __future__ import annotations

import logging
import os
import sys

log = logging.getLogger("coconuts")
slog = log.getChild("static")  # static key search track
flog = log.getChild("frida")   # Frida / hook resolution track

SUCCESS = 25  # between INFO and WARNING: results worth spotting (key found, files written)
logging.addLevelName(SUCCESS, "SUCCESS")


class ConsoleFormatter(logging.Formatter):
    """Formats records as '[+] frida: message', coloured by level when writing to a terminal."""

    STYLES = {  # level: (tag, tag colour, message colour) as ANSI SGR codes
        logging.DEBUG: ("[.]", "2", "2"),
        logging.INFO: ("[*]", "36", ""),
        SUCCESS: ("[+]", "1;32", "32"),
        logging.WARNING: ("[!]", "1;33", "33"),
        logging.ERROR: ("[-]", "1;31", "31"),
    }

    def __init__(self, color: bool):
        super().__init__("%(message)s")
        self.color = color

    def _paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color and code else text

    def format(self, record: logging.LogRecord) -> str:
        style = max((lv for lv in self.STYLES if lv <= record.levelno), default=logging.DEBUG)
        tag, tag_code, msg_code = self.STYLES[style]
        prefix = self._paint(tag, tag_code) + " "
        if record.name.startswith(log.name + "."):
            prefix += self._paint(record.name[len(log.name) + 1:] + ":", "2") + " "
        # Indent continuation lines (tracebacks, Frida stacks) under the message
        body = "\n    ".join(super().format(record).splitlines())
        return prefix + self._paint(body, msg_code)


def use_color(disabled: bool) -> bool:
    return (not disabled and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
            and sys.stderr.isatty())
