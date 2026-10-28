"""Post-dump pass (--pretty): reformat every dumped .js file in place with jsbeautifier."""

from __future__ import annotations

import os
import time

import jsbeautifier

from .log import SUCCESS, log


def _find_js_files(out_dir: str) -> list[str]:
    found = []
    for root, _dirs, files in os.walk(out_dir):
        found.extend(os.path.join(root, name) for name in files if name.lower().endswith(".js"))
    return sorted(found)


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def prettify_dir(out_dir: str) -> None:
    """Beautifies every .js file under out_dir, overwriting it. Logs one progress line per file."""
    paths = _find_js_files(out_dir)
    if not paths:
        log.info("No .js files in %s to prettify.", out_dir)
        return

    opts = jsbeautifier.default_options()
    opts.indent_size = 2
    total = len(paths)
    width = len(str(total))
    done = failed = 0
    started = time.monotonic()
    log.info("Prettifying %d .js file(s) in %s...", total, out_dir)
    for i, path in enumerate(paths, 1):
        rel = os.path.relpath(path, out_dir)
        try:
            with open(path, "rb") as f:
                raw = f.read()
            # surrogateescape round-trips any non-UTF-8 bytes untouched instead of failing the file
            log.info("[%*d/%d] %s (%s)", width, i, total, rel, _human_size(len(raw)))
            t0 = time.monotonic()
            pretty = jsbeautifier.beautify(raw.decode("utf-8", "surrogateescape"), opts)
            with open(path, "wb") as f:
                f.write(pretty.encode("utf-8", "surrogateescape"))
            log.debug("Prettified %s in %.1fs", rel, time.monotonic() - t0)
            done += 1
        except Exception as e:
            log.warning("Could not prettify %s: %s", rel, e)
            failed += 1
    log.log(SUCCESS, "Prettified %d .js file(s) in %.1fs.", done, time.monotonic() - started)
    if failed:
        log.warning("%d file(s) left as dumped.", failed)
