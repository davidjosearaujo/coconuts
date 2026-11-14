"""The --pretty pass: reformatting dumped .js in place with jsbeautifier.

A dumped script is whatever the engine handed over, so this pass has to survive files that are not
valid UTF-8 and files jsbeautifier chokes on, and leave those as they were rather than truncating
them or failing the run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coconuts.pretty import _find_js_files, _human_size, prettify_dir

UGLY = b"function f(){if(a){return 1}else{return 2}}"


class TestFindJsFiles:
    def test_finds_them_recursively_and_sorted(self, tmp_path: Path) -> None:
        (tmp_path / "src/app").mkdir(parents=True)
        for rel in ("b.js", "src/a.js", "src/app/c.js"):
            (tmp_path / rel).write_bytes(UGLY)
        found = _find_js_files(str(tmp_path))
        assert [Path(p).name for p in found] == ["b.js", "a.js", "c.js"]
        assert found == sorted(found), "a stable order keeps the progress lines meaningful"

    def test_the_extension_is_matched_whatever_its_case(self, tmp_path: Path) -> None:
        (tmp_path / "loud.JS").write_bytes(UGLY)
        (tmp_path / "mixed.Js").write_bytes(UGLY)
        assert len(_find_js_files(str(tmp_path))) == 2

    def test_other_files_are_left_out(self, tmp_path: Path) -> None:
        for rel in ("main.jsc", "main.luac", "data.json", "notes.txt", "jsfile"):
            (tmp_path / rel).write_bytes(UGLY)
        assert _find_js_files(str(tmp_path)) == []

    def test_a_missing_directory_is_not_an_error(self, tmp_path: Path) -> None:
        assert _find_js_files(str(tmp_path / "nope")) == []


class TestHumanSize:
    @pytest.mark.parametrize("n,expected", [
        (0, "0 B"),
        (999, "999 B"),
        (1023, "1023 B"),
        (1024, "1.0 KB"),
        (1536, "1.5 KB"),
        (1024 * 1024, "1.0 MB"),
        (1024 * 1024 * 1024, "1.0 GB"),
    ])
    def test_the_unit_turns_over_at_1024(self, n: int, expected: str) -> None:
        assert _human_size(n) == expected

    def test_bytes_are_never_shown_with_a_decimal(self) -> None:
        """Only the byte unit is whole: '1023 B', not '1023.0 B'."""
        assert all("." not in _human_size(n) for n in (0, 1, 512, 1023))


class TestPrettifyDir:
    def test_the_file_is_reformatted_in_place(self, tmp_path: Path) -> None:
        path = tmp_path / "main.js"
        path.write_bytes(UGLY)
        prettify_dir(str(tmp_path))
        out = path.read_text()
        assert out != UGLY.decode()
        assert "\n" in out, "beautified output is laid out over several lines"
        assert "function f()" in out

    def test_it_indents_with_two_spaces(self, tmp_path: Path) -> None:
        (tmp_path / "main.js").write_bytes(b"function f(){return 1}")
        prettify_dir(str(tmp_path))
        body = (tmp_path / "main.js").read_text()
        assert "\n  return 1" in body, body

    def test_nothing_to_do_is_said_plainly(self, tmp_path: Path,
                                           caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("INFO"):
            prettify_dir(str(tmp_path))
        assert "No .js files" in caplog.text

    def test_non_utf8_bytes_survive_the_round_trip(self, tmp_path: Path) -> None:
        """A dumped script can hold any bytes; surrogateescape has to give them back unchanged
        rather than replacing them or failing the file."""
        path = tmp_path / "latin.js"
        path.write_bytes(b"var s='caf\xe9';var t=1")
        prettify_dir(str(tmp_path))
        assert b"\xe9" in path.read_bytes()

    def test_a_file_that_cannot_be_beautified_is_left_as_dumped(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture) -> None:
        import jsbeautifier
        (tmp_path / "broken.js").write_bytes(UGLY)
        monkeypatch.setattr(jsbeautifier, "beautify",
                            lambda *a, **kw: (_ for _ in ()).throw(ValueError("boom")))
        with caplog.at_level("WARNING"):
            prettify_dir(str(tmp_path))
        assert (tmp_path / "broken.js").read_bytes() == UGLY
        assert "Could not prettify" in caplog.text
        assert "1 file(s) left as dumped" in caplog.text

    def test_one_bad_file_does_not_stop_the_others(
            self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "a.js").write_bytes(UGLY)
        (tmp_path / "b.js").write_bytes(UGLY)
        import jsbeautifier
        real = jsbeautifier.beautify

        def only_b(text, opts=None):
            if "1" in text and "a_marker" in text:
                raise ValueError("boom")
            return real(text, opts)

        (tmp_path / "a.js").write_bytes(b"var a_marker=1")
        monkeypatch.setattr(jsbeautifier, "beautify", only_b)
        prettify_dir(str(tmp_path))
        assert (tmp_path / "a.js").read_bytes() == b"var a_marker=1"   # left alone
        assert (tmp_path / "b.js").read_bytes() != UGLY                # still beautified

    def test_every_file_is_reported_with_its_size(self, tmp_path: Path,
                                                   caplog: pytest.LogCaptureFixture) -> None:
        for name in ("a.js", "b.js", "c.js"):
            (tmp_path / name).write_bytes(UGLY)
        with caplog.at_level("INFO"):
            prettify_dir(str(tmp_path))
        assert "[1/3]" in caplog.text and "[3/3]" in caplog.text
        assert _human_size(len(UGLY)) in caplog.text
        assert "Prettified 3 .js file(s)" in caplog.text

    def test_the_counter_is_padded_so_the_lines_align(self, tmp_path: Path,
                                                       caplog: pytest.LogCaptureFixture) -> None:
        for i in range(11):
            (tmp_path / f"f{i:02}.js").write_bytes(UGLY)
        with caplog.at_level("INFO"):
            prettify_dir(str(tmp_path))
        assert "[ 1/11]" in caplog.text, "single digits are padded to the width of the total"
        assert "[11/11]" in caplog.text
