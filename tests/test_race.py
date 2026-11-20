"""The static+Frida race in main(), decided by the test rather than by timing.

Both tracks are replaced by fakes that block on the events the real ones are handed, so each
scenario has exactly one possible outcome: no sleeps, no clock, no flakiness. What is under test is
main()'s own arbitration -- which track's key is used, whether the loser is told to stop, whether a
captured key is verified before being trusted, and what that leaves for the offline pass.
"""

from __future__ import annotations

import sys
import threading
import time
import types
from pathlib import Path

import pytest

from coconuts.ciphers import normalize_key

from .conftest import KEY_TEXT, LUAJIT_CHUNK, PUC_CHUNK, SIGN, asset_source, encrypt_asset

KEY = normalize_key(KEY_TEXT)
WRONG_KEY = normalize_key(b"notthekey")
BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxLuaJavaBridge_callLuaFunctionWithString"
WAIT = 10  # a bound on a wait that should return at once; only a hung test ever reaches it


class FakeDevice:
    id = "fake-device"


class Race:
    """The fakes for one race, plus what each track was told and asked to do."""

    def __init__(self) -> None:
        self.frida_called = threading.Event()
        self.static_called = threading.Event()
        self.static_aborted: bool | None = None     # did the static track see the abort signal?
        self.frida_aborted: bool | None = None
        self.extract: dict | None = None            # the arguments the offline pass was given

    # -- the two tracks ------------------------------------------------------------------
    def frida(self, key: bytes | None, *, wait_for_static: bool = False,
              after_static_entered: bool = False,
              aes: tuple | None = None, sign: bytes | None = None):
        """A fake run_frida_race that hands back `key`.

        `after_static_entered` holds the key back until the static track is actually inside its
        search, which is the only way to test that the abort reaches a search already running:
        win sooner and main()'s worker skips the search outright instead.
        """
        def run(_device, _package, _script, _writer, _timeout, _live, static_won,
                dynamic_won=None, aes_box=None, sign_box=None):
            self.frida_called.set()
            if after_static_entered:
                self.static_called.wait(WAIT)
            if wait_for_static:
                static_won.wait(WAIT)
            self.frida_aborted = static_won.is_set()
            if aes is not None:
                aes_box.update(key=aes[0], iv=aes[1], flags=aes[2])
            if sign is not None:
                sign_box["sign"] = sign
            return key
        return run

    def static(self, key: bytes | None, *, wait_for_frida: bool = False):
        """A fake recover_key_static that hands back `key`."""
        def run(_lib, _entries, sign=None, abort_event=None, high_prob_done=None):
            self.static_called.set()
            if high_prob_done is not None:
                high_prob_done.set()
            if wait_for_frida and abort_event is not None:
                abort_event.wait(WAIT)
            self.static_aborted = bool(abort_event and abort_event.is_set())
            return key
        return run


@pytest.fixture
def race(monkeypatch: pytest.MonkeyPatch) -> Race:
    """Everything outside main()'s arbitration replaced: the device, the hook resolution, and
    (by default) the two tracks, which each test sets to the outcome it is about."""
    r = Race()
    frida_mod = types.ModuleType("frida")
    frida_mod.get_usb_device = lambda timeout=None: FakeDevice()
    frida_mod.get_device = lambda serial, timeout=None: FakeDevice()
    monkeypatch.setitem(sys.modules, "frida", frida_mod)

    def resolve(lib_path, abort_event=None, high_prob_done=None, force_heavy=False):
        # Resolving the hook offsets means radare2 analysis, which in a real run takes far longer
        # than collecting the APK's scripts. So this returns only once the static track has
        # settled -- won outright, or entered its search -- which is what puts the two tracks in
        # a defined order without a sleep or a clock to tune.
        deadline = time.monotonic() + WAIT
        while time.monotonic() < deadline:
            if (abort_event is not None and abort_event.is_set()) or r.static_called.is_set():
                break
            time.sleep(0.002)
        return BRIDGE, None, None, False, None

    monkeypatch.setattr("coconuts.__main__.resolve_frida_targets", resolve)
    monkeypatch.setattr("coconuts.__main__.build_frida_script",
                        lambda *a, **kw: "// no agent in this test")
    return r


def apk_with_encrypted_scripts(tmp_path: Path) -> str:
    """Two encrypted scripts, because the signature prefix is detected from what they share: one
    sample alone leaves it unknown and nothing decrypts."""
    return asset_source(tmp_path, "apk", {
        "src/main.luac": encrypt_asset(LUAJIT_CHUNK),
        "src/app/MyApp.luac": encrypt_asset(PUC_CHUNK),
    })


def run_main(tmp_path: Path, apk: str, *extra: str) -> tuple[int, Path]:
    from coconuts.__main__ import main
    out = tmp_path / "out"
    lib = tmp_path / "libcocos2dlua.so"
    lib.write_bytes(b"\x7fELF" + b"\0" * 64)   # never read: both tracks are fakes
    code = main(["--apk", apk, "--package", "com.example.game", "--lib", str(lib),
                 "-o", str(out), *extra])
    return code, out


def record_extract(monkeypatch: pytest.MonkeyPatch, r: Race, written: int = 1) -> None:
    """Captures what main() hands to the offline pass instead of extracting for real."""
    def fake(apks, key, lib_path, out_dir, forced_sign=None, preloaded_entries=None,
             aes=None, exact_sign=None):
        r.extract = {"apks": apks, "key": key, "lib_path": lib_path, "aes": aes,
                     "exact_sign": exact_sign, "forced_sign": forced_sign,
                     "entries": preloaded_entries}
        return written
    monkeypatch.setattr("coconuts.__main__.extract_offline", fake)


class TestWhoWins:
    def test_frida_wins_and_its_key_is_used(self, tmp_path: Path, race: Race,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(KEY))
        monkeypatch.setattr("coconuts.__main__.recover_key_static",
                            race.static(None, wait_for_frida=True))
        code, out = run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert code == 0
        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK
        assert race.frida_called.is_set()

    def test_the_static_track_is_told_to_stop_when_frida_wins(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch) -> None:
        """The loser has to be signalled, or a Tier-3 brute force keeps a finished run alive."""
        monkeypatch.setattr("coconuts.__main__.run_frida_race",
                            race.frida(KEY, after_static_entered=True))
        monkeypatch.setattr("coconuts.__main__.recover_key_static",
                            race.static(None, wait_for_frida=True))
        run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert race.static_called.is_set(), "the search has to be running for the abort to matter"
        assert race.static_aborted is True

    def test_static_wins_and_frida_is_never_spawned(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch) -> None:
        """Spawning the game is the expensive, visible half: once the key is known from the
        library there is no reason to touch the device at all."""
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(None))
        monkeypatch.setattr("coconuts.__main__.recover_key_static", race.static(KEY))
        code, out = run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert code == 0
        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK
        assert race.static_called.is_set()
        assert not race.frida_called.is_set(), "the game was spawned after the race was over"

    def test_the_static_key_wins_when_both_tracks_find_one(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch) -> None:
        """Both can finish: the static key came from the library itself, so it is preferred and
        the captured one is not even verified."""
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(WRONG_KEY))
        monkeypatch.setattr("coconuts.__main__.recover_key_static", race.static(KEY))
        record_extract(monkeypatch, race)
        code, _out = run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert code == 0
        assert race.extract["key"] == KEY

    def test_neither_track_finds_a_key(self, tmp_path: Path, race: Race,
                                       monkeypatch: pytest.MonkeyPatch,
                                       caplog: pytest.LogCaptureFixture) -> None:
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(None))
        monkeypatch.setattr("coconuts.__main__.recover_key_static", race.static(None))
        with caplog.at_level("ERROR"):
            code, out = run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert code == 0          # the run completes; it just has nothing to write
        assert not (out / "src/main.luac").exists()
        assert "No working key found" in caplog.text


class TestKeyVerification:
    def test_a_captured_key_that_works_is_verified_and_reported(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture) -> None:
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(KEY))
        monkeypatch.setattr("coconuts.__main__.recover_key_static", race.static(None))
        with caplog.at_level("INFO"):
            run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert "Key verified against 2 script(s)" in caplog.text

    def test_a_captured_key_that_does_not_decrypt_is_dropped(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture) -> None:
        """A hook can read a key the game uses for something else -- a real game handed over one
        that decrypts none of its scripts. Trusting it would write 508 files of garbage."""
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(WRONG_KEY))
        monkeypatch.setattr("coconuts.__main__.recover_key_static",
                            race.static(None, wait_for_frida=True))
        record_extract(monkeypatch, race)
        with caplog.at_level("INFO"):
            run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert "doesn't decrypt the APK's scripts" in caplog.text
        assert race.extract["key"] is None, "the rejected key must not reach the offline pass"

    def test_the_search_frida_cut_short_is_resumed(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture) -> None:
        """The static track stopped because Frida said it had the key. Now that the key turns out
        to be wrong, the offline pass gets the library back so it can search again."""
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(WRONG_KEY))
        monkeypatch.setattr("coconuts.__main__.recover_key_static",
                            race.static(None, wait_for_frida=True))
        record_extract(monkeypatch, race)
        with caplog.at_level("INFO"):
            run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert "Resuming the search that Frida cut short" in caplog.text
        assert race.extract["lib_path"] is not None

    def test_a_search_that_ran_to_the_end_is_not_repeated(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch) -> None:
        """The static track finished and found nothing, so handing the library to the offline
        pass would only repeat the same failed search."""
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(None))
        monkeypatch.setattr("coconuts.__main__.recover_key_static", race.static(None))
        record_extract(monkeypatch, race)
        run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert race.extract["lib_path"] is None

    def test_the_signature_seen_with_the_key_is_passed_on(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch) -> None:
        """The hook sees the key and the signature together, which beats guessing one."""
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(KEY, sign=SIGN))
        monkeypatch.setattr("coconuts.__main__.recover_key_static", race.static(None))
        record_extract(monkeypatch, race)
        run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert race.extract["exact_sign"] == SIGN

    def test_a_signature_is_not_passed_on_with_a_static_key(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch) -> None:
        """It was only ever verified alongside the captured key, which lost."""
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(KEY, sign=SIGN))
        monkeypatch.setattr("coconuts.__main__.recover_key_static", race.static(KEY))
        record_extract(monkeypatch, race)
        run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert race.extract["exact_sign"] is None


class TestShortCircuits:
    def test_an_unencrypted_game_ends_the_race_before_the_device(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch,
            caplog: pytest.LogCaptureFixture) -> None:
        """A game whose scripts ship as plaintext needs no key, so nothing should be spawned --
        this is what a real Lua game turned out to be."""
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(KEY))
        monkeypatch.setattr("coconuts.__main__.recover_key_static", race.static(None))
        apk = asset_source(tmp_path, "apk", {"src/main.luac": LUAJIT_CHUNK})
        with caplog.at_level("INFO"):
            code, out = run_main(tmp_path, apk)
        assert code == 0
        assert "none of the scripts are encrypted" in caplog.text.lower()
        assert not race.frida_called.is_set()
        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK

    def test_captured_aes_goes_down_the_aes_path(
            self, tmp_path: Path, race: Race, monkeypatch: pytest.MonkeyPatch) -> None:
        """EncryptManager wraps every asset, so a captured AES key routes around XXTEA entirely.
        flags=5 is the roll count the agent reports."""
        aes = (b"\x01" * 32, b"\x02" * 16, 5)
        # No XXTEA key from either track: the AES box alone decides, so neither needs to wait.
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(None, aes=aes))
        monkeypatch.setattr("coconuts.__main__.recover_key_static", race.static(None))
        record_extract(monkeypatch, race)
        run_main(tmp_path, apk_with_encrypted_scripts(tmp_path))
        assert race.extract["aes"] is not None
        assert race.extract["aes"][0] == aes[0] and race.extract["aes"][1] == aes[1]
        assert race.extract["key"] is None

    def test_static_only_never_touches_frida(self, tmp_path: Path, race: Race,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("coconuts.__main__.run_frida_race", race.frida(KEY))
        code, out = run_main(tmp_path, apk_with_encrypted_scripts(tmp_path),
                             "--static-only", "--key", KEY_TEXT.decode())
        assert code == 0
        assert not race.frida_called.is_set()
        assert (out / "src/main.luac").read_bytes() == LUAJIT_CHUNK
