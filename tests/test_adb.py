"""Device resolution and APK pulling, against a fake `adb` rather than a real device."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from coconuts import adb
from coconuts.adb import DeviceError, SKIP_SPLIT_RE, adb_resolve_device, adb_run, pull_apks


class FakeAdb:
    """Stands in for subprocess.run. `replies` maps a joined argument string to (rc, stdout, stderr)."""

    def __init__(self, replies: dict[str, tuple[int, str, str]]) -> None:
        self.replies = replies
        self.calls: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        args = cmd[1:]
        if args[:1] == ["-s"]:
            args = args[2:]  # the serial is checked separately, via .calls
        key = " ".join(args)
        for prefix in sorted(self.replies, key=len, reverse=True):
            if key.startswith(prefix):
                rc, out, err = self.replies[prefix]
                return subprocess.CompletedProcess(cmd, rc, out, err)
        raise AssertionError(f"unexpected adb call: {key}")


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch):
    def install(replies: dict[str, tuple[int, str, str]]) -> FakeAdb:
        f = FakeAdb(replies)
        monkeypatch.setattr(adb.subprocess, "run", f)
        monkeypatch.setattr(adb, "find_adb", lambda: "adb")
        return f
    return install


BOOTED = {"shell getprop sys.boot_completed": (0, "1\n", "")}


def devices(*rows: str) -> tuple[int, str, str]:
    return 0, "List of devices attached\n" + "".join(r + "\n" for r in rows), ""


class TestResolveDevice:
    def test_the_single_ready_device_is_chosen(self, fake) -> None:
        fake({"devices": devices("ABC123\tdevice"), **BOOTED})
        assert adb_resolve_device(None) == "ABC123"

    def test_daemon_start_up_chatter_is_ignored(self, fake) -> None:
        fake({"devices": (0, "* daemon not running; starting now at tcp:5037\n* daemon started successfully\n"
                             "List of devices attached\nABC123\tdevice\n", ""), **BOOTED})
        assert adb_resolve_device(None) == "ABC123"

    def test_no_device(self, fake) -> None:
        fake({"devices": devices()})
        with pytest.raises(DeviceError, match="No Android device"):
            adb_resolve_device(None)

    def test_several_devices_need_an_explicit_choice(self, fake) -> None:
        fake({"devices": devices("A\tdevice", "B\tdevice")})
        with pytest.raises(DeviceError, match="Multiple devices.*--device"):
            adb_resolve_device(None)

    def test_an_unready_device_is_skipped_when_another_is_ready(self, fake) -> None:
        fake({"devices": devices("A\toffline", "B\tdevice"), **BOOTED})
        assert adb_resolve_device(None) == "B"

    def test_a_named_serial_is_used(self, fake) -> None:
        fake({"devices": devices("A\tdevice", "B\tdevice"), **BOOTED})
        assert adb_resolve_device("B") == "B"

    def test_an_unknown_serial_lists_what_is_connected(self, fake) -> None:
        fake({"devices": devices("A\tdevice")})
        with pytest.raises(DeviceError, match=r"'Z' not found.*A \[device\]"):
            adb_resolve_device("Z")

    @pytest.mark.parametrize("state,message", [
        ("unauthorized", "unauthorized"), ("offline", "offline"), ("recovery", "not ready"),
    ])
    def test_a_device_that_cannot_be_used_says_why(self, fake, state: str, message: str) -> None:
        fake({"devices": devices(f"A\t{state}")})
        with pytest.raises(DeviceError, match=message):
            adb_resolve_device(None)

    def test_a_device_still_booting(self, fake) -> None:
        fake({"devices": devices("A\tdevice"), "shell getprop sys.boot_completed": (0, "\n", "")})
        with pytest.raises(DeviceError, match="hasn't finished booting"):
            adb_resolve_device(None)

    def test_the_serial_is_passed_to_later_commands(self, fake) -> None:
        f = fake({"devices": devices("A\tdevice"), **BOOTED})
        adb_resolve_device("A")
        assert f.calls[-1][:3] == ["adb", "-s", "A"]


class TestAdbRun:
    def test_missing_adb(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*a, **k):
            raise FileNotFoundError
        monkeypatch.setattr(adb.subprocess, "run", boom)
        monkeypatch.setattr(adb, "find_adb", lambda: None)
        with pytest.raises(DeviceError, match="adb not found"):
            adb_run(None, ["devices"])

    def test_a_hung_command_times_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def hang(cmd, **k):
            raise subprocess.TimeoutExpired(cmd, 5)
        monkeypatch.setattr(adb.subprocess, "run", hang)
        monkeypatch.setattr(adb, "find_adb", lambda: "adb")
        with pytest.raises(DeviceError, match="timed out"):
            adb_run(None, ["devices"], timeout=5)

    def test_failure_reports_the_first_real_line_of_output(self, fake) -> None:
        fake({"pull x y": (1, "", "* daemon started\nadb: error: remote object 'x' does not exist\n")})
        with pytest.raises(DeviceError, match="remote object 'x' does not exist"):
            adb_run(None, ["pull", "x", "y"])

    def test_check_false_returns_the_failure(self, fake) -> None:
        fake({"shell false": (1, "", "")})
        assert adb_run(None, ["shell", "false"], check=False).returncode == 1


class TestSplitFilter:
    @pytest.mark.parametrize("path,skipped", [
        ("/data/app/x/base.apk", False),
        ("/data/app/x/split_config.arm64_v8a.apk", True),
        ("/data/app/x/split_config.en.apk", True),
        ("/data/app/x/split_config.xxhdpi.apk", True),
        ("/data/app/x/split_assets.apk", False),
        ("/data/app/x/split_feature.apk", False),
    ])
    def test_config_splits_only(self, path: str, skipped: bool) -> None:
        assert bool(SKIP_SPLIT_RE.search(path)) is skipped


class TestPullApks:
    PM = ("package:/data/app/x/base.apk\npackage:/data/app/x/split_config.en.apk\n"
          "package:/data/app/x/split_config.arm64_v8a.apk\npackage:/data/app/x/split_assets.apk\n")

    def test_config_splits_are_skipped_by_default(self, fake, tmp_path: Path) -> None:
        f = fake({"shell pm path com.x": (0, self.PM, ""), "pull": (0, "", "")})
        local = pull_apks("com.x", None, str(tmp_path))
        pulled = [c[2] for c in f.calls if c[1] == "pull"]
        assert pulled == ["/data/app/x/base.apk", "/data/app/x/split_assets.apk"]
        assert [Path(p).name for p in local] == ["00_base.apk", "01_split_assets.apk"]

    def test_all_splits_pulls_everything(self, fake, tmp_path: Path) -> None:
        fake({"shell pm path com.x": (0, self.PM, ""), "pull": (0, "", "")})
        assert len(pull_apks("com.x", None, str(tmp_path), all_splits=True)) == 4

    def test_only_config_splits_are_kept_rather_than_pulling_nothing(self, fake, tmp_path: Path) -> None:
        only = "package:/data/app/x/split_config.en.apk\n"
        fake({"shell pm path com.x": (0, only, ""), "pull": (0, "", "")})
        assert len(pull_apks("com.x", None, str(tmp_path))) == 1

    def test_a_missing_package(self, fake, tmp_path: Path) -> None:
        fake({"shell pm path com.x": (1, "", "")})
        with pytest.raises(DeviceError, match="not found on device"):
            pull_apks("com.x", None, str(tmp_path))

    def test_an_adb_error_is_not_reported_as_a_missing_package(self, fake, tmp_path: Path) -> None:
        fake({"shell pm path com.x": (1, "", "error: device offline\n")})
        with pytest.raises(DeviceError, match="Could not query.*device offline"):
            pull_apks("com.x", None, str(tmp_path))
