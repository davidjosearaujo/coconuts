"""Runs the Frida agent's behaviour tests (tests/frida_agent_test.js) under Node.

The agent is a template with __PLACEHOLDER__ tokens, so the variants it has to cope with are
rendered here through build_frida_script() -- the same path the real tool uses -- and handed to
the JS suite, which drives them against a stubbed Frida runtime.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

import coconuts.frida_dump
from coconuts.frida_dump import build_frida_script

TESTS_DIR = Path(__file__).parent
AGENT = Path(coconuts.frida_dump.__file__).parent / "frida_hook.js"
LUA_BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxLuaJavaBridge_callLuaFunctionWithString"
JS_BRIDGE = "Java_org_cocos2dx_lib_Cocos2dxJavascriptJavaBridge_evalString"

# Offsets must match DUMP_OFF / KEY_OFF in frida_agent_test.js.
VARIANTS = {
    "lua.js": (LUA_BRIDGE, None, None, False),
    "js_offsets.js": (JS_BRIDGE, 0x200, 0x300, False),
    "stdstring.js": (JS_BRIDGE, None, 0x300, True),
    "badsym.js": ("Java_org_cocos2dx_lib_NoSuchJavaBridge_nope", None, None, False),
}


def test_agent_is_valid_javascript() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    subprocess.run([node, "--check", str(AGENT)], check=True)


def test_agent_behaviour(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")

    rendered = tmp_path / "rendered"
    rendered.mkdir()
    for name, args in VARIANTS.items():
        (rendered / name).write_text(build_frida_script(*args), encoding="utf-8")

    result = subprocess.run(
        [node, str(TESTS_DIR / "frida_agent_test.js"), str(rendered)],
        capture_output=True, text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        pytest.fail(f"agent behaviour tests failed:\n{result.stdout}\n{result.stderr}")


def test_placeholders_are_all_substituted() -> None:
    """A leftover __TOKEN__ would be a ReferenceError the moment the agent loads on a device."""
    for args in VARIANTS.values():
        assert "__" not in build_frida_script(*args).replace("__dl__", ""), args
