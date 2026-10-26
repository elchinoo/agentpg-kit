"""The shared UI's regression tests under tests/ui run in node against a tiny fake DOM (no browser, no server). Skipped without node."""
import shutil
import subprocess
from pathlib import Path

import pytest

UI = Path(__file__).resolve().parent / "ui"
STATIC = Path(__file__).resolve().parent.parent / "src" / "apgkit" / "static"
SCRIPTS = sorted(p.name for p in UI.glob("*.mjs"))


@pytest.mark.skipif(shutil.which("node") is None, reason="needs node")
@pytest.mark.parametrize("script", SCRIPTS)
def test_ui_script(script):
    out = subprocess.run(["node", str(UI / script)], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
    assert out.stdout.startswith("ok:")


def test_the_shared_ui_never_builds_markup_from_strings():
    for js in STATIC.glob("*.js"):
        src = "\n".join(line.split("//")[0] for line in js.read_text().splitlines())   # comments may name the banned calls
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            assert bad not in src, f"{js.name} uses {bad}"


def test_the_shared_ui_never_uses_native_dialogs():
    import re
    for js in STATIC.glob("*.js"):
        src = "\n".join(line.split("//")[0] for line in js.read_text().splitlines())
        assert not re.search(r"(?<![\w.])(window\.)?(confirm|alert|prompt)\s*\(", src.replace("confirmDialog(", "")), f"{js.name} calls a native dialog"


def test_every_kit_rendered_form_control_has_an_accessible_name():
    import re
    for js in (STATIC / "ui.js", STATIC / "session.js"):
        src = js.read_text()
        for m in re.finditer(r'h\("(input|select|textarea)",([^\n]*)', src):
            line = m.group(2)
            ident = re.search(r'id: "([\w-]+)"', line)
            labelled = ident and f'for: "{ident.group(1)}"' in src
            assert "aria-label" in line or "...props" in line or labelled, f"{js.name}: unnamed {m.group(1)}: {line[:60]}"
    ui = (STATIC / "ui.js").read_text()
    assert '"aria-label": label || title' in ui   # promptDialog's input is named even without a visible label
