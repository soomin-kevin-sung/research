"""Minimal re-creation of C:\\agent-isolation-test for the Codex elevated R3 measurement.

Only what R3 needs: the independent Python runtime and child program under tools\\, and
codex-elevated\\ws-A, ws-B and temp. The paths are the same as in the main setup, so Codex reuses
its existing cap_sid entries. Does not touch setup.json, HKCU, the profile or the Codex backup.
Run with the test venv Python; delete C:\\agent-isolation-test after the measurement.
"""
import sys
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import ROOT, TOOLS, PYRT, CHILD, ws  # noqa: E402

if ROOT.exists():
    sys.exit(f"{ROOT} already exists; refusing to overwrite")
ROOT.mkdir()
TOOLS.mkdir()
src = Path(sys.base_prefix)
PYRT.mkdir()
for f in ("python.exe", "python3.dll", "python312.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
    shutil.copy2(src / f, PYRT / f)
shutil.copytree(src / "DLLs", PYRT / "DLLs")
shutil.copytree(src / "Lib", PYRT / "Lib", ignore=shutil.ignore_patterns(
    "site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3", "__pycache__", "pydoc_data"))
shutil.copy2(Path(__file__).with_name("probe-token-backends-child.py"), CHILD)
for name in ("ws-A", "ws-B"):
    ws("codex-elevated", name).mkdir(parents=True)
    (ws("codex-elevated", name) / "existing.txt").write_text(f"{name}-original\n")
(ROOT / "codex-elevated" / "temp").mkdir()
print("prepared", ROOT)
