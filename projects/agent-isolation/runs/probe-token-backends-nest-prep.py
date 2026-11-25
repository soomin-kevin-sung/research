"""Minimal re-creation of C:\\agent-isolation-test for the nested-folder measurement (g_nest).

Creates the independent Python runtime and child program under tools\\, the QwenPaw test profile,
ws-A for the four configs (with ws-A\\.key: secret.txt and decoy files for g_nestc), the Codex temp folders and
test CODEX_HOME, and
targets\\nest-ro (f.txt, w\\f.txt, w-empty\\) and targets\\nest-deny (f.txt, open\\g.txt, open-w\\h.txt).
The nest folders inherit the root DACL. Paths for ws-A and temp are the same as in the main setup,
so Codex reuses those cap_sid entries. Does not touch setup.json, HKCU, the profile or the Codex backup.
Run with the test venv Python; delete C:\\agent-isolation-test after the measurement.
"""
import sys
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import ROOT, TOOLS, PYRT, CHILD, QP_PROFILE, TARGETS, protect, token_sids, ws  # noqa: E402

if ROOT.exists():
    sys.exit(f"{ROOT} already exists; refusing to overwrite")
user_sid, _ = token_sids()
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
QP_PROFILE.mkdir()
protect(QP_PROFILE, user_sid)
for cfg in ("qwenpaw-unelevated", "qwenpaw-admin", "codex-unelevated", "codex-elevated"):
    ws(cfg, "ws-A").mkdir(parents=True)
    (ws(cfg, "ws-A") / "existing.txt").write_text("ws-A-original\n")
    key = ws(cfg, "ws-A") / ".key"  # g_nestc: deny-read folder inside the writable workspace
    key.mkdir()
    (key / "secret.txt").write_text("key-secret\n")
    for tag in [*(f"b{t}" for t in range(1, 6)), *(f"c{t}" for t in range(1, 6)), "final"]:
        (key / f"decoy-{tag}.txt").write_text("decoy\n")
for d in ("codex-unelevated/temp", "codex-unelevated/home", "codex-elevated/temp"):
    (ROOT / d).mkdir(parents=True)
files = {"nest-ro/f.txt": "nest-ro-parent\n", "nest-ro/w/f.txt": "nest-ro-child\n",
         "nest-deny/f.txt": "nest-deny-parent\n", "nest-deny/open/g.txt": "nest-deny-open\n",
         "nest-deny/open-w/h.txt": "nest-deny-open-w\n"}
for rel, text in files.items():
    p = TARGETS / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
(TARGETS / "nest-ro" / "w-empty").mkdir()
print("prepared", ROOT)
