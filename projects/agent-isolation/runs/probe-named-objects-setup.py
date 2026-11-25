"""Non-elevated preparation for the named object and pipe measurements (plan-token-backends.md N, Q).

A reduced version of probe-token-backends-setup.py: only what N and Q need. Creates
C:\\agent-isolation-test (tools runtime and the in-sandbox program, per-config ws-A / ws-B with the same
layout as 2026-11-25 so Codex finds its existing cap_sid entries, qwenpaw-profile, Codex temp folders)
and the Codex backup in C:\\agent-isolation-backup (plan 2.3). No targets, DPAPI data, profile folder or
HKCU test keys are created. Writes local/2026-11-26/setup.json (kept out of the public repo).
Run with the test venv Python.
"""
import os
import sys
import shutil
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, TOOLS, PYRT, CHILD, QP_PROFILE, BACKUP, CONFIGS, REAL_CODEX_HOME,  # noqa: E402
                                   token_sids, lookup_sid, icacls, protect, sddl, dacl_aces, sha256, save, ws)

for p in (ROOT, BACKUP):
    if p.exists():
        sys.exit(f"{p} already exists; refusing to overwrite")
user_sid, logon_sid = token_sids()
codex_group = lookup_sid("CodexSandboxUsers")
rec = {"user_sid": user_sid, "logon_sid": logon_sid, "codex_group_sid": codex_group,
       "codex_accounts": {n: lookup_sid(n) for n in ("CodexSandboxOffline", "CodexSandboxOnline")}}

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

for cfg in CONFIGS:
    for name in ("ws-A", "ws-B"):
        ws(cfg, name).mkdir(parents=True)
    a = ws(cfg, "ws-A")
    for sub in (".git", ".codex", ".agents", "ro"):
        (a / sub).mkdir()
        (a / sub / "f.txt").write_text(f"{sub}-original\n")
    (a / "existing.txt").write_text("ws-A-original\n")
    (ws(cfg, "ws-B") / "existing.txt").write_text("ws-B-original\n")
    if cfg.startswith("codex"):
        (ROOT / cfg / "temp").mkdir()
    if cfg == "codex-unelevated":
        (ROOT / cfg / "home").mkdir()

# Codex backup (byte copy; contents are not opened or printed)
BACKUP.mkdir()
icacls(BACKUP, "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
if codex_group:
    icacls(BACKUP, "/deny", f"*{codex_group}:(OI)(CI)F")
secrets = REAL_CODEX_HOME / ".sandbox-secrets"
marker_file = REAL_CODEX_HOME / ".sandbox" / "setup_marker.json"
backup_rec = {"originals": {}, "copies": {}}
shutil.copytree(secrets, BACKUP / ".sandbox-secrets")
(BACKUP / ".sandbox").mkdir()
shutil.copy2(marker_file, BACKUP / ".sandbox" / "setup_marker.json")
for p in [secrets, *secrets.iterdir(), marker_file]:
    backup_rec["originals"][str(p)] = {"sddl": sddl(p), "sha256": sha256(p) if p.is_file() else None}
for p in (BACKUP / ".sandbox-secrets").iterdir():
    backup_rec["copies"][p.name] = sha256(p)
backup_rec["copies"]["setup_marker.json"] = sha256(BACKUP / ".sandbox" / "setup_marker.json")
backup_rec["backup_dacl"] = dacl_aces(BACKUP)
rec["backup"] = backup_rec
rec["dacl"] = {str(p): dacl_aces(p) for p in [ROOT, TOOLS, PYRT, QP_PROFILE,
                                              *(ws(c, n) for c in CONFIGS for n in ("ws-A", "ws-B"))]}
print(save("setup.json", rec))
