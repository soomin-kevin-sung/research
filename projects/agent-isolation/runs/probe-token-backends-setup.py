"""Non-elevated preparation for plan-token-backends.md (section 2.1, 2.3, 5 step 1).

Creates C:\\agent-isolation-test (tools runtime, per-config workspaces, fixed-DACL targets, DPAPI
blobs, hard link, R5 test keys under HKCU\\Software\\agent-isolation-test, C2 folder under the
profile) and the Codex backup in C:\\agent-isolation-backup. targets\\admin-owned is left for the
UAC session. Writes local/2026-11-25/setup.json (kept out of the public repo).
Run with the test venv Python.
"""
import os
import sys
import uuid
import shutil
import winreg
from pathlib import Path

import ntsecuritycon as con
import win32crypt
import win32security

sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, TOOLS, PYRT, CHILD, QP_PROFILE, TARGETS, BACKUP, CONFIGS,  # noqa: E402
                                   REAL_CODEX_HOME, SID_USERS, SID_EVERYONE, token_sids, lookup_sid,
                                   icacls, protect, sddl, dacl_aces, sha256, save, ws)

if ROOT.exists():
    sys.exit(f"{ROOT} already exists; refusing to overwrite")
user_sid, logon_sid = token_sids()
codex_group = lookup_sid("CodexSandboxUsers")
rec = {"user_sid": user_sid, "logon_sid": logon_sid, "codex_group_sid": codex_group,
       "codex_accounts": {n: lookup_sid(n) for n in ("CodexSandboxOffline", "CodexSandboxOnline")}}

# ---- root, tools runtime, child program
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

# ---- QwenPaw test profile with the same DACL shape as a real profile
QP_PROFILE.mkdir()
protect(QP_PROFILE, user_sid)

# ---- per-config workspaces
for cfg in CONFIGS:
    for name in ("ws-A", "ws-B", "ws-large"):
        ws(cfg, name).mkdir(parents=True)
    a = ws(cfg, "ws-A")
    for sub in (".git", ".codex", ".agents", "ro"):
        (a / sub).mkdir()
        (a / sub / "f.txt").write_text(f"{sub}-original\n")
        (a / sub / "del.txt").write_text(f"{sub}-delete-target\n")
    (a / "existing.txt").write_text("ws-A-original\n")
    (ws(cfg, "ws-B") / "existing.txt").write_text("ws-B-original\n")  # ws-B has no .git/.agents/.codex
    large = ws(cfg, "ws-large")
    for d in range(100):
        sub = large / f"d{d:02d}"
        sub.mkdir()
        for f in range(100):
            (sub / f"f{f:02d}.txt").write_text("x")
    if cfg.startswith("codex"):
        (ROOT / cfg / "temp").mkdir()
    if cfg == "codex-unelevated":
        (ROOT / cfg / "home").mkdir()

# ---- targets with fixed DACLs
TARGETS.mkdir()
targets = {"user-only": [], "default-inherit": None, "everyone-write": [f"*{SID_EVERYONE}:(OI)(CI)M"],
           "logon-write": [f"*{logon_sid}:(OI)(CI)M"], "deny-read": [f"*{SID_USERS}:(OI)(CI)RX"],
           "dpapi": [f"*{SID_USERS}:(OI)(CI)RX"], "moved-src": [f"*{SID_USERS}:(OI)(CI)RX"],
           "hardlink-dir": [f"*{SID_USERS}:(OI)(CI)RX"]}
for name, extra in targets.items():
    d = TARGETS / name
    d.mkdir()
    if extra is not None:
        protect(d, user_sid, extra)
    (d / "f.txt").write_text(f"{name}-original\n")
(TARGETS / "deny-read" / "h.txt").write_text("hardlink-target\n")
os.link(TARGETS / "deny-read" / "h.txt", TARGETS / "hardlink-dir" / "h-link.txt")

# ---- DPAPI blobs (synthetic)
marker = f"ISO-TOKEN-BACKENDS-DPAPI-{uuid.uuid4().hex[:12]}"
(TARGETS / "dpapi" / "user.bin").write_bytes(win32crypt.CryptProtectData(marker.encode(), "iso", None, None, None, 0))
(TARGETS / "dpapi" / "machine.bin").write_bytes(
    win32crypt.CryptProtectData(marker.encode(), "iso", None, None, None, 0x4))  # CRYPTPROTECT_LOCAL_MACHINE
rec["dpapi_expected"] = marker

# ---- C2 folder directly under the real profile (deleted after measurement)
c2 = Path(os.environ["USERPROFILE"]) / "agent-isolation-c2"
c2.mkdir()
(c2 / "f.txt").write_text("c2-original\n")
rec["c2"] = str(c2)

# ---- R5 synthetic registry keys under HKCU (deleted after measurement)
KEY_ALL, KEY_WRITE = 0xF003F, 0x20006
base = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\agent-isolation-test")
r5 = {"everyone-write": SID_EVERYONE, "logon-write": logon_sid, "users-write": SID_USERS}
for name, sid in r5.items():
    k = winreg.CreateKey(base, name)
    dacl = win32security.ACL()
    for s, mask in ((user_sid, KEY_ALL), ("S-1-5-18", KEY_ALL), ("S-1-5-32-544", KEY_ALL), (sid, KEY_WRITE)):
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, con.CONTAINER_INHERIT_ACE, mask,
                                   win32security.ConvertStringSidToSid(s))
    win32security.SetSecurityInfo(k.handle, win32security.SE_REGISTRY_KEY,
                                  win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
                                  None, None, dacl, None)
    winreg.CloseKey(k)
winreg.CloseKey(base)
rec["r5_keys"] = {n: rf"Software\agent-isolation-test\{n}" for n in r5}

# ---- Codex backup (byte copy; contents are not opened or printed)
BACKUP.mkdir()
protect_backup = ["/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"]
icacls(BACKUP, *protect_backup)
if codex_group:
    icacls(BACKUP, "/deny", f"*{codex_group}:(OI)(CI)F")
secrets = REAL_CODEX_HOME / ".sandbox-secrets"
marker_file = REAL_CODEX_HOME / ".sandbox" / "setup_marker.json"
backup_rec = {"originals": {}}
shutil.copytree(secrets, BACKUP / ".sandbox-secrets")
(BACKUP / ".sandbox").mkdir()
shutil.copy2(marker_file, BACKUP / ".sandbox" / "setup_marker.json")
for p in [secrets, *secrets.iterdir(), marker_file]:
    backup_rec["originals"][str(p)] = {"sddl": sddl(p), "sha256": sha256(p) if p.is_file() else None}
for p in (BACKUP / ".sandbox-secrets").iterdir():
    backup_rec.setdefault("copies", {})[p.name] = sha256(p)
backup_rec["copies"]["setup_marker.json"] = sha256(BACKUP / ".sandbox" / "setup_marker.json")
backup_rec["backup_dacl"] = dacl_aces(BACKUP)
rec["backup"] = backup_rec

# ---- record initial DACLs of everything created
rec["dacl"] = {str(p): dacl_aces(p) for p in [ROOT, TOOLS, PYRT, QP_PROFILE, c2, *(TARGETS.iterdir()),
                                              *(ws(c, n) for c in CONFIGS for n in ("ws-A", "ws-B"))]}
print(save("setup.json", rec))
