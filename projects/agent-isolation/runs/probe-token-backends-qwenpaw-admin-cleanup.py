"""Removes what QwenPaw's own cleanup left after the QwenPaw admin campaign (UAC-approved session only).

Scope is limited to SIDs recorded in local/2026-11-25/qwenpaw-admin-accounts.json (QwenPaw sandbox accounts
that no longer resolve) and their capability SIDs, plus the QwenpawUsers group:
  1. ProfileList keys whose ProfileImagePath is C:\\Users\\qwenpaw_* and whose folder is gone
  2. SeBatchLogonRight entries for those user SIDs
  3. WinSta0 / Default desktop ACEs and \\\\.\\NUL device ACEs for those user and capability SIDs
  4. QwenpawUsers ACEs under the measurement venv and the .qwenpaw_acl_granted marker
  5. the QwenpawUsers group, only when it has no members
Every step records its before and after state in local/2026-11-25/qwenpaw-admin-leftover-cleanup.json.
"""
import os
import sys
import json
import ctypes
import subprocess
import winreg
from pathlib import Path

import win32file
import win32net
import win32security as ws
import win32service

sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import LOCAL, save  # noqa: E402

if not ctypes.windll.shell32.IsUserAnAdmin():
    raise SystemExit("needs the UAC-approved session")

VENV = Path(os.environ["LOCALAPPDATA"]) / "agent-isolation-qwenpaw-2.3.0.post1"
PL = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
known = json.loads((LOCAL / "qwenpaw-admin-accounts.json").read_text(encoding="utf-8"))


def resolves(sid):
    try:
        ws.LookupAccountSid(None, ws.ConvertStringSidToSid(sid))
        return True
    except ws.error:
        return False


users = sorted(s for s in known if not resolves(s))
caps = sorted({v["cap_sid"] for v in known.values() if v.get("cap_sid")})
targets = set(users) | set(caps)
out = {"known_accounts": len(known), "users_not_resolving": len(users), "cap_sids": len(caps), "steps": {}}


def step(name, fn):
    try:
        out["steps"][name] = fn()
    except Exception as e:  # keep going; each step is independent
        out["steps"][name] = {"error": f"{type(e).__name__}:{e}"}
    save("qwenpaw-admin-leftover-cleanup.json", out)
    print(name, json.dumps(out["steps"][name], ensure_ascii=False)[:200], flush=True)


def profile_list():
    done, skipped = [], []
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, PL, 0, winreg.KEY_READ | winreg.KEY_WRITE) as root:
        for sid in users:
            try:
                with winreg.OpenKey(root, sid) as k:
                    path = winreg.QueryValueEx(k, "ProfileImagePath")[0]
            except OSError:
                skipped.append([sid, "no_key"])
                continue
            if not Path(path).name.startswith("qwenpaw_") or Path(path).exists():
                skipped.append([sid, "path_check_failed"])
                continue
            winreg.DeleteKey(root, sid)
            done.append(sid)
    left = []
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, PL) as root:
        for sid in users:
            try:
                winreg.CloseKey(winreg.OpenKey(root, sid))
                left.append(sid)
            except OSError:
                pass
    return {"deleted": len(done), "skipped": skipped, "remaining": len(left)}


def batch_logon():
    h = ws.LsaOpenPolicy(None, 0x000F0FFF)
    try:
        before = {ws.ConvertSidToStringSid(x) for x in ws.LsaEnumerateAccountsWithUserRight(h, "SeBatchLogonRight")}
        removed, other_rights = 0, {}
        for sid in users:
            if sid not in before:
                continue
            psid = ws.ConvertStringSidToSid(sid)
            rights = list(ws.LsaEnumerateAccountRights(h, psid))
            if set(rights) - {"SeBatchLogonRight"}:
                other_rights[sid] = rights
            ws.LsaRemoveAccountRights(h, psid, False, ("SeBatchLogonRight",))
            removed += 1
        after = {ws.ConvertSidToStringSid(x) for x in ws.LsaEnumerateAccountsWithUserRight(h, "SeBatchLogonRight")}
    finally:
        ws.LsaClose(h)
    return {"before_total": len(before), "removed": removed, "other_rights": other_rights,
            "after_total": len(after), "after_target_sids": len(after & set(users))}


def strip_aces(get, put):
    sd = get()
    dacl = sd.GetSecurityDescriptorDacl()
    before = dacl.GetAceCount()
    for i in reversed(range(before)):
        if ws.ConvertSidToStringSid(dacl.GetAce(i)[-1]) in targets:
            dacl.DeleteAce(i)
    removed = before - dacl.GetAceCount()
    if removed:
        put(dacl)
    return {"aces_before": before, "removed": removed, "aces_after": get().GetSecurityDescriptorDacl().GetAceCount()}


def window_objects():
    res = {}
    access = 0x20000 | 0x40000  # READ_CONTROL | WRITE_DAC
    for name, h in (("winsta", win32service.OpenWindowStation("WinSta0", False, access)),
                    ("desktop", win32service.OpenDesktop("Default", 0, False, access))):
        try:
            res[name] = strip_aces(
                lambda: ws.GetSecurityInfo(h, ws.SE_WINDOW_OBJECT, ws.DACL_SECURITY_INFORMATION),
                lambda d: ws.SetSecurityInfo(h, ws.SE_WINDOW_OBJECT, ws.DACL_SECURITY_INFORMATION, None, None, d, None))
        finally:
            h.CloseDesktop() if name == "desktop" else h.CloseWindowStation()
    return res


def nul_device():
    h = win32file.CreateFile(r"\\.\NUL", 0x20000 | 0x40000, 3, None, 3, 0, None)
    try:
        return strip_aces(
            lambda: ws.GetSecurityInfo(h.handle, ws.SE_KERNEL_OBJECT, ws.DACL_SECURITY_INFORMATION),
            lambda d: ws.SetSecurityInfo(h.handle, ws.SE_KERNEL_OBJECT, ws.DACL_SECURITY_INFORMATION, None, None, d, None))
    finally:
        h.Close()


def group_sid():
    try:
        return ws.ConvertSidToStringSid(ws.LookupAccountName(None, "QwenpawUsers")[0])
    except ws.error:
        return None


def venv_acl():
    g = group_sid()
    marker = VENV / ".qwenpaw_acl_granted"
    res = {"group_found": g is not None, "marker_before": marker.exists()}
    if g:
        p = subprocess.run(["icacls", str(VENV), "/remove:g", f"*{g}", "/T", "/C", "/Q"], capture_output=True)
        res["icacls_exit"] = p.returncode
        res["icacls_tail"] = p.stdout.decode("mbcs", "replace")[-200:]
        d = ws.GetNamedSecurityInfo(str(VENV), ws.SE_FILE_OBJECT, ws.DACL_SECURITY_INFORMATION).GetSecurityDescriptorDacl()
        res["root_aces_for_group_after"] = sum(1 for i in range(d.GetAceCount())
                                               if ws.ConvertSidToStringSid(d.GetAce(i)[-1]) == g)
    marker.unlink(missing_ok=True)
    res["marker_after"] = marker.exists()
    return res


def group():
    if group_sid() is None:
        return {"present": False}
    members = win32net.NetLocalGroupGetMembers(None, "QwenpawUsers", 0)[0]
    if members:
        return {"present": True, "members": len(members), "deleted": False}
    win32net.NetLocalGroupDel(None, "QwenpawUsers")
    return {"present": True, "members": 0, "deleted": group_sid() is None}


step("profile_list", profile_list)
step("batch_logon_right", batch_logon)
step("window_objects", window_objects)
step("nul_device", nul_device)
step("venv_acl", venv_acl)
step("qwenpaw_group", group)
print("done", flush=True)
