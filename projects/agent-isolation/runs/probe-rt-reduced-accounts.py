"""Admin steps of the reduced restricting SID measurement (runs/2026-11-26-03.md). UAC-approved session only.

Usage: python probe-rt-reduced-accounts.py create | create-one | bno-add | cleanup
  create-one  (2026-11-26-04) the group and iso-rt-sbx1 only, no device ACE. With ISO_ROOT and ISO_DATE set
           by the batch file, the passwords and records use that run's folders.
  create   records the admin-only state, creates the measurement group iso-rt-sbx-users and the accounts
           iso-rt-sbx1 and iso-rt-sbx2 (passwords from C:\\agent-isolation-test\\secrets\\sbx.json, written by
           probe-rt-reduced-setup.py prep). Adds iso-rt-sbx2 to the DACLs of \\Device\\Null, \\Device\\CNG and
           \\Device\\KsecDD with the mask Everyone has (read, write, execute), as QwenPaw admin does for
           \\\\.\\NUL: these devices give write only to Everyone, which the reduced list drops. iso-rt-sbx1 gets
           no device ACE. Records the state again.
  bno-add  adds iso-rt-sbx2 to the DACL of the global named object directory \\BaseNamedObjects with what
           Everyone has there (query, traverse, create object, create subdirectory, read control). Git Bash
           creates its directory there and fails without it under the reduced list. The DACL is saved first.
  cleanup  restores the saved device and \\BaseNamedObjects DACLs, deletes both accounts, their profiles if
           any, and the group, records the admin-only state.
Only the measurement accounts and group named above are created or deleted. Codex and QwenPaw accounts,
groups, firewall rules and WFP filters are only read. Writes local/2026-11-26-rt/accounts-<step>.json.
Device DACL changes are in memory only (a restart also restores them).
"""
import os
import sys
import json
import time
import ctypes
import subprocess
import importlib.util
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26-rt")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import ROOT, LOCAL, save, lookup_sid  # noqa: E402

import win32net  # noqa: E402
import win32netcon  # noqa: E402
import win32security  # noqa: E402

ACCOUNTS = ("iso-rt-sbx1", "iso-rt-sbx2")
GROUP = "iso-rt-sbx-users"
DEVICE_FIX_ACCOUNT = "iso-rt-sbx2"
DEVICES = ("\\Device\\Null", "\\Device\\CNG", "\\Device\\KsecDD")
SECRETS = ROOT / "secrets" / "sbx.json"
DEV_ORIGINAL = LOCAL / "device-dacl-original.json"
BNO = "\\BaseNamedObjects"
BNO_ORIGINAL = LOCAL / "bno-dacl-original.json"


def is_elevated():
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def campaign_module():
    spec = importlib.util.spec_from_file_location("campaign", Path(__file__).with_name("probe-token-backends-campaign.py"))
    k = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(k)
    k.SETUP = {"codex_accounts": {n: lookup_sid(n) for n in ("CodexSandboxOffline", "CodexSandboxOnline")}}
    return k


class _US(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ushort), ("MaximumLength", ctypes.c_ushort), ("Buffer", ctypes.c_void_p)]


class _OA(ctypes.Structure):
    _fields_ = [("Length", ctypes.c_ulong), ("RootDirectory", ctypes.c_void_p), ("ObjectName", ctypes.POINTER(_US)),
                ("Attributes", ctypes.c_ulong), ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p)]


class _IOSB(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_void_p)]


_nt = ctypes.WinDLL("ntdll")
_nt.NtOpenFile.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong, ctypes.POINTER(_OA), ctypes.POINTER(_IOSB),
                           ctypes.c_ulong, ctypes.c_ulong]
_nt.NtClose.argtypes = [ctypes.c_void_p]


def dev_open(path, access):
    """NtOpenFile on the device object itself (no file name below it)."""
    b = ctypes.create_unicode_buffer(path)
    us = _US(len(path) * 2, len(path) * 2 + 2, ctypes.cast(b, ctypes.c_void_p))
    oa = _OA(ctypes.sizeof(_OA), None, ctypes.pointer(us), 0x40, None, None)
    h, io = ctypes.c_void_p(), _IOSB()
    st = _nt.NtOpenFile(ctypes.byref(h), access, ctypes.byref(oa), ctypes.byref(io), 7, 0)
    if st:
        raise OSError(f"NtOpenFile {path}: 0x{st & 0xffffffff:08x}")
    return h.value


def dev_sddl(path):
    h = dev_open(path, 0x20000)  # READ_CONTROL
    try:
        sd = win32security.GetSecurityInfo(h, win32security.SE_KERNEL_OBJECT, win32security.DACL_SECURITY_INFORMATION)
        return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            sd, win32security.SDDL_REVISION_1, win32security.DACL_SECURITY_INFORMATION)
    finally:
        _nt.NtClose(h)


def dev_set(path, sddl):
    sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, win32security.SDDL_REVISION_1)
    h = dev_open(path, 0x20000 | 0x40000)  # READ_CONTROL | WRITE_DAC
    try:
        win32security.SetSecurityInfo(h, win32security.SE_KERNEL_OBJECT, win32security.DACL_SECURITY_INFORMATION,
                                      None, None, sd.GetSecurityDescriptorDacl(), None)
    finally:
        _nt.NtClose(h)


_nt.NtOpenDirectoryObject.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong, ctypes.POINTER(_OA)]


def dir_open(path, access):
    b = ctypes.create_unicode_buffer(path)
    us = _US(len(path) * 2, len(path) * 2 + 2, ctypes.cast(b, ctypes.c_void_p))
    oa = _OA(ctypes.sizeof(_OA), None, ctypes.pointer(us), 0x40, None, None)
    h = ctypes.c_void_p()
    st = _nt.NtOpenDirectoryObject(ctypes.byref(h), access, ctypes.byref(oa))
    if st:
        raise OSError(f"NtOpenDirectoryObject {path}: 0x{st & 0xffffffff:08x}")
    return h.value


def bno_sddl():
    h = dir_open(BNO, 0x20000)
    try:
        sd = win32security.GetSecurityInfo(h, win32security.SE_KERNEL_OBJECT, win32security.DACL_SECURITY_INFORMATION)
        return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            sd, win32security.SDDL_REVISION_1, win32security.DACL_SECURITY_INFORMATION)
    finally:
        _nt.NtClose(h)


def bno_set(sddl):
    sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, win32security.SDDL_REVISION_1)
    h = dir_open(BNO, 0x20000 | 0x40000)
    try:
        win32security.SetSecurityInfo(h, win32security.SE_KERNEL_OBJECT, win32security.DACL_SECURITY_INFORMATION,
                                      None, None, sd.GetSecurityDescriptorDacl(), None)
    finally:
        _nt.NtClose(h)


def profiles():
    """ProfileList entries and C:\\Users folders of the measurement accounts (by SID and by name)."""
    import winreg
    sids = {n: lookup_sid(n) for n in ACCOUNTS}
    out = {"sids": sids, "profilelist": {}, "user_dirs": sorted(p.name for p in Path(r"C:\Users").iterdir()
                                                                 if p.name.lower().startswith("iso-rt"))}
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") as k:
        i = 0
        while True:
            try:
                sid = winreg.EnumKey(k, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(k, sid) as sk:
                    path = winreg.QueryValueEx(sk, "ProfileImagePath")[0]
            except OSError:
                continue
            if sid in sids.values() or "iso-rt" in path.lower():
                out["profilelist"][sid] = path
    return out


def state(k):
    st = k.g_uacstate(None, {})
    st["measurement_accounts"] = {n: lookup_sid(n) for n in ACCOUNTS}
    st["measurement_group"] = lookup_sid(GROUP)
    try:
        members, _, _ = win32net.NetLocalGroupGetMembers(None, GROUP, 2)
        st["measurement_group_members"] = sorted(m["domainandname"].split("\\")[-1] for m in members)
    except win32net.error as e:
        st["measurement_group_members"] = f"error:{e.winerror}"
    st["profiles"] = profiles()
    st["device_sddl"] = {d: dev_sddl(d) for d in DEVICES}
    st["bno_sddl"] = bno_sddl()
    return st


def create(k, accounts=ACCOUNTS, devices=True):
    rec = {"before": state(k)}
    if any(rec["before"]["measurement_accounts"].values()) or rec["before"]["measurement_group"]:
        raise SystemExit("measurement accounts or group already exist; run cleanup first")
    pw = json.loads(SECRETS.read_text(encoding="utf-8"))
    users_name = win32security.LookupAccountSid(None, win32security.ConvertStringSidToSid("S-1-5-32-545"))[0]
    win32net.NetLocalGroupAdd(None, 1, {"name": GROUP, "comment": "agent-isolation measurement, deleted after the run"})
    for n in accounts:
        win32net.NetUserAdd(None, 1, {"name": n, "password": pw[n], "priv": win32netcon.USER_PRIV_USER,
                                      "comment": "agent-isolation measurement, deleted after the run",
                                      "flags": win32netcon.UF_SCRIPT | win32netcon.UF_DONT_EXPIRE_PASSWD
                                      | win32netcon.UF_PASSWD_CANT_CHANGE})
        win32net.NetLocalGroupAddMembers(None, GROUP, 3, [{"domainandname": n}])
        members, _, _ = win32net.NetLocalGroupGetMembers(None, users_name, 2)
        if not any(m["domainandname"].split("\\")[-1].lower() == n for m in members):
            win32net.NetLocalGroupAddMembers(None, users_name, 3, [{"domainandname": n}])
    if not devices:
        rec["after"] = state(k)
        return rec
    # devices: save the DACLs, then add the fix account with the mask Everyone has (0x1201bf)
    original = {d: dev_sddl(d) for d in DEVICES}
    DEV_ORIGINAL.write_text(json.dumps({"sddl": original, "time": time.time()}), encoding="utf-8")
    sid = lookup_sid(DEVICE_FIX_ACCOUNT)
    for d in DEVICES:
        dev_set(d, original[d] + f"(A;;0x1201bf;;;{sid})")
    rec["device_fix_account"] = DEVICE_FIX_ACCOUNT
    rec["after"] = state(k)
    return rec


def bno_add(k):
    rec = {"before": state(k)}
    if BNO_ORIGINAL.exists():
        raise SystemExit("bno-add already ran (saved DACL exists)")
    original = bno_sddl()
    BNO_ORIGINAL.write_text(json.dumps({"sddl": original, "time": time.time()}), encoding="utf-8")
    bno_set(original + f"(A;;CCDCLCSWRC;;;{lookup_sid(DEVICE_FIX_ACCOUNT)})")
    rec["after"] = state(k)
    return rec


def cleanup(k):
    rec = {"before": state(k)}
    if BNO_ORIGINAL.exists():
        orig = json.loads(BNO_ORIGINAL.read_text(encoding="utf-8"))["sddl"]
        bno_set(orig)
        rec["bno_restored"] = bno_sddl() == orig
    sids = rec["before"]["measurement_accounts"]
    if DEV_ORIGINAL.exists():
        orig = json.loads(DEV_ORIGINAL.read_text(encoding="utf-8"))["sddl"]
        rec["devices_restored"] = {}
        for d, sddl in orig.items():
            dev_set(d, sddl)
            rec["devices_restored"][d] = dev_sddl(d) == sddl
    for n in ACCOUNTS:
        try:
            win32net.NetUserDel(None, n)
            rec.setdefault("deleted", []).append(n)
        except win32net.error as e:
            rec.setdefault("delete_errors", {})[n] = e.winerror
    for sid in filter(None, sids.values()):  # profile folder and ProfileList key, if a profile was ever created
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"Get-CimInstance Win32_UserProfile | Where-Object SID -eq '{sid}' | Remove-CimInstance"],
                           capture_output=True)
        rec.setdefault("profile_remove_exit", []).append(r.returncode)
    try:
        win32net.NetLocalGroupDel(None, GROUP)
        rec["group_deleted"] = True
    except win32net.error as e:
        rec["group_deleted"] = f"error:{e.winerror}"
    rec["after"] = state(k)
    return rec


def main():
    if not is_elevated():
        raise SystemExit("run from the UAC-approved batch file (IsUserAnAdmin is false)")
    LOCAL.mkdir(parents=True, exist_ok=True)
    step = sys.argv[1]
    k = campaign_module()
    rec = {"create": create, "bno-add": bno_add, "cleanup": cleanup,
           "create-one": lambda k: create(k, ACCOUNTS[:1], devices=False)}[step](k)
    print(save(f"accounts-{step}.json", rec))


if __name__ == "__main__":
    main()
