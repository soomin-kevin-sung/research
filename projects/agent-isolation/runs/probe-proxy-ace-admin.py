"""Admin steps of the local proxy, profile read ACE and HKLM key measurement (runs/2026-11-27-02.md).
UAC-approved batch file only.

Usage: python probe-proxy-ace-admin.py create | cleanup     (ISO_ROOT and ISO_DATE are set by the batch file)
  create   records the admin-only state, then
             - local group iso-rt-pxg (the shell group of the request; measurement only)
             - local account iso-rt-pxa1 (the shell account: standard user, Users and iso-rt-pxg)
             - local account iso-rt-pxb1 (the second standard user B: Users only)
             passwords from secrets\\pxa.json written by probe-proxy-ace.py prep
             - HKLM\\SOFTWARE\\AgentIsolationMeasure\\pw-installer-me and ...\\pw-installer-b, each with one REG_SZ
               dummy value "pw" and a protected DACL: deny KEY_ALL_ACCESS to iso-rt-pxg and CodexSandboxUsers,
               allow KEY_ALL_ACCESS to SYSTEM and Administrators, allow KEY_READ to the installer
               (pw-installer-me: the current user; pw-installer-b: user B). The parent key keeps the inherited
               DACL of HKLM\\SOFTWARE.
           then reads both keys with this elevated token (reference) and records the state again.
           No firewall rule, WFP filter or ACE outside the test folder.
  cleanup  records the state and every HKLM key whose name contains one of the two account SIDs, deletes
           HKLM\\SOFTWARE\\AgentIsolationMeasure, the profiles if any, the two accounts and the group, and records the
           state and the key scan again.
Codex and QwenPaw accounts, groups, firewall rules and WFP filters are only read (g_uacstate).
Writes local/2026-11-27-pxa/admin-<step>.json.
"""
import os
import sys
import json
import time
import ctypes
import subprocess
import importlib.util
import winreg
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-27-pxa")
os.environ.setdefault("ISO_ROOT", str(Path(os.environ["USERPROFILE"]) / "agent-isolation-pxa"))
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import ROOT, LOCAL, save, load, lookup_sid  # noqa: E402

import win32net  # noqa: E402
import win32netcon  # noqa: E402
import win32security  # noqa: E402

SHELL, USER_B, GROUP = "iso-rt-pxa1", "iso-rt-pxb1", "iso-rt-pxg"
SECRETS = ROOT / "secrets" / "pxa.json"
KEY_PARENT = r"SOFTWARE\AgentIsolationMeasure"
KEYS = {"pw-installer-me": "user", "pw-installer-b": "user_b"}
DUMMY = "iso-dummy-not-a-password"
KEY_ALL_ACCESS, KEY_READ = 0xF003F, 0x20019


def tls_admin():
    spec = importlib.util.spec_from_file_location("tlsadmin", Path(__file__).with_name("probe-tls-profile-admin.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def key_sddl(path):
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
    except OSError as e:
        return f"error:{e.winerror}"
    winreg.CloseKey(k)
    sd = win32security.GetNamedSecurityInfo("MACHINE\\" + path, win32security.SE_REGISTRY_KEY,
                                            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
    return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
        sd, win32security.SDDL_REVISION_1,
        win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)


def read_key(path):
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
    except OSError as e:
        return {"open": f"error:{e.winerror}"}
    try:
        return {"open": "ok", "value_match": winreg.QueryValueEx(k, "pw")[0] == DUMMY}
    except OSError as e:
        return {"open": "ok", "query": f"error:{e.winerror}"}
    finally:
        winreg.CloseKey(k)


def group_members():
    try:
        m, _, _ = win32net.NetLocalGroupGetMembers(None, GROUP, 2)
        return sorted(x["domainandname"].split("\\")[-1] for x in m)
    except win32net.error as e:
        return f"error:{e.winerror}"


def state(k, h, T, scan=False):
    st = k.g_uacstate(None, {})
    for name in (SHELL, USER_B):
        sid = lookup_sid(name)
        st[name] = {"sid": sid, "profile": h.profile_state(sid)}
        try:
            st[name]["groups"] = sorted(win32net.NetUserGetLocalGroups(None, name, 0)) if sid else []
        except win32net.error as e:
            st[name]["groups"] = f"error:{e.winerror}"
        if scan and sid:
            st[name]["sid_keys"] = T.sid_key_scan(sid)
    st["group_sid"] = lookup_sid(GROUP)
    st["group_members"] = group_members() if st["group_sid"] else None
    st["keys"] = {n: key_sddl(KEY_PARENT + "\\" + n) for n in KEYS}
    st["key_parent"] = key_sddl(KEY_PARENT)
    return st


def add_user(name, pw, groups):
    win32net.NetUserAdd(None, 1, {"name": name, "password": pw, "priv": win32netcon.USER_PRIV_USER,
                                  "comment": "agent-isolation measurement, deleted after the run",
                                  "flags": win32netcon.UF_SCRIPT | win32netcon.UF_DONT_EXPIRE_PASSWD
                                  | win32netcon.UF_PASSWD_CANT_CHANGE})
    for g in groups:
        members, _, _ = win32net.NetLocalGroupGetMembers(None, g, 2)
        if not any(m["domainandname"].split("\\")[-1].lower() == name for m in members):
            win32net.NetLocalGroupAddMembers(None, g, 3, [{"domainandname": name}])


def create(k, h, T):
    setup = load("setup.json")
    rec = {"before": state(k, h, T)}
    if rec["before"][SHELL]["sid"] or rec["before"][USER_B]["sid"] or rec["before"]["group_sid"]:
        raise SystemExit("measurement accounts or group already exist; run cleanup first")
    if not isinstance(rec["before"]["key_parent"], str) or not rec["before"]["key_parent"].startswith("error:2"):
        raise SystemExit(f"HKLM\\{KEY_PARENT} already exists or cannot be checked: {rec['before']['key_parent']}")
    pw = json.loads(SECRETS.read_text(encoding="utf-8"))
    users_name = win32security.LookupAccountSid(None, win32security.ConvertStringSidToSid("S-1-5-32-545"))[0]
    win32net.NetLocalGroupAdd(None, 1, {"name": GROUP, "comment": "agent-isolation measurement, deleted after the run"})
    add_user(SHELL, pw[SHELL], [users_name, GROUP])
    add_user(USER_B, pw[USER_B], [users_name])
    sids = {"user": setup["user_sid"], "user_b": lookup_sid(USER_B), "group": lookup_sid(GROUP),
            "codex_group": lookup_sid("CodexSandboxUsers")}
    rec["sids_used"] = {k2: bool(v) for k2, v in sids.items()}
    S = win32security.ConvertStringSidToSid
    winreg.CloseKey(winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, KEY_PARENT, 0, winreg.KEY_ALL_ACCESS))
    for name, installer in KEYS.items():
        path = KEY_PARENT + "\\" + name
        kk = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(kk, "pw", 0, winreg.REG_SZ, DUMMY)
        winreg.CloseKey(kk)
        dacl = win32security.ACL()
        for deny in ("group", "codex_group"):
            if sids[deny]:
                dacl.AddAccessDeniedAce(win32security.ACL_REVISION, KEY_ALL_ACCESS, S(sids[deny]))
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, KEY_ALL_ACCESS, S("S-1-5-18"))
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, KEY_ALL_ACCESS, S("S-1-5-32-544"))
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, KEY_READ, S(sids[installer]))
        win32security.SetNamedSecurityInfo("MACHINE\\" + path, win32security.SE_REGISTRY_KEY,
                                           win32security.DACL_SECURITY_INFORMATION
                                           | win32security.PROTECTED_DACL_SECURITY_INFORMATION, None, None, dacl, None)
    rec["elevated_read"] = {n: read_key(KEY_PARENT + "\\" + n) for n in KEYS}
    rec["after"] = state(k, h, T)
    return rec


def delete_tree(path):
    r = subprocess.run(["reg", "delete", "HKLM\\" + path, "/f"], capture_output=True)
    return {"exit": r.returncode, "stderr": r.stderr.decode("cp949", "replace").strip()[-300:]}


def cleanup(k, h, T):
    rec = {"before": state(k, h, T, scan=True)}
    rec["key_delete"] = delete_tree(KEY_PARENT) if not str(rec["before"]["key_parent"]).startswith("error:2") else "absent"
    for name in (SHELL, USER_B):
        sid = rec["before"][name]["sid"]
        if not sid:
            continue
        t0 = time.monotonic()
        while h.profile_state(sid)["hku_loaded"] and time.monotonic() - t0 < 120:
            time.sleep(1)
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"$p = Get-CimInstance Win32_UserProfile | Where-Object SID -eq '{sid}'; "
                            "if ($p) { $p | Remove-CimInstance; 'removed' } else { 'none' }"], capture_output=True)
        rec[f"profile_remove_{name}"] = {"hive_wait_seconds": round(time.monotonic() - t0, 1), "exit": r.returncode,
                                         "stdout": r.stdout.decode("cp949", "replace").strip(),
                                         "stderr": r.stderr.decode("cp949", "replace").strip()[-300:]}
        try:
            win32net.NetUserDel(None, name)
            rec[f"deleted_{name}"] = True
        except win32net.error as e:
            rec[f"deleted_{name}"] = f"error:{e.winerror}"
    if rec["before"]["group_sid"]:
        try:
            win32net.NetLocalGroupDel(None, GROUP)
            rec["group_deleted"] = True
        except win32net.error as e:
            rec["group_deleted"] = f"error:{e.winerror}"
    after = state(k, h, T)
    for name in (SHELL, USER_B):
        sid = rec["before"][name]["sid"]
        if sid:
            after[name]["sid_keys_old_sid"] = T.sid_key_scan(sid)
            after[name]["profile_by_old_sid"] = h.profile_state(sid)
    rec["after"] = after
    return rec


def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("run from the UAC-approved batch file (IsUserAnAdmin is false)")
    LOCAL.mkdir(parents=True, exist_ok=True)
    step = sys.argv[1]
    T = tls_admin()
    k, h = T.campaign_module(), T.host_module()
    rec = {"create": create, "cleanup": cleanup}[step](k, h, T)
    print(save(f"admin-{step}.json", rec))


if __name__ == "__main__":
    main()
