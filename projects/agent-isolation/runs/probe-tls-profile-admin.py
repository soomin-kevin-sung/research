"""Admin steps of the schannel and profile measurement (runs/2026-11-26-05.md). UAC-approved batch file only.

Usage: python probe-tls-profile-admin.py create | cleanup     (ISO_ROOT and ISO_DATE are set by the batch file)
  create   records the admin-only state, creates the local account iso-rt-tls1 (standard user, member of
           Users only, password from secrets\\tls.json written by probe-tls-profile.py prep), records the state
           again. No group, no firewall rule, no ACE outside the test folder.
  cleanup  records the state and every HKLM key whose name contains the account SID, waits up to 120 s for the
           account's hive to unload, deletes the profile (Win32_UserProfile, which removes the folder and the
           ProfileList entry), deletes the account, and records the state and the HKLM key scan again.
Codex and QwenPaw accounts, groups, firewall rules and WFP filters are only read (g_uacstate).
Writes local/2026-11-26-tls/admin-<step>.json.
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

os.environ.setdefault("ISO_DATE", "2026-11-26-tls")
os.environ.setdefault("ISO_ROOT", str(Path(os.environ["USERPROFILE"]) / "agent-isolation-tls"))
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import ROOT, LOCAL, save, lookup_sid  # noqa: E402

import win32net  # noqa: E402
import win32netcon  # noqa: E402
import win32security  # noqa: E402

ACCOUNT = "iso-rt-tls1"
SECRETS = ROOT / "secrets" / "tls.json"


def campaign_module():
    spec = importlib.util.spec_from_file_location("campaign", Path(__file__).with_name("probe-token-backends-campaign.py"))
    k = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(k)
    k.SETUP = {"codex_accounts": {n: lookup_sid(n) for n in ("CodexSandboxOffline", "CodexSandboxOnline")}}
    return k


def host_module():
    spec = importlib.util.spec_from_file_location("host", Path(__file__).with_name("probe-tls-profile.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def sid_key_scan(sid):
    """Key names under HKLM\\SOFTWARE and HKLM\\SYSTEM (without the CurrentControlSet link) that contain the SID."""
    hits, stats = [], {"keys": 0, "unreadable": 0}
    needle = sid.upper()
    stack = [("SOFTWARE",), ("SYSTEM",)]
    t0 = time.monotonic()
    while stack:
        parts = stack.pop()
        path = "\\".join(parts)
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_ENUMERATE_SUB_KEYS | 0x00000100)
        except OSError:
            stats["unreadable"] += 1
            continue
        stats["keys"] += 1
        i = 0
        while True:
            try:
                name = winreg.EnumKey(k, i)
            except OSError:
                break
            i += 1
            if parts == ("SYSTEM",) and name.lower() == "currentcontrolset":
                continue
            if needle in name.upper():
                hits.append(path + "\\" + name)
            stack.append(parts + (name,))
        winreg.CloseKey(k)
    stats["seconds"] = round(time.monotonic() - t0, 1)
    return {"stats": stats, "hits": hits[:200], "hit_count": len(hits)}


def state(k, h, scan=False):
    st = k.g_uacstate(None, {})
    sid = lookup_sid(ACCOUNT)
    st["account_sid"] = sid
    st["profile"] = h.profile_state(sid)
    try:
        st["account_groups"] = sorted(win32net.NetUserGetLocalGroups(None, ACCOUNT, 0)) if sid else []
    except win32net.error as e:
        st["account_groups"] = f"error:{e.winerror}"
    if scan and sid:
        st["sid_keys"] = sid_key_scan(sid)
    return st


def create(k, h):
    rec = {"before": state(k, h)}
    if rec["before"]["account_sid"]:
        raise SystemExit(f"{ACCOUNT} already exists; run cleanup first")
    pw = json.loads(SECRETS.read_text(encoding="utf-8"))[ACCOUNT]
    users_name = win32security.LookupAccountSid(None, win32security.ConvertStringSidToSid("S-1-5-32-545"))[0]
    win32net.NetUserAdd(None, 1, {"name": ACCOUNT, "password": pw, "priv": win32netcon.USER_PRIV_USER,
                                  "comment": "agent-isolation measurement, deleted after the run",
                                  "flags": win32netcon.UF_SCRIPT | win32netcon.UF_DONT_EXPIRE_PASSWD
                                  | win32netcon.UF_PASSWD_CANT_CHANGE})
    members, _, _ = win32net.NetLocalGroupGetMembers(None, users_name, 2)
    if not any(m["domainandname"].split("\\")[-1].lower() == ACCOUNT for m in members):
        win32net.NetLocalGroupAddMembers(None, users_name, 3, [{"domainandname": ACCOUNT}])
    rec["after"] = state(k, h)
    return rec


def cleanup(k, h):
    rec = {"before": state(k, h, scan=True)}
    sid = rec["before"]["account_sid"]
    t0 = time.monotonic()
    while sid and h.profile_state(sid)["hku_loaded"] and time.monotonic() - t0 < 120:
        time.sleep(1)
    rec["hive_wait_seconds"] = round(time.monotonic() - t0, 1)
    if sid:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"$p = Get-CimInstance Win32_UserProfile | Where-Object SID -eq '{sid}'; "
                            "if ($p) { $p | Remove-CimInstance; 'removed' } else { 'none' }"],
                           capture_output=True)
        rec["profile_remove"] = {"exit": r.returncode, "stdout": r.stdout.decode("cp949", "replace").strip(),
                                 "stderr": r.stderr.decode("cp949", "replace").strip()[-500:]}
        try:
            win32net.NetUserDel(None, ACCOUNT)
            rec["account_deleted"] = True
        except win32net.error as e:
            rec["account_deleted"] = f"error:{e.winerror}"
    after = state(k, h)
    if sid:
        after["sid_keys"] = sid_key_scan(sid)
        after["profile_by_old_sid"] = h.profile_state(sid)
    rec["after"] = after
    return rec


def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("run from the UAC-approved batch file (IsUserAnAdmin is false)")
    LOCAL.mkdir(parents=True, exist_ok=True)
    step = sys.argv[1]
    k, h = campaign_module(), host_module()
    rec = {"create": create, "cleanup": cleanup}[step](k, h)
    print(save(f"admin-{step}.json", rec))


if __name__ == "__main__":
    main()
