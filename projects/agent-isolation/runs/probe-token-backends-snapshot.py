"""Non-elevated state snapshot for plan-token-backends.md section 3.

Usage: python probe-token-backends-snapshot.py <label>
Writes local/2026-11-25/state-<label>.json. Secrets are hashed, never printed. Admin-only items
(WFP filters, batch-logon right list) are recorded separately in the UAC session.
"""
import os
import sys
import json
import hashlib
import subprocess
import winreg
from pathlib import Path

import win32file
import win32security

sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, REAL_CODEX_HOME, save, dacl_aces, sha256, token_sids,  # noqa: E402
                                   lookup_sid, process_categories)

label = sys.argv[1]
user_sid, _ = token_sids()
profile = Path(os.environ["USERPROFILE"])
codex_group = lookup_sid("CodexSandboxUsers")


def ps(cmd):
    r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd + " | ConvertTo-Json -Depth 3 -Compress"],
                       capture_output=True)
    out = r.stdout.decode("utf-8", "replace").strip()
    try:
        return json.loads(out) if out else None
    except json.JSONDecodeError:
        return {"raw": out[:500], "err": r.stderr.decode("utf-8", "replace")[:300]}


def safe(fn):
    try:
        return fn()
    except Exception as e:  # record, do not stop
        return f"error:{type(e).__name__}:{e}"


def explicit(path):
    return [a for a in dacl_aces(path) if not a["flags"] & 0x10]


def has_group_ace(path):
    return any(a["sid"] == codex_group for a in dacl_aces(path))


s = {"label": label}
s["accounts"] = safe(lambda: ps("Get-LocalUser | Where-Object { $_.Name -like 'CodexSandbox*' -or $_.Name -like 'qwenpaw_*' } | "
                                "Select-Object Name,Enabled,@{n='PasswordLastSet';e={$_.PasswordLastSet.ToString('o')}},"
                                "@{n='LastLogon';e={if($_.LastLogon){$_.LastLogon.ToString('o')}}}"))
s["groups"] = {g: safe(lambda g=g: ps(f"Get-LocalGroupMember -Group '{g}' -ErrorAction SilentlyContinue | Select-Object Name"))
               for g in ("CodexSandboxUsers", "QwenpawUsers")}
s["firewall"] = safe(lambda: ps("Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'codex_sandbox_*' "
                                "-or $_.DisplayName -like 'QwenPaw_Block_*' } | Select-Object DisplayName,Direction,Action,Enabled"))
s["services"] = safe(lambda: ps("Get-Service seclogon, *Codex* -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType"))


def winsta_desktop():
    import win32service
    out = {}
    for name, h in (("winsta", win32service.GetProcessWindowStation()),
                    ("desktop", win32service.GetThreadDesktop(win32api_thread()))):
        sd = win32security.GetSecurityInfo(h.handle if hasattr(h, "handle") else h, win32security.SE_WINDOW_OBJECT,
                                           win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        out[name] = [{"sid": win32security.ConvertSidToStringSid(dacl.GetAce(i)[2]),
                      "mask": hex(dacl.GetAce(i)[1] & 0xffffffff)} for i in range(dacl.GetAceCount())]
    return out


def win32api_thread():
    import win32api
    return win32api.GetCurrentThreadId()


s["winsta_desktop"] = safe(winsta_desktop)


def nul_dacl():
    h = win32file.CreateFile(r"\\.\NUL", 0x20000, 3, None, 3, 0, None)
    sd = win32security.GetSecurityInfo(h.handle, 6, win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    h.Close()
    return [{"sid": win32security.ConvertSidToStringSid(dacl.GetAce(i)[2]), "mask": hex(dacl.GetAce(i)[1] & 0xffffffff)}
            for i in range(dacl.GetAceCount())]


s["nul_dacl"] = safe(nul_dacl)


def reg_values(root, path):
    out = {}
    with winreg.OpenKey(root, path) as k:
        i = 0
        while True:
            try:
                n, v, _ = winreg.EnumValue(k, i)
                out[n] = v
            except OSError:
                break
            i += 1
    return out


s["winlogon_userlist"] = safe(lambda: reg_values(winreg.HKEY_LOCAL_MACHINE,
                                                 r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"))
s["hklm_openai_codex"] = safe(lambda: sorted(reg_values(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\OpenAI\Codex").keys()))


def profile_list():
    out = []
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
            if "codexsandbox" in path.lower() or "qwenpaw" in path.lower():
                out.append(path)
    return sorted(out)


s["profile_list"] = safe(profile_list)
s["profile_dirs"] = sorted(p.name for p in Path(r"C:\Users").iterdir()
                           if p.name.lower().startswith(("codexsandbox", "qwenpaw_")))


def codex_state():
    h = REAL_CODEX_HOME
    st = {"config_sha": sha256(h / "config.toml"),
          "auth_mtime": (h / "auth.json").stat().st_mtime if (h / "auth.json").exists() else None,
          "cap_sid_sha": sha256(h / "cap_sid"), "cap_sid_size": (h / "cap_sid").stat().st_size}
    try:
        cap = json.loads((h / "cap_sid").read_text())
        st["cap_sid_counts"] = {k: (len(v) if isinstance(v, (dict, list)) else 1) for k, v in cap.items()}
    except (ValueError, OSError) as e:
        st["cap_sid_counts"] = f"error:{e}"
    aces = dacl_aces(h)
    st["home_dacl"] = {"total": len(aces), "deny": sum(1 for a in aces if a["type"] == 1)}
    sb = h / ".sandbox"
    st["sandbox_files"] = {p.name: sha256(p) for p in sorted(sb.iterdir()) if p.is_file() and not p.name.endswith(".log")}
    marker = json.loads((sb / "setup_marker.json").read_text())
    st["marker_version"] = marker.get("version")
    sec = h / ".sandbox-secrets"
    st["secrets"] = {p.name: {"size": p.stat().st_size, "mtime": p.stat().st_mtime, "sha256": sha256(p)}
                     for p in sorted(sec.iterdir())}
    st["sandbox_bin"] = {p.name: p.stat().st_size for p in sorted((h / ".sandbox-bin").iterdir())}
    return st


s["codex"] = safe(codex_state)


def qwenpaw_state():
    root = profile / ".qwenpaw"
    items = sorted((str(p.relative_to(root)), p.stat().st_size, int(p.stat().st_mtime))
                   for p in root.rglob("*") if p.is_file()) if root.exists() else []
    pk = Path(os.environ["LOCALAPPDATA"]) / "Packages"
    maps = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings"
    names = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, maps) as k:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return {"real_qwenpaw_files": len(items), "real_qwenpaw_sha": hashlib.sha256(repr(items).encode()).hexdigest(),
            "packages_qwenpaw": sorted(p.name for p in pk.glob("qwenpaw_*")), "hkcu_ac_mappings": len(names)}


s["qwenpaw"] = safe(qwenpaw_state)


def file_aces():
    out = {}
    dirs = []
    if ROOT.exists():
        dirs = [ROOT, *(d for d in ROOT.iterdir() if d.is_dir())]
        for top in list(dirs[1:]):
            dirs += [d for d in top.iterdir() if d.is_dir() and d.name != "pyrt"]
        dirs += [d for d in ROOT.glob("*/ws-A/*") if d.is_dir()]
    for p in dirs:
        out[str(p)] = explicit(p)
    temp = Path(os.environ["LOCALAPPDATA"]) / "Temp"
    out[str(temp)] = explicit(temp)
    out[str(profile)] = explicit(profile)
    venv = Path(os.environ["LOCALAPPDATA"]) / "agent-isolation-qwenpaw-2.3.0.post1"
    out[str(venv)] = explicit(venv)
    return out


s["explicit_aces"] = safe(file_aces)
s["profile_children_with_codex_group_ace"] = safe(lambda: sorted(p.name for p in profile.iterdir() if safe(lambda p=p: has_group_ace(p)) is True))
s["protect_credentials_codex_ace"] = {n: safe(lambda n=n: has_group_ace(profile / "AppData" / "Roaming" / "Microsoft" / n))
                                     for n in ("Protect", "Credentials")}
sandbox_sids = {x for x in (lookup_sid("CodexSandboxOffline"), lookup_sid("CodexSandboxOnline")) if x}
cats = process_categories(user_sid, sandbox_sids)
s["processes"] = {"sandbox_account": sum(1 for c in cats.values() if c == "sandbox_account"), "total": len(cats)}
print(save(f"state-{label}.json", s))
