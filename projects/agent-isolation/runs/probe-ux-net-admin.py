"""Admin steps of the recycle bin, clipboard and network measurement (runs/2026-11-27-01.md). UAC-approved batch only.

Usage: python probe-ux-net-admin.py create | cleanup     (ISO_ROOT and ISO_DATE are set by the batch file)
  create   records the admin-only state, then
             - creates the local account iso-rt-ux1 (standard user, Users only, password from secrets\\ux.json)
             - shares %ISO_ROOT%\\share as iso-ux-share (share permission Everyone read; the folder allows Users read
               and holds one test file)
             - packet capture with pktmon at the network adapters, filtered to 192.0.2.1 only (the documentation
               address the shell tries to reach over SMB). Skipped when pktmon already has filters.
           and records the state again. No group, firewall rule or WFP filter is added.
  cleanup  records the state, every HKLM key whose name contains the account SID, the number of recycle bin items
           named iso-rb-* in each C:\\$Recycle.Bin folder (other items are only counted) and the C$ share
           permissions (read only), then
             - stops pktmon, converts the capture to text, counts packets to and from 192.0.2.1, removes the filter
             - lists BITS jobs of all users whose display name starts with iso-ux- and removes them
             - removes the share
             - stops the WebClient service if it was stopped before the measurement and is running now
             - deletes the account's recycle bin folder C:\\$Recycle.Bin\\<SID>, the profile if any, the account
           and records the state and the HKLM key scan again.
Codex and QwenPaw accounts, groups, firewall rules and WFP filters are only read (g_uacstate).
Writes local/2026-11-27-ux/admin-<step>.json.
"""
import os
import re
import sys
import json
import time
import ctypes
import subprocess
import importlib.util
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-27-ux")
os.environ.setdefault("ISO_ROOT", str(Path(os.environ["USERPROFILE"]) / "agent-isolation-ux"))
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import ROOT, LOCAL, save, load, lookup_sid  # noqa: E402

import win32net  # noqa: E402
import win32netcon  # noqa: E402
import win32security  # noqa: E402

ACCOUNT = "iso-rt-ux1"
SECRETS = ROOT / "secrets" / "ux.json"
SHARE, SHARE_NAME = ROOT / "share", "iso-ux-share"
TESTNET = "192.0.2.1"
PKT_ETL, PKT_TXT = LOCAL / "pktmon.etl", LOCAL / "pktmon.txt"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def tls_admin():
    spec = importlib.util.spec_from_file_location("tlsadmin", Path(__file__).with_name("probe-tls-profile-admin.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run(argv, timeout=180):
    r = subprocess.run(argv, capture_output=True, timeout=timeout)
    enc = "utf-8" if argv[0] in (PS, "pktmon") else "cp949"  # pktmon writes UTF-8
    return {"exit": r.returncode, "stdout": r.stdout.decode(enc, "replace").strip()[-3000:],
            "stderr": r.stderr.decode(enc, "replace").strip()[-800:]}


def ps(script, timeout=180):
    return run([PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + script], timeout)


def shares():
    out, resume = [], 0
    while True:
        data, _, resume = win32net.NetShareEnum(None, 0, resume)
        out += [d["netname"] for d in data]
        if not resume:
            return sorted(out)


def iso_bits_jobs():
    # OwnerAccount is an NTAccount, not a string. The 2026-11-27-01 run called .Split on it directly, so every
    # matching job wrote an error to stderr and stdout stayed empty (runs/2026-11-27-01.md, PC state section).
    return ps("Get-BitsTransfer -AllUsers | Where-Object DisplayName -like 'iso-ux-*' | ForEach-Object { "
              "([string]$_.OwnerAccount).Split('\\')[-1] + '|' + $_.DisplayName + '|' + $_.JobState }")


def bin_scan(account_sid, user_sid):
    """Per recycle bin folder: how many $I files name an original file that starts with iso-rb-. Other items are
    only counted, their names are not kept."""
    out = {}
    root = Path("C:\\$Recycle.Bin")
    for d in root.iterdir():
        cat = ("account" if d.name == account_sid else "user" if d.name == user_sid else
               d.name if d.name.count("-") <= 3 else "other_account")
        ours = total = 0
        try:
            for p in d.iterdir():
                if not p.name.startswith("$I"):
                    continue
                total += 1
                b = p.read_bytes()
                name = ""
                if len(b) >= 28 and int.from_bytes(b[:8], "little") == 2:
                    n = int.from_bytes(b[24:28], "little")
                    name = b[28:28 + 2 * n].decode("utf-16-le", "replace").rstrip("\0")
                if Path(name).name.startswith("iso-rb-"):
                    ours += 1
            res = {"iso_rb_items": ours, "i_files": total}
        except OSError as e:
            res = f"error:{e.winerror}"
        out.setdefault(cat, []).append(res)
    return out


def service_state(name):
    r = ps(f"(Get-Service {name}).Status")
    return r["stdout"]


def state(k, h, T, scan=False):
    st = k.g_uacstate(None, {})
    sid = lookup_sid(ACCOUNT)
    st["account_sid"] = sid
    st["profile"] = h.profile_state(sid)
    try:
        st["account_groups"] = sorted(win32net.NetUserGetLocalGroups(None, ACCOUNT, 0)) if sid else []
    except win32net.error as e:
        st["account_groups"] = f"error:{e.winerror}"
    st["shares"] = shares()
    st["webclient"] = service_state("WebClient")
    st["bits_iso_jobs_all_users"] = iso_bits_jobs()["stdout"].splitlines()
    st["account_bin_exists"] = bool(sid) and (Path("C:\\$Recycle.Bin") / sid).exists()
    st["pktmon_status"] = run(["pktmon", "status"])["stdout"][-600:]
    if scan and sid:
        st["sid_keys"] = T.sid_key_scan(sid)
    return st


def create(k, h, T):
    rec = {"before": state(k, h, T)}
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
    # share: Everyone read at the share level (0x1200a9); the folder DACL decides the rest
    sd = win32security.SECURITY_DESCRIPTOR()
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, 0x1200A9, win32security.ConvertStringSidToSid("S-1-1-0"))
    sd.SetSecurityDescriptorDacl(True, dacl, False)
    try:
        win32net.NetShareAdd(None, 502, {"netname": SHARE_NAME, "type": win32netcon.STYPE_DISKTREE,
                                         "remark": "agent-isolation measurement", "permissions": 0, "max_uses": -1,
                                         "current_uses": 0, "path": str(SHARE), "passwd": None,
                                         "security_descriptor": sd})
        rec["share"] = "created"
    except win32net.error as e:
        rec["share"] = f"error:{e.winerror}:{e.strerror}"
    flt = run(["pktmon", "filter", "list"])
    rec["pktmon_filters_before"] = flt
    existing = [ln for ln in flt["stdout"].splitlines() if re.match(r"^\s*\d+\s", ln)]
    if existing:
        rec["pktmon"] = "skipped: pktmon already has filters"
    else:
        rec["pktmon_filter_add"] = run(["pktmon", "filter", "add", "iso-ux-testnet", "-i", TESTNET])
        rec["pktmon_start"] = run(["pktmon", "start", "--capture", "--comp", "nics", "--file-name", str(PKT_ETL),
                                   "--file-size", "16"])
        rec["pktmon"] = "started" if rec["pktmon_start"]["exit"] == 0 else "start_failed"
    rec["after"] = state(k, h, T)
    return rec


def cleanup(k, h, T):
    setup = load("setup.json")
    rec = {"before": state(k, h, T, scan=True)}
    sid = rec["before"]["account_sid"]
    rec["bin_scan_before"] = bin_scan(sid, setup.get("user_sid"))
    rec["c_share_access"] = ps("Get-SmbShareAccess -Name 'C$' | ForEach-Object { $_.AccountName + '|' + "
                               "$_.AccessControlType + '|' + $_.AccessRight }")["stdout"].splitlines()
    created = load("admin-create.json") if (LOCAL / "admin-create.json").exists() else {}
    if created.get("pktmon") == "started":
        rec["pktmon_stop"] = run(["pktmon", "stop"])
        rec["pktmon_etl2txt"] = run(["pktmon", "etl2txt", str(PKT_ETL), "--out", str(PKT_TXT)], timeout=600)
        lines = []
        if PKT_TXT.exists():
            # etl2txt writes UTF-16 with a BOM (seen 2026-11-27-01). The capture held only the 3 header events then.
            raw = PKT_TXT.read_bytes()
            text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
            lines = [ln for ln in text.splitlines() if TESTNET in ln]
        rec["pktmon_testnet_lines"] = len(lines)
        rec["pktmon_testnet_sample"] = [ln[:300] for ln in lines[:12]]
        rec["pktmon_filter_remove"] = run(["pktmon", "filter", "remove"])
    rec["bits_before"] = iso_bits_jobs()
    rec["bits_remove"] = ps("Get-BitsTransfer -AllUsers | Where-Object DisplayName -like 'iso-ux-*' | Remove-BitsTransfer")
    rec["bits_after"] = iso_bits_jobs()
    if SHARE_NAME in shares():
        try:
            win32net.NetShareDel(None, SHARE_NAME, 0)
            rec["share_removed"] = True
        except win32net.error as e:
            rec["share_removed"] = f"error:{e.winerror}"
    before_wc = (setup.get("services_before") or {}).get("WebClient") or {}
    now_wc = service_state("WebClient")
    rec["webclient"] = {"before_measurement": before_wc.get("state") if isinstance(before_wc, dict) else before_wc,
                        "at_cleanup": now_wc}
    if isinstance(before_wc, dict) and before_wc.get("state") == 1 and now_wc.lower() == "running":
        rec["webclient"]["stop"] = ps("Stop-Service WebClient -Force; (Get-Service WebClient).Status")
    t0 = time.monotonic()
    while sid and h.profile_state(sid)["hku_loaded"] and time.monotonic() - t0 < 120:
        time.sleep(1)
    rec["hive_wait_seconds"] = round(time.monotonic() - t0, 1)
    if sid:
        b = Path("C:\\$Recycle.Bin") / sid
        if b.exists():
            rec["account_bin_listing"] = run(["cmd", "/d", "/c", "dir", "/a", "/b", str(b)])["stdout"].splitlines()[:40]
            rec["account_bin_remove"] = run(["cmd", "/d", "/c", "rd", "/s", "/q", str(b)])
        rec["account_bin_exists_after"] = b.exists()
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"$p = Get-CimInstance Win32_UserProfile | Where-Object SID -eq '{sid}'; "
                            "if ($p) { $p | Remove-CimInstance; 'removed' } else { 'none' }"], capture_output=True)
        rec["profile_remove"] = {"exit": r.returncode, "stdout": r.stdout.decode("cp949", "replace").strip(),
                                 "stderr": r.stderr.decode("cp949", "replace").strip()[-500:]}
        try:
            win32net.NetUserDel(None, ACCOUNT)
            rec["account_deleted"] = True
        except win32net.error as e:
            rec["account_deleted"] = f"error:{e.winerror}"
    after = state(k, h, T)
    after["bin_scan"] = bin_scan(sid, setup.get("user_sid"))
    if sid:
        after["sid_keys"] = T.sid_key_scan(sid)
        after["profile_by_old_sid"] = h.profile_state(sid)
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
