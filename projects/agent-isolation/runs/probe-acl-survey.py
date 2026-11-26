"""Read-only survey: where Everyone or the user's logon SID can write (runs/2026-11-26-04.md).

Requested by another session that keeps the Codex elevated restricting SID list (capability SIDs, account,
logon SID, Everyone) and wants to know how many places on a real PC accept writes from those two SIDs.

Usage: python probe-acl-survey.py registry | pipes
  registry  walks HKU\\<user SID>, HKU\\<user SID>_Classes and HKLM. Each key is opened with READ_CONTROL and
            KEY_ENUMERATE_SUB_KEYS and KEY_QUERY_VALUE (pywin32 RegEnumKey calls RegQueryInfoKey first)
            (REG_OPTION_OPEN_LINK, so symbolic links are not followed) and its
            DACL is read. No value is read or written. A key counts when an allow ACE that applies to the key
            itself (not inherit-only) gives a write-type right to the SID: KEY_SET_VALUE, KEY_CREATE_SUB_KEY,
            WRITE_DAC, WRITE_OWNER, GENERIC_WRITE or GENERIC_ALL. Everyone, the current logon SID, any other
            logon SID (S-1-5-5-*), Users and Authenticated Users are counted separately; the last two fail the
            WRITE_RESTRICTED second check under the Codex list, so they are shown for reference only.
  pipes     lists the names under \\\\.\\pipe\\ (directory listing only: no pipe is opened, so no server sees a
            connection and no DACL is read) and groups them by name pattern.
Writes local/2026-11-26-survey/<kind>.json (full lists stay there; SIDs of this PC are replaced by their kind).
"""
import os
import re
import sys
import json
import time
from collections import Counter
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26-survey")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import save, token_sids  # noqa: E402

WRITE_BITS = {"KEY_SET_VALUE": 0x2, "KEY_CREATE_SUB_KEY": 0x4, "WRITE_DAC": 0x40000, "WRITE_OWNER": 0x80000,
              "GENERIC_WRITE": 0x40000000, "GENERIC_ALL": 0x10000000}
WRITE_MASK = sum(WRITE_BITS.values())


def registry():
    import win32api
    import win32con
    import win32security
    user_sid, logon_sid = token_sids()
    targets = {"S-1-1-0": "everyone", logon_sid: "user_logon", "S-1-5-32-545": "users", "S-1-5-11": "authenticated_users"}
    roots = [("HKU", win32con.HKEY_USERS, user_sid), ("HKU", win32con.HKEY_USERS, user_sid + "_Classes"),
             ("HKLM", win32con.HKEY_LOCAL_MACHINE, "")]
    access = win32con.READ_CONTROL | win32con.KEY_ENUMERATE_SUB_KEYS | win32con.KEY_QUERY_VALUE | 0x100  # 64-bit view
    stats = Counter()
    hits = {k: [] for k in ("everyone", "user_logon", "other_logon", "users", "authenticated_users")}
    undecoded = []
    t0 = time.monotonic()

    def label(root_name, path):
        p = path.replace(user_sid, "<user SID>")
        return f"{root_name}\\{p}" if p else root_name

    def visit(root_name, root, path, depth):
        try:
            h = win32api.RegOpenKeyEx(root, path, 0x8, access)  # REG_OPTION_OPEN_LINK
        except win32api.error:
            try:
                h = win32api.RegOpenKeyEx(root, path, 0x8, win32con.READ_CONTROL | 0x100)
                stats["enum_denied"] += 1
            except win32api.error:
                stats["unreadable"] += 1
                return
        stats["keys"] += 1
        try:
            sd = win32api.RegGetKeySecurity(h, win32security.DACL_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl()
        except win32api.error:
            stats["sd_unreadable"] += 1
            dacl = None
        if dacl is None:
            stats["null_or_unread_dacl"] += 1
        else:
            for i in range(dacl.GetAceCount()):
                try:
                    (atype, aflags), mask, sid = dacl.GetAce(i)
                except NotImplementedError:  # callback / object ACEs that pywin32 does not decode
                    stats["undecoded_aces"] += 1
                    undecoded.append(label(root_name, path))
                    continue
                if atype != 0 or aflags & 0x8:  # allow ACEs that apply to this key
                    continue
                if not mask & WRITE_MASK:
                    continue
                s = win32security.ConvertSidToStringSid(sid)
                kind = targets.get(s) or ("other_logon" if s.startswith("S-1-5-5-") else None)
                if kind:
                    hits[kind].append({"key": label(root_name, path), "mask": hex(mask & 0xffffffff),
                                       "inherited": bool(aflags & 0x10)})
        try:
            i = 0
            while True:
                try:
                    name = win32api.RegEnumKey(h, i)
                except win32api.error:
                    break
                i += 1
                if root_name == "HKLM" and path.upper() == "SYSTEM" and name.upper() == "CURRENTCONTROLSET":
                    continue
                visit(root_name, root, f"{path}\\{name}" if path else name, depth + 1)
        finally:
            h.Close()

    for root_name, root, path in roots:
        visit(root_name, root, path, 0)
    rec = {"seconds": round(time.monotonic() - t0, 1), "stats": dict(stats),
           "counts": {k: len(v) for k, v in hits.items()},
           "counts_explicit": {k: sum(1 for x in v if not x["inherited"]) for k, v in hits.items()},
           "by_top": {k: Counter("\\".join(x["key"].split("\\")[:3]) for x in v).most_common(15) for k, v in hits.items()},
           "hits": hits, "undecoded_ace_keys": Counter("\\".join(k.split("\\")[:4]) for k in undecoded).most_common(30)}
    print(save("registry.json", rec))
    print(json.dumps({k: rec[k] for k in ("seconds", "stats", "counts", "counts_explicit")}))


PIPE_GROUPS = [
    ("AppContainer 안 Chromium 계열 프로세스(mojo·crashpad)", r"^Sessions\\\d+\\AppContainerNamedObjects\\"),
    ("Chromium·Electron mojo", r"(^|\\)mojo\."),
    ("Chromium 계열 기타(crashpad, chrome, maglev)", r"(^|\\)(chrome\.|crashpad_|maglev\.)"),
    ("Git Bash(MSYS2) 신호 파이프", r"^msys-.*-sigwait$"), ("콘솔(ConPTY)", r"^conpty-"), ("libuv(Node 등)", r"^uv\\"),
    ("Codex", r"^codex-"), ("Claude Code 세션 간 메시지", r"^LOCAL\\cc-msg-"), ("PowerShell 호스트", r"^PSHost\."),
    (".NET 진단", r"^dotnet-diagnostic-"), ("Windows 서비스·RPC", r"^(InitShutdown|lsass|ntsvcs|scerpc|epmapper|LSM_API_service|"
     r"eventlog|atsvc|wkssvc|srvsvc|spoolss|trkwks|W32TIME_ALT|winreg|ROUTER|tapsrv|RpcProxy\\|Winsock2\\|PIPE_EVENTROOT\\|"
     r"Ctx_WinStation_API_service|SessEnvPublicRpc|MsFteWds|SearchTextHarvester|cert|keysvc|protected_storage|"
     r"ProtectedPrefix\\|wlansvc|DAV RPC SERVICE|AppContracts_|GoogleCrashServices|TermSrv_API_service|"
     r"WiFiNetworkManagerTask|E:\\|openssh-ssh-agent)"),
    ("GUID 이름", r"^[{]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[}]?$"),
    ("이번 측정", r"^iso-"),
]


def pipes():
    names = os.listdir("\\\\.\\pipe\\")
    groups = Counter()
    other = []
    for n in names:
        for g, pat in PIPE_GROUPS:
            if re.search(pat, n):
                groups[g] += 1
                break
        else:
            groups["기타"] += 1
            other.append(re.sub(r"\d{3,}", "<n>", re.sub(r"[0-9a-fA-F]{8,}", "<hex>", n)))
    rec = {"total": len(names), "groups": dict(groups), "other_patterns": Counter(other).most_common(60),
           "names": sorted(names)}
    print(save("pipes.json", rec))
    print(json.dumps({"total": rec["total"], "groups": rec["groups"]}, ensure_ascii=False))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    {"registry": registry, "pipes": pipes}[sys.argv[1]]()
