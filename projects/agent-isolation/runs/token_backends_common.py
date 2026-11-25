"""Shared host-side helpers for the four-config Restricted Token measurements (plan-token-backends.md)."""
import os
import json
import time
import ctypes
import hashlib
import subprocess
from pathlib import Path

import win32api
import win32con
import win32security

ROOT = Path(r"C:\agent-isolation-test")
TOOLS = ROOT / "tools"
PYRT = TOOLS / "pyrt"
PY = PYRT / "python.exe"
CHILD = TOOLS / "child.py"
QP_PROFILE = ROOT / "qwenpaw-profile"
TARGETS = ROOT / "targets"
BACKUP = Path(r"C:\agent-isolation-backup")
REPO = Path(__file__).resolve().parents[1]
LOCAL = REPO / "local" / os.environ.get("ISO_DATE", "2026-11-25")  # ISO_DATE=2026-11-26 for the named object run
CONFIGS = ("qwenpaw-unelevated", "qwenpaw-admin", "codex-unelevated", "codex-elevated")
CODEX = Path(os.environ["APPDATA"]) / r"npm\node_modules\@openai\codex\node_modules\@openai\codex-win32-x64\vendor\x86_64-pc-windows-msvc\bin\codex.exe"
REAL_CODEX_HOME = Path(os.environ["USERPROFILE"]) / ".codex"
SID_SYSTEM, SID_ADMINS, SID_USERS, SID_EVERYONE = "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545", "S-1-1-0"


def ws(config, name):
    return ROOT / config / name


def token_sids():
    h = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    user = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(h, win32security.TokenUser)[0])
    logon = None
    for sid, attrs in win32security.GetTokenInformation(h, win32security.TokenGroups):
        if attrs & 0xC0000000 == 0xC0000000:
            logon = win32security.ConvertSidToStringSid(sid)
    return user, logon


def lookup_sid(name):
    try:
        return win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, name)[0])
    except win32security.error:
        return None


def icacls(path, *args):
    r = subprocess.run(["icacls", str(path), *args], capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"icacls {path} {args}: {r.stdout.decode('cp949', 'replace')} {r.stderr.decode('cp949', 'replace')}")


def protect(path, user_sid, extra=()):
    """Replace the DACL with user/SYSTEM/Administrators full control (+extra), inheritance removed."""
    icacls(path, "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", f"*{SID_SYSTEM}:(OI)(CI)F",
           f"*{SID_ADMINS}:(OI)(CI)F", *extra)


def sddl(path, obj=win32security.SE_FILE_OBJECT):
    info = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    sd = win32security.GetNamedSecurityInfo(str(path), obj, info)
    return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, info)


def dacl_aces(path, obj=win32security.SE_FILE_OBJECT):
    sd = win32security.GetNamedSecurityInfo(str(path), obj, win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    out = []
    for i in range(dacl.GetAceCount() if dacl else 0):
        (atype, aflags), mask, sid = dacl.GetAce(i)
        out.append({"type": atype, "flags": aflags, "mask": hex(mask & 0xffffffff),
                    "sid": win32security.ConvertSidToStringSid(sid)})
    return out


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(name, data):
    LOCAL.mkdir(parents=True, exist_ok=True)
    p = LOCAL / name
    p.write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    return p


def load(name):
    return json.loads((LOCAL / name).read_text(encoding="utf-8"))


def parse_isojson(text):
    for line in (text or "").splitlines():
        if line.startswith("ISOJSON "):
            return json.loads(line[8:])
    return None


def write_spec(workdir, tag, tasks):
    spec_dir = Path(workdir) / "_specs"
    spec_dir.mkdir(parents=True, exist_ok=True)
    p = spec_dir / f"{tag}.json"
    p.write_text(json.dumps({"tasks": tasks}), encoding="utf-8")
    return p


def child_argv(spec_path):
    return [str(PY), "-I", "-B", str(CHILD), str(spec_path)]


def child_cmdline(spec_path):
    return " ".join(f'"{a}"' for a in child_argv(spec_path))


def heartbeat_alive(path, window=3.0):
    """True if the heartbeat file was rewritten within the last `window` seconds."""
    p = Path(path)
    if not p.exists():
        return None
    time.sleep(window)
    return (time.time() - p.stat().st_mtime) < window


def wait_file(path, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if Path(path).exists():
            return True
        time.sleep(0.2)
    return False


def find_window(title, timeout=8.0):
    user32 = ctypes.WinDLL("user32")
    found = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def cb(hwnd, _):
        buf = ctypes.create_unicode_buffer(256)
        user32.GetWindowTextW(ctypes.c_void_p(hwnd), buf, 256)
        if buf.value == title:
            found.append(bool(user32.IsWindowVisible(ctypes.c_void_p(hwnd))))
        return True

    t0 = time.time()
    while time.time() - t0 < timeout:
        found.clear()
        user32.EnumWindows(cb, None)
        if found:
            return {"found": True, "visible": found[0]}
        time.sleep(0.3)
    return {"found": False}


def process_categories(user_sid, sandbox_sids):
    """{pid: category} using WTSEnumerateProcessesW (no process handles are opened)."""
    wts = ctypes.WinDLL("wtsapi32")

    class WTS_PROCESS_INFO(ctypes.Structure):
        _fields_ = [("SessionId", ctypes.c_uint32), ("ProcessId", ctypes.c_uint32),
                    ("pProcessName", ctypes.c_wchar_p), ("pUserSid", ctypes.c_void_p)]

    ptr = ctypes.POINTER(WTS_PROCESS_INFO)()
    count = ctypes.c_uint32()
    if not wts.WTSEnumerateProcessesW(None, 0, 1, ctypes.byref(ptr), ctypes.byref(count)):
        return {}
    adv = ctypes.WinDLL("advapi32")
    k32 = ctypes.WinDLL("kernel32")
    out = {}
    for i in range(count.value):
        e = ptr[i]
        sid = None
        if e.pUserSid:
            s = ctypes.c_wchar_p()
            if adv.ConvertSidToStringSidW(ctypes.c_void_p(e.pUserSid), ctypes.byref(s)):
                sid = s.value
                k32.LocalFree(s)
        if sid == user_sid:
            cat = "user"
        elif sid in sandbox_sids:
            cat = "sandbox_account"
        elif sid in ("S-1-5-18", "S-1-5-19", "S-1-5-20") or (sid or "").startswith("S-1-5-80-") or sid is None:
            cat = "system_service"
        else:
            cat = "other_account"
        out[str(e.ProcessId)] = cat
    wts.WTSFreeMemory(ptr)
    return out


def hku_category(name, user_sid, sandbox_sids):
    base = name[:-8] if name.endswith("_Classes") else name
    suffix = "_Classes" if name.endswith("_Classes") else ""
    if name == ".DEFAULT":
        return ".DEFAULT"
    if base == user_sid:
        cat = "user"
    elif base in sandbox_sids:
        cat = "sandbox_account"
    elif base in ("S-1-5-18", "S-1-5-19", "S-1-5-20"):
        cat = "system_service"
    else:
        cat = "other"
    return cat + suffix


def start_test_process(seconds, marker, heartbeat):
    """Host-side test target: non-elevated, owned by the user, marker in its command line."""
    return subprocess.Popen([str(PY), "-I", "-B", str(CHILD), "sleep", str(seconds), str(heartbeat), marker],
                            creationflags=0x08000000, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
