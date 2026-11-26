"""Runs inside the sandbox (standalone Python runtime, stdlib + ctypes only).

Usage:
  python child.py <spec.json>          run the tasks listed in the spec, print one ISOJSON line
  python child.py sleep <sec> <hb>     lifetime-limited sleeper that writes a heartbeat file every second
  python child.py window <sec> <title> visible test window for <sec> seconds

Safety: other processes, tokens and registry keys are only opened and closed. No process memory is
read or written, no token is duplicated or impersonated, no registry value is written. Files are
only touched under the paths the harness passes in the spec (synthetic test files), except
"open" tasks that open a real file for read access and close it without reading.
Named objects and pipes (2026-11-26) use only synthetic iso-nq-* names; the only data written is a
test string into synthetic sections and pipes. No pipe client is impersonated.
"run" tasks (2026-11-26, T1-T6) start installed tools (Node, Git Bash, Git) with the test commands the
harness passes; they touch only the workspace and its test repository.
2026-11-26-03 (reduced restricting SID list): user32, crypt32 and userenv are loaded only if they can be
(a token without desktop access may fail user32 initialization); "run" tasks may give the tool an empty
pipe instead of NUL as standard input ("stdin": "pipe") and extra environment variables ("env").
"""
import os
import sys
import json
import time
import ctypes
import subprocess
import winreg
from ctypes import wintypes
from pathlib import Path

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
DLL_ERRORS = {}


def _dll(name):
    """None if the DLL cannot be loaded (for example user32 initialization without desktop access)."""
    try:
        return ctypes.WinDLL(name, use_last_error=True)
    except OSError as e:
        DLL_ERRORS[name] = f"error:{getattr(e, 'winerror', None)}"
        return None


user32 = _dll("user32")
crypt32 = _dll("crypt32")
userenv = _dll("userenv")

HANDLE = wintypes.HANDLE
k32.OpenProcess.restype = HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.CloseHandle.argtypes = [HANDLE]
k32.GetCurrentProcess.restype = HANDLE
k32.LocalFree.argtypes = [ctypes.c_void_p]
k32.CreateFileW.restype = HANDLE
k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                            wintypes.DWORD, wintypes.DWORD, HANDLE]
k32.CreateToolhelp32Snapshot.restype = HANDLE
k32.IsProcessInJob.argtypes = [HANDLE, HANDLE, ctypes.POINTER(wintypes.BOOL)]
k32.QueryInformationJobObject.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD)]
adv.OpenProcessToken.argtypes = [HANDLE, wintypes.DWORD, ctypes.POINTER(HANDLE)]
adv.GetTokenInformation.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD)]
adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
adv.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
adv.LookupPrivilegeNameW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR,
                                     ctypes.POINTER(wintypes.DWORD)]
if user32:
    user32.GetThreadDesktop.restype = HANDLE
    user32.GetProcessWindowStation.restype = HANDLE
    user32.GetUserObjectInformationW.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                                 ctypes.POINTER(wintypes.DWORD)]
if userenv:
    userenv.GetUserProfileDirectoryW.argtypes = [HANDLE, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
ntdll.NtQueryInformationProcess.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                            ctypes.POINTER(wintypes.ULONG)]
ntdll.NtQueryKey.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                             ctypes.POINTER(wintypes.ULONG)]
INVALID = HANDLE(-1).value


def err():
    return f"error:{ctypes.get_last_error()}"


def sid_str(psid):
    if not psid:
        return None
    s = wintypes.LPWSTR()
    if not adv.ConvertSidToStringSidW(ctypes.c_void_p(psid), ctypes.byref(s)):
        return None
    v = s.value
    k32.LocalFree(s)
    return v


# ---------------------------------------------------------------- token
def own_token(access=0x0008):
    h = HANDLE()
    adv.OpenProcessToken(k32.GetCurrentProcess(), access, ctypes.byref(h))
    return h


def tok_raw(h, cls):
    size = wintypes.DWORD()
    adv.GetTokenInformation(h, cls, None, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value or 8)
    return buf if adv.GetTokenInformation(h, cls, buf, size, ctypes.byref(size)) else None


def tok_groups(h, cls):
    buf = tok_raw(h, cls)
    if buf is None:
        return None
    n = ctypes.c_uint32.from_buffer(buf).value
    return [{"sid": sid_str(ctypes.c_void_p.from_buffer(buf, 8 + 16 * i).value),
             "attrs": ctypes.c_uint32.from_buffer(buf, 16 + 16 * i).value} for i in range(n)]


def acl_aces(pacl):
    out = []
    if not pacl:
        return out
    count = ctypes.c_uint16.from_address(pacl + 4).value
    for i in range(count):
        pace = ctypes.c_void_p()
        if not adv.GetAce(ctypes.c_void_p(pacl), i, ctypes.byref(pace)):
            continue
        base = pace.value
        out.append({"type": ctypes.c_uint8.from_address(base).value,
                    "flags": ctypes.c_uint8.from_address(base + 1).value,
                    "mask": hex(ctypes.c_uint32.from_address(base + 4).value),
                    "sid": sid_str(base + 8)})
    return out


def obj_name(h):
    need = wintypes.DWORD()
    user32.GetUserObjectInformationW(h, 2, None, 0, ctypes.byref(need))
    buf = ctypes.create_unicode_buffer(need.value // 2 + 1)
    if user32.GetUserObjectInformationW(h, 2, buf, need, ctypes.byref(need)):
        return buf.value
    return err()


def hkcu_name():
    hk = HANDLE()
    rc = adv.RegOpenCurrentUser(0x20019, ctypes.byref(hk))
    if rc != 0:
        return f"error:{rc}"
    buf = ctypes.create_string_buffer(2048)
    ret = wintypes.ULONG()
    st = ntdll.NtQueryKey(hk, 3, buf, 2048, ctypes.byref(ret))
    adv.RegCloseKey(hk)
    if st != 0:
        return f"ntstatus:{st & 0xffffffff:#x}"
    n = ctypes.c_uint32.from_buffer(buf).value
    return ctypes.wstring_at(ctypes.addressof(buf) + 4, n // 2)


def profile_dir():
    if not userenv:
        return "userenv_unavailable"
    h = own_token()
    size = wintypes.DWORD(1024)
    buf = ctypes.create_unicode_buffer(1024)
    ok = userenv.GetUserProfileDirectoryW(h, buf, ctypes.byref(size))
    k32.CloseHandle(h)
    return buf.value if ok else err()


class BASIC_LIMIT(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]


class EXT_LIMIT(ctypes.Structure):
    _fields_ = [("Basic", BASIC_LIMIT), ("Io", ctypes.c_ulonglong * 6), ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


def job_info():
    inj = wintypes.BOOL()
    k32.IsProcessInJob(k32.GetCurrentProcess(), None, ctypes.byref(inj))
    out = {"in_job": bool(inj.value)}
    if inj.value:
        e = EXT_LIMIT()
        if k32.QueryInformationJobObject(None, 9, ctypes.byref(e), ctypes.sizeof(e), None):
            out.update(limit_flags=hex(e.Basic.LimitFlags), active_process_limit=e.Basic.ActiveProcessLimit,
                       process_memory_limit=e.ProcessMemoryLimit, job_memory_limit=e.JobMemoryLimit)
        else:
            out["limits"] = err()
        ui = wintypes.DWORD()
        out["ui_restrictions"] = hex(ui.value) if k32.QueryInformationJobObject(
            None, 4, ctypes.byref(ui), 4, None) else err()
    return out


def token_info():
    h = own_token()
    privs = []
    buf = tok_raw(h, 3)
    if buf is not None:
        n = ctypes.c_uint32.from_buffer(buf).value
        for i in range(n):
            luid_addr = ctypes.addressof(buf) + 4 + 12 * i
            name = ctypes.create_unicode_buffer(64)
            ln = wintypes.DWORD(64)
            adv.LookupPrivilegeNameW(None, ctypes.c_void_p(luid_addr), name, ctypes.byref(ln))
            privs.append({"name": name.value, "attrs": ctypes.c_uint32.from_buffer(buf, 4 + 12 * i + 8).value})
    dd = tok_raw(h, 6)
    il = tok_raw(h, 25)
    user = tok_raw(h, 1)
    groups = tok_groups(h, 2) or []
    logon = [g["sid"] for g in groups if g["attrs"] & 0xC0000000 == 0xC0000000]
    res = {"user": sid_str(ctypes.c_void_p.from_buffer(user, 0).value) if user else None,
           "groups": groups, "logon_sids": logon, "restricted_sids": tok_groups(h, 11),
           "integrity": sid_str(ctypes.c_void_p.from_buffer(il, 0).value) if il else None,
           "privileges": privs,
           "default_dacl": acl_aces(ctypes.c_void_p.from_buffer(dd, 0).value) if dd else None,
           "desktop": obj_name(user32.GetThreadDesktop(k32.GetCurrentThreadId())) if user32 else "user32_unavailable",
           "winsta": obj_name(user32.GetProcessWindowStation()) if user32 else "user32_unavailable",
           "dll_errors": DLL_ERRORS,
           "hkcu": hkcu_name(), "profile_dir": profile_dir(), "pid": os.getpid(), "ppid_chain": ancestors()}
    res.update(job_info())
    k32.CloseHandle(h)
    return res


# ---------------------------------------------------------------- processes
class PE32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]


def snapshot():
    h = k32.CreateToolhelp32Snapshot(2, 0)
    out = {}
    e = PE32()
    e.dwSize = ctypes.sizeof(e)
    ok = k32.Process32FirstW(h, ctypes.byref(e))
    while ok:
        out[e.th32ProcessID] = (e.th32ParentProcessID, e.szExeFile)
        ok = k32.Process32NextW(h, ctypes.byref(e))
    k32.CloseHandle(h)
    return out


def ancestors():
    snap = snapshot()
    chain, pid = [], os.getpid()
    for _ in range(8):
        if pid not in snap:
            break
        ppid, exe = snap[pid]
        chain.append({"pid": pid, "exe": exe})
        pid = ppid
    return chain


PROC_RIGHTS = {"QUERY_LIMITED": 0x1000, "VM_READ": 0x10, "VM_WRITE": 0x20, "VM_OPERATION": 0x8,
               "CREATE_THREAD": 0x2, "TERMINATE": 0x1, "DUP_HANDLE": 0x40, "SYNCHRONIZE": 0x100000}
TOKEN_RIGHTS = {"TOKEN_QUERY": 0x8, "TOKEN_DUPLICATE": 0x2, "TOKEN_IMPERSONATE": 0x4,
                "TOKEN_ASSIGN_PRIMARY": 0x1, "TOKEN_ADJUST_DEFAULT": 0x80}


def proc_open(pid):
    res = {}
    for name, right in PROC_RIGHTS.items():
        h = k32.OpenProcess(right, False, pid)
        res[name] = "granted" if h else err()
        if h:
            k32.CloseHandle(h)
    tok = {}
    hp = k32.OpenProcess(0x1000, False, pid)
    if hp:
        for name, right in TOKEN_RIGHTS.items():
            ht = HANDLE()
            ok = adv.OpenProcessToken(hp, right, ctypes.byref(ht))
            tok[name] = "granted" if ok else err()
            if ok:
                k32.CloseHandle(ht)
        k32.CloseHandle(hp)
    else:
        tok = "process_not_opened"
    return {"process": res, "token": tok}


def cmdline_has(pid, marker):
    hp = k32.OpenProcess(0x1000, False, pid)
    if not hp:
        return err()
    size = 4096
    buf = ctypes.create_string_buffer(size)
    ret = wintypes.ULONG()
    st = ntdll.NtQueryInformationProcess(hp, 60, buf, size, ctypes.byref(ret))
    k32.CloseHandle(hp)
    if st != 0:
        return f"ntstatus:{st & 0xffffffff:#x}"
    length = ctypes.c_uint16.from_buffer(buf).value
    ptr = ctypes.c_void_p.from_buffer(buf, 8).value
    return "marker_found" if marker in ctypes.wstring_at(ptr, length // 2) else "marker_not_found"


def proc_list(categories):
    """categories: {pid: category} computed by the host. Only user/sandbox pids are opened."""
    snap = snapshot()
    counts = {}
    for pid in snap:
        cat = categories.get(str(pid), "unknown")
        c = counts.setdefault(cat, {"visible": 0, "query_limited_opened": 0, "opened_tried": 0})
        c["visible"] += 1
        if cat in ("user", "sandbox_account"):
            c["opened_tried"] += 1
            h = k32.OpenProcess(0x1000, False, pid)
            if h:
                c["query_limited_opened"] += 1
                k32.CloseHandle(h)
    return {"total_visible": len(snap), "by_category": counts}


def find_procs(names):
    snap = snapshot()
    return {n: [pid for pid, (_, exe) in snap.items() if exe.lower().startswith(n.lower())] for n in names}


# ---------------------------------------------------------------- files
def open_only(path, access):
    h = k32.CreateFileW(str(path), access, 0x7, None, 3, 0x02000000, None)
    if h in (None, INVALID):
        return err()
    k32.CloseHandle(h)
    return "granted"


def expand(p):
    return os.path.expandvars(p.replace("{PROFILE}", profile_dir()))


def fs_op(o):
    op, path = o["op"], expand(o.get("path", ""))
    try:
        if op == "read":
            Path(path).read_bytes()
        elif op == "write":
            Path(path).write_text(o.get("data", "sandbox-write\n"))
        elif op == "append":
            with open(path, "a") as f:
                f.write("sandbox-append\n")
        elif op == "mkdir":
            os.mkdir(path)
        elif op == "rename":
            os.rename(path, expand(o["to"]))
        elif op == "delete":
            os.remove(path)
        elif op == "rmdir":
            os.rmdir(path)
        elif op == "exists":
            return "exists" if os.path.exists(path) else "missing"
        elif op == "list":
            return f"ok:{len(os.listdir(path))}"
        elif op == "open":
            return open_only(path, o.get("access", 0x80000000))
        elif op == "wait_read":
            t0 = time.time()
            while not os.path.exists(path) and time.time() - t0 < o.get("wait", 20):
                time.sleep(0.25)
            Path(path).read_bytes()
        elif op == "signal":
            Path(path).write_text("ready")
            return "signalled"
        else:
            return f"unknown_op:{op}"
        return "ok"
    except OSError as e:
        return f"error:{getattr(e, 'winerror', None) or e.errno}"


# ---------------------------------------------------------------- registry
ROOTS = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE, "HKU": winreg.HKEY_USERS}


def reg_open(root, path, access):
    try:
        winreg.CloseKey(winreg.OpenKey(ROOTS[root], path, 0, access))
        return "granted"
    except OSError as e:
        return f"error:{e.winerror}"


def hku_names():
    out, i = [], 0
    while True:
        try:
            out.append(winreg.EnumKey(winreg.HKEY_USERS, i))
        except OSError:
            break
        i += 1
    return out


# ---------------------------------------------------------------- dpapi
class BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_unprotect(path, expected):
    if not crypt32:
        return "crypt32_unavailable"
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        return f"read_error:{e.winerror}"
    inb = BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_char)))
    outb = BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(outb)):
        return err()
    plain = ctypes.string_at(outb.pbData, outb.cbData)
    k32.LocalFree(outb.pbData)
    return "decrypted_match" if plain == expected.encode() else "decrypted_mismatch"


# ---------------------------------------------------------------- child processes
def spawn(o):
    flags = 0x08000000  # CREATE_NO_WINDOW
    if o.get("breakaway"):
        flags |= 0x01000000
    args = [sys.executable, "-I", "-B", __file__, "sleep", str(o["seconds"]), expand(o["heartbeat"])]
    try:
        if o.get("stdout") == "inherit":
            p = subprocess.Popen(args, creationflags=flags, close_fds=False)
        else:
            p = subprocess.Popen(args, creationflags=flags, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"spawned": True, "pid": p.pid}
    except OSError as e:
        return {"spawned": False, "error": getattr(e, "winerror", None) or e.errno}


def sleeper(seconds, hb):
    end = time.time() + float(seconds)
    Path(hb).write_text(f"{os.getpid()} {time.time()}\n")
    while time.time() < end:
        try:
            Path(hb).write_text(f"{os.getpid()} {time.time()}\n")
        except OSError:
            pass
        time.sleep(1)


def window(seconds, title):
    if not user32:
        return "user32_unavailable"
    user32.CreateWindowExW.restype = HANDLE
    user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                       ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                       HANDLE, HANDLE, HANDLE, ctypes.c_void_p]
    hw = user32.CreateWindowExW(0, "STATIC", title, 0x10CF0000, 100, 100, 300, 120, None, None, None, None)
    msg = wintypes.MSG()
    end = time.time() + float(seconds)
    while time.time() < end:
        while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        time.sleep(0.05)
    return bool(hw)


def parbuild(ws):
    from concurrent.futures import ProcessPoolExecutor
    out = {}
    par = Path(ws) / "parallel"
    par.mkdir(exist_ok=True)
    try:
        with ProcessPoolExecutor(max_workers=4) as ex:
            pids = list(ex.map(build_one, range(16), [str(par)] * 16))
        out["parallel_ok"] = len(list(par.glob("*.pyc"))) == 16
        out["worker_processes"] = len(set(pids))
    except Exception as e:
        out["parallel_ok"] = f"error:{type(e).__name__}:{getattr(e, 'winerror', '')}"
    return out


def build_one(i, out_dir):
    import py_compile
    p = Path(out_dir) / f"m{i}.py"
    p.write_text("".join(f"VALUE_{i}_{j} = {j}\n" for j in range(300)))
    py_compile.compile(str(p), cfile=str(p) + "c", doraise=True)
    return os.getpid()


def pipe_open(name):
    return {"read": open_only(rf"\\.\pipe\{name}", 0x80000000), "write": open_only(rf"\\.\pipe\{name}", 0x40000000)}


# ---------------------------------------------------------------- named objects and pipes (2026-11-26, N0-N4, Q1-Q3)
# Only synthetic names (iso-nq-...) are used. No pipe client is impersonated.
DW, BOOL, LPCW, VP = wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR, ctypes.c_void_p
for _n, _res, _args in (
        ("CreateEventW", HANDLE, [VP, BOOL, BOOL, LPCW]), ("CreateMutexW", HANDLE, [VP, BOOL, LPCW]),
        ("CreateSemaphoreW", HANDLE, [VP, wintypes.LONG, wintypes.LONG, LPCW]),
        ("CreateFileMappingW", HANDLE, [HANDLE, VP, DW, DW, DW, LPCW]),
        ("OpenEventW", HANDLE, [DW, BOOL, LPCW]), ("OpenMutexW", HANDLE, [DW, BOOL, LPCW]),
        ("OpenSemaphoreW", HANDLE, [DW, BOOL, LPCW]), ("OpenFileMappingW", HANDLE, [DW, BOOL, LPCW]),
        ("MapViewOfFile", VP, [HANDLE, DW, DW, DW, ctypes.c_size_t]), ("UnmapViewOfFile", BOOL, [VP]),
        ("WaitForSingleObject", DW, [HANDLE, DW]), ("SetEvent", BOOL, [HANDLE]), ("ReleaseMutex", BOOL, [HANDLE]),
        ("ReleaseSemaphore", BOOL, [HANDLE, wintypes.LONG, VP]),
        ("CreateNamedPipeW", HANDLE, [LPCW, DW, DW, DW, DW, DW, DW, VP]), ("ConnectNamedPipe", BOOL, [HANDLE, VP]),
        ("DisconnectNamedPipe", BOOL, [HANDLE]), ("SetNamedPipeHandleState", BOOL, [HANDLE, ctypes.POINTER(DW), VP, VP]),
        ("ReadFile", BOOL, [HANDLE, VP, DW, ctypes.POINTER(DW), VP]),
        ("WriteFile", BOOL, [HANDLE, VP, DW, ctypes.POINTER(DW), VP]),
        ("ProcessIdToSessionId", BOOL, [DW, ctypes.POINTER(DW)])):
    getattr(k32, _n).restype = _res
    getattr(k32, _n).argtypes = _args
adv.GetSecurityInfo.restype = DW
adv.GetSecurityInfo.argtypes = [HANDLE, ctypes.c_int, DW, ctypes.POINTER(VP), ctypes.POINTER(VP), ctypes.POINTER(VP),
                                ctypes.POINTER(VP), ctypes.POINTER(VP)]
adv.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [VP, DW, DW, ctypes.POINTER(wintypes.LPWSTR), VP]
ntdll.NtQueryObject.argtypes = [HANDLE, ctypes.c_int, VP, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
ntdll.NtOpenDirectoryObject.argtypes = [ctypes.POINTER(HANDLE), DW, VP]
ntdll.NtClose.argtypes = [HANDLE]

SYNC, WRITE_DAC_R, READ_CONTROL_R = 0x100000, 0x40000, 0x20000
OPENERS = {"event": "OpenEventW", "mutex": "OpenMutexW", "semaphore": "OpenSemaphoreW", "section": "OpenFileMappingW"}
# read-type and write-type rights per object type. The mutex type has no write-type specific right.
NOBJ_RIGHTS = {"event": {"read": SYNC, "write": 0x2}, "mutex": {"read": SYNC},
               "semaphore": {"read": SYNC, "write": 0x2}, "section": {"read": 0x4, "write": 0x2}}
KEEP = []  # handles kept open until the process exits (N3, Q2)


def kobj_sddl(h):
    """Owner, DACL and label of an object through a handle that has READ_CONTROL."""
    psd = VP()
    rc = adv.GetSecurityInfo(h, 6, 0x1 | 0x4 | 0x10, None, None, None, None, ctypes.byref(psd))
    if rc != 0:
        return f"error:{rc}"
    s = wintypes.LPWSTR()
    ok = adv.ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, 1, 0x1 | 0x4 | 0x10, ctypes.byref(s), None)
    v = s.value if ok else err()
    if ok:
        k32.LocalFree(s)
    k32.LocalFree(psd)
    return v


def nt_name(h):
    buf = ctypes.create_string_buffer(2048)
    ret = wintypes.ULONG()
    st = ntdll.NtQueryObject(h, 1, buf, 2048, ctypes.byref(ret))  # ObjectNameInformation
    if st:
        return f"ntstatus:0x{st & 0xffffffff:08x}"
    length = ctypes.c_uint16.from_buffer(buf, 0).value
    ptr = ctypes.c_void_p.from_buffer(buf, 8).value
    return ctypes.wstring_at(ptr, length // 2) if ptr else ""


def wait0(h):
    w = k32.WaitForSingleObject(h, 0)
    return {0: "signaled", 0x80: "abandoned", 0x102: "not_signaled"}.get(w, f"wait:{w}")


def section_io(h, write=None, size=64):
    view = k32.MapViewOfFile(h, 0x2 if write else 0x4, 0, 0, size)
    if not view:
        return err()
    try:
        if write:
            data = write.encode()[:size - 1] + b"\0"
            ctypes.memmove(view, data, len(data))
            return "written"
        return ctypes.string_at(view, size).split(b"\0", 1)[0].decode("utf-8", "replace")
    finally:
        k32.UnmapViewOfFile(view)


def nobj_create(objs, keep=True):
    out = {}
    for o in objs:
        typ, name = o["type"], o["name"]
        if typ == "event":
            h = k32.CreateEventW(None, True, bool(o.get("signaled")), name)
        elif typ == "mutex":
            h = k32.CreateMutexW(None, False, name)
        elif typ == "semaphore":
            h = k32.CreateSemaphoreW(None, 0, 10, name)
        else:
            h = k32.CreateFileMappingW(INVALID, None, 0x04, 0, 4096, name)
        le = ctypes.get_last_error()
        if not h:
            out[name] = {"created": f"error:{le}"}
            continue
        r = {"created": "existing" if le == 183 else "new", "path": nt_name(h), "sddl": kobj_sddl(h)}
        if r["created"] == "new" and typ == "section" and o.get("marker"):
            r["marker"] = section_io(h, write=o["marker"])
        if r["created"] == "existing":  # N4: is this the object the other side made?
            if typ == "event":
                r["state"] = wait0(h)
            elif typ == "section":
                r["content"] = section_io(h)
        if keep:
            KEEP.append(h)
        else:
            k32.CloseHandle(h)
        out[name] = r
    return out


def nobj_effect(typ, name, marker):
    fn = getattr(k32, OPENERS[typ])
    access = {"event": 0x2, "semaphore": 0x2, "mutex": SYNC, "section": 0x6}[typ]
    h = fn(access, False, name)
    if not h:
        return f"not_opened:{ctypes.get_last_error()}"
    try:
        if typ == "event":
            return "set" if k32.SetEvent(h) else err()
        if typ == "semaphore":
            return "released" if k32.ReleaseSemaphore(h, 1, None) else err()
        if typ == "mutex":
            w = wait0(h)
            if w in ("signaled", "abandoned"):
                k32.ReleaseMutex(h)
                return "acquired_and_released"
            return w
        return {"read": section_io(h), "write": section_io(h, write=marker)}
    finally:
        k32.CloseHandle(h)


def nobj_open(objs, effects=False, marker=""):
    out = {}
    for o in objs:
        typ, name = o["type"], o["name"]
        fn = getattr(k32, OPENERS[typ])
        r = {}
        for label, right in [*NOBJ_RIGHTS[typ].items(), ("write_dac", WRITE_DAC_R), ("read_control", READ_CONTROL_R)]:
            h = fn(right, False, name)
            r[label] = "granted" if h else err()
            if h:
                k32.CloseHandle(h)
        if effects:
            r["effect"] = nobj_effect(typ, name, marker)
        out[name] = r
    return out


def ns_dirs():
    """N0: open the named object directories with each right separately (sandbox side)."""
    sess = DW()
    k32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sess))

    class US(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", VP)]

    class OA(ctypes.Structure):
        _fields_ = [("Length", wintypes.ULONG), ("RootDirectory", HANDLE), ("ObjectName", ctypes.POINTER(US)),
                    ("Attributes", wintypes.ULONG), ("SecurityDescriptor", VP), ("SecurityQualityOfService", VP)]
    out = {"session": sess.value}
    rights = {"query": 0x1, "traverse": 0x2, "create_object": 0x4, "create_subdirectory": 0x8, "read_control": READ_CONTROL_R}
    for label, path in (("global", r"\BaseNamedObjects"), ("global_restricted", r"\BaseNamedObjects\Restricted"),
                        ("local", rf"\Sessions\{sess.value}\BaseNamedObjects"),
                        ("local_restricted", rf"\Sessions\{sess.value}\BaseNamedObjects\Restricted")):
        b = ctypes.create_unicode_buffer(path)
        us = US(len(path) * 2, len(path) * 2 + 2, ctypes.cast(b, VP))
        r = {}
        for rn, right in rights.items():
            oa = OA(ctypes.sizeof(OA), None, ctypes.pointer(us), 0x40, None, None)
            h = HANDLE()
            st = ntdll.NtOpenDirectoryObject(ctypes.byref(h), right, ctypes.byref(oa))
            r[rn] = "granted" if st == 0 else f"ntstatus:0x{st & 0xffffffff:08x}"
            if st == 0:
                if rn == "read_control":
                    r["sddl"] = kobj_sddl(h)
                ntdll.NtClose(h)
        out[label] = r
    return out


PIPE_ACCESS = {"duplex": 0x3, "inbound": 0x1}


def pipe_steps():
    """Q1: the calls multiprocessing.connection.Pipe makes on Windows, one step at a time."""
    import uuid
    out = {}
    for kind, duplex in (("duplex", True), ("inbound", False)):
        name = rf"\\.\pipe\iso-nq-q1-{uuid.uuid4().hex[:10]}"
        h1 = k32.CreateNamedPipeW(name, PIPE_ACCESS[kind] | 0x40000000 | 0x00080000,  # OVERLAPPED | FIRST_PIPE_INSTANCE
                                  0x4 | 0x2, 1, 8192 if duplex else 0, 8192, 0xFFFFFFFF, None)
        r = {"server": "created" if h1 != INVALID else err()}
        if h1 != INVALID:
            r["server_sddl"] = kobj_sddl(h1)
            h2 = k32.CreateFileW(name, 0xC0000000 if duplex else 0x40000000, 0, None, 3, 0x40000000, None)
            r["client"] = "opened" if h2 != INVALID else err()
            if h2 != INVALID:
                mode = DW(2)  # PIPE_READMODE_MESSAGE
                r["set_state"] = "ok" if k32.SetNamedPipeHandleState(h2, ctypes.byref(mode), None, None) else err()
                k32.CloseHandle(h2)
            k32.CloseHandle(h1)
        out[kind] = r
    # server without the first-instance flag, then one client open per access right
    clients = {}
    for label, access in (("read", 0x80000000), ("write", 0x40000000), ("read_write", 0xC0000000),
                          ("read_control", READ_CONTROL_R)):
        name = rf"\\.\pipe\iso-nq-q1-{uuid.uuid4().hex[:10]}"
        h1 = k32.CreateNamedPipeW(name, 0x3, 0x0, 255, 4096, 4096, 0, None)
        if h1 == INVALID:
            clients[label] = f"server_{err()}"
            continue
        h2 = k32.CreateFileW(name, access, 0, None, 3, 0, None)
        clients[label] = "opened" if h2 != INVALID else err()
        if h2 != INVALID:
            k32.CloseHandle(h2)
        k32.CloseHandle(h1)
    out["plain_server_clients"] = clients
    from multiprocessing.connection import Pipe
    for d in (True, False):
        try:
            a, b = Pipe(duplex=d)
            a.close()
            b.close()
            out[f"mp_pipe_duplex_{d}"] = "ok"
        except Exception as e:
            out[f"mp_pipe_duplex_{d}"] = f"error:{type(e).__name__}:{getattr(e, 'winerror', '')}"
    return out


def pipe_try_create(name, first, keep=False, instances=255):
    flags = 0x3 | (0x00080000 if first else 0)
    h = k32.CreateNamedPipeW(rf"\\.\pipe\{name}", flags, 0x0, instances, 4096, 4096, 0, None)
    if h == INVALID:
        return {"created": err()}, None
    r = {"created": "yes", "sddl": kobj_sddl(h)}
    if not keep:
        k32.CloseHandle(h)
        return r, None
    return r, h


def pipe_serve(name, instances, log):
    """Q2: pipe server kept for the life of the process. Each connection and up to 256 bytes received are logged."""
    import threading
    out = {"instances": []}
    for i in range(instances):
        r, h = pipe_try_create(name, first=(i == 0), keep=True)
        out["instances"].append(r["created"])
        if i == 0:
            out["sddl"] = r.get("sddl")
        if h is None:
            continue
        KEEP.append(h)

        def serve(h=h, i=i):
            while True:
                ok = k32.ConnectNamedPipe(h, None)
                if not ok and ctypes.get_last_error() != 535:  # ERROR_PIPE_CONNECTED
                    time.sleep(0.2)
                    continue
                buf = ctypes.create_string_buffer(256)
                n = DW()
                got = k32.ReadFile(h, buf, 255, ctypes.byref(n), None)
                data = buf.raw[:n.value].decode("utf-8", "replace") if got else f"read_error:{ctypes.get_last_error()}"
                try:
                    with open(log, "a", encoding="utf-8") as f:
                        f.write(json.dumps({"instance": i, "time": time.time(), "data": data}) + "\n")
                except OSError:
                    pass
                k32.DisconnectNamedPipe(h)
        threading.Thread(target=serve, daemon=True).start()
    return out


def pipe_connect(path, access, wait=3.0):
    """CreateFile on a pipe, retrying while every server instance is busy (ERROR_PIPE_BUSY 231). A server
    that may create only one instance needs a moment to reconnect after the previous client."""
    t0 = time.time()
    while True:
        h = k32.CreateFileW(path, access, 0, None, 3, 0, None)
        if h != INVALID:
            return h, "opened"
        e = ctypes.get_last_error()
        if e != 231 or time.time() - t0 > wait:
            return None, f"error:{e}"
        time.sleep(0.05)


def pipe_client(name, data):
    """Q2: connect to a pipe with each right; the write connection sends `data`."""
    path = rf"\\.\pipe\{name}"
    out = {}
    h, out["read"] = pipe_connect(path, 0x80000000)
    if h:
        k32.CloseHandle(h)
    h, out["write"] = pipe_connect(path, 0x40000000)
    if h:
        b = data.encode()
        n = DW()
        out["write_data"] = "sent" if k32.WriteFile(h, b, len(b), ctypes.byref(n), None) else err()
        k32.CloseHandle(h)
    h, out["read_control"] = pipe_connect(path, READ_CONTROL_R)
    if h:
        out["sddl"] = kobj_sddl(h)
        k32.CloseHandle(h)
    return out


def run_tool(argv, cwd=None, timeout=30, stdin="devnull", env=None):
    """T1-T6: run an installed tool (Node, Git Bash, Git) and keep its exit code and output tails.
    Output is captured through anonymous pipes, which worked in all four configurations (ISO-11).
    stdin "devnull" opens NUL (subprocess.DEVNULL, used up to 2026-11-26-02); "pipe" gives an empty pipe."""
    t0 = time.monotonic()
    kw = {"stdin": subprocess.DEVNULL} if stdin == "devnull" else {"input": b""}
    if env:
        kw["env"] = {**os.environ, **env}
    try:
        # argv is passed unchanged: expandvars would replace $PATH in bash commands before bash sees them
        p = subprocess.run(list(argv), cwd=expand(cwd) if cwd else None, capture_output=True,
                           timeout=timeout, **kw)
        return {"exit": p.returncode, "seconds": round(time.monotonic() - t0, 2),
                "stdout": p.stdout.decode("utf-8", "replace")[-800:],
                "stderr": p.stderr.decode("utf-8", "replace")[-800:]}
    except subprocess.TimeoutExpired as e:
        return {"exit": "timeout", "seconds": timeout,
                "stdout": (e.stdout or b"").decode("utf-8", "replace")[-800:],
                "stderr": (e.stderr or b"").decode("utf-8", "replace")[-800:]}
    except OSError as e:
        return {"exit": f"oserror:{getattr(e, 'winerror', None) or e.errno}"}


def hold(seconds, hb, stop):
    end = time.time() + float(seconds)
    while time.time() < end and not Path(stop).exists():
        try:
            Path(hb).write_text(f"{os.getpid()} {time.time()}\n")
        except OSError:
            pass
        time.sleep(0.5)
    return "stopped" if Path(stop).exists() else "timeout"


# ---------------------------------------------------------------- dispatcher
def run_task(t):
    kind = t["kind"]
    if kind == "token":
        return token_info()
    if kind == "fs":
        return {o.get("id", f"{o['op']}:{o.get('path')}"): fs_op(o) for o in t["ops"]}
    if kind == "env":
        return {n: os.environ.get(n) for n in t["names"]}
    if kind == "reg":
        return {k.get("id", f"{k['root']}\\{k['path']}"): reg_open(k["root"], k["path"], k["access"]) for k in t["keys"]}
    if kind == "hku":
        names = hku_names()
        return {"names": names, "opened": {n: reg_open("HKU", n, winreg.KEY_READ) for n in names}}
    if kind == "proc_open":
        return {str(pid): proc_open(int(pid)) for pid in t["pids"]}
    if kind == "proc_open_ancestors":
        # only ancestors whose image name starts with one of the given product names; first match per name
        out, used = {}, set()
        for a in ancestors()[1:]:
            for n in t["names"]:
                if n not in used and a["exe"].lower().startswith(n.lower()):
                    used.add(n)
                    out[f"{a['exe']}"] = proc_open(a["pid"])
        return out
    if kind == "cmdline":
        return cmdline_has(int(t["pid"]), t["marker"])
    if kind == "proc_list":
        return proc_list(t["categories"])
    if kind == "dpapi":
        return {Path(p).name: dpapi_unprotect(p, t["expected"]) for p in t["paths"]}
    if kind == "spawn":
        return spawn(t)
    if kind == "sleep":
        sleeper(t["seconds"], expand(t["heartbeat"]))
        return "slept"
    if kind == "window":
        return window(t["seconds"], t["title"])
    if kind == "parbuild":
        return parbuild(t["ws"])
    if kind == "pipe":
        return pipe_open(t["name"])
    if kind == "wait":
        time.sleep(t["seconds"])
        return "waited"
    if kind == "nsdir":
        return ns_dirs()
    if kind == "nobj_open":
        return nobj_open(t["objects"], t.get("effects", False), t.get("marker", ""))
    if kind == "nobj_create":
        return nobj_create(t["objects"], keep=t.get("keep", True))
    if kind == "pipe_steps":
        return pipe_steps()
    if kind == "pipe_serve":
        return pipe_serve(t["name"], t.get("instances", 4), expand(t["log"]))
    if kind == "pipe_client":
        return pipe_client(t["name"], t["data"])
    if kind == "hold":
        return hold(t["seconds"], expand(t["heartbeat"]), expand(t["stop"]))
    if kind == "run":
        return run_tool(t["argv"], t.get("cwd"), t.get("timeout", 30), t.get("stdin", "devnull"), t.get("env"))
    return f"unknown_kind:{kind}"


def main():
    if sys.argv[1] == "sleep":
        sleeper(sys.argv[2], sys.argv[3])
        return
    if sys.argv[1] == "window":
        window(sys.argv[2], sys.argv[3])
        return
    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out = {}
    for t in spec["tasks"]:
        if t["kind"] == "checkpoint":  # results so far, for a harness that acts while this process keeps running
            try:
                Path(expand(t["path"])).write_text(json.dumps(out), encoding="utf-8")
                out[t["id"]] = "written"
            except OSError as e:
                out[t["id"]] = f"error:{e}"
            continue
        try:
            out[t["id"]] = run_task(t)
        except Exception as e:  # keep going; record the failure
            out[t["id"]] = f"exception:{type(e).__name__}:{e}"
    line = json.dumps(out)
    if spec.get("out"):
        try:
            Path(expand(spec["out"])).write_text(line, encoding="utf-8")
        except OSError:
            pass
    print("ISOJSON " + line, flush=True)


if __name__ == "__main__":
    main()
