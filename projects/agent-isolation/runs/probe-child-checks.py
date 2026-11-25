"""Runs inside the sandbox. Read-only permission checks; prints one JSON line.

reg    : open registry keys with read / set-value / create-subkey access. Nothing is written.
clip   : whether the clipboard can be opened, and how many formats it holds. Content is never read.
limits : job object limits of this process, 3 concurrent children, one 256 MB allocation.
"""
import sys
import json
import time
import ctypes
import subprocess
import winreg
from ctypes import wintypes

mode = sys.argv[1]
out = {}

if mode == "reg":
    roots = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    keys = [("HKCU", r"Software"), ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ("HKCU", r"Environment"), ("HKCU", r"Software\Classes"), ("HKCU", r"Console"),
            ("HKLM", r"SOFTWARE")]
    rights = {"read": winreg.KEY_READ, "set_value": winreg.KEY_SET_VALUE,
              "create_subkey": winreg.KEY_CREATE_SUB_KEY}
    for r, k in keys:
        res = {}
        for name, acc in rights.items():
            try:
                winreg.OpenKey(roots[r], k, 0, acc).Close()
                res[name] = "granted"
            except OSError as e:
                res[name] = f"denied:{e.winerror}"
        out[f"{r}\\{k}"] = res

elif mode == "clip":
    u = ctypes.WinDLL("user32", use_last_error=True)
    u.OpenClipboard.argtypes = [wintypes.HWND]
    out["sequence_number_nonzero"] = u.GetClipboardSequenceNumber() != 0
    ok = u.OpenClipboard(None)
    out["open"] = bool(ok)
    out["error"] = 0 if ok else ctypes.get_last_error()
    if ok:
        out["format_count"] = u.CountClipboardFormats()
        u.CloseClipboard()

elif mode == "limits":
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    cur = wintypes.HANDLE(-1)  # pseudo handle of the current process

    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class EXT(ctypes.Structure):
        _fields_ = [("Basic", BASIC), ("Io", ctypes.c_uint64 * 6), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    in_job = wintypes.BOOL()
    k.IsProcessInJob(cur, None, ctypes.byref(in_job))
    out["in_job"] = bool(in_job)
    info, ret = EXT(), wintypes.DWORD()
    if k.QueryInformationJobObject(None, 9, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(ret)):
        out["job_limit_flags"] = hex(info.Basic.LimitFlags)
        out["active_process_limit"] = info.Basic.ActiveProcessLimit
        out["process_memory_limit"] = info.ProcessMemoryLimit
        out["job_memory_limit"] = info.JobMemoryLimit
    else:
        out["job_query_error"] = ctypes.get_last_error()

    procs, errors = [], []
    for _ in range(3):
        try:
            procs.append(subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(4)"]))
        except OSError as e:
            errors.append(e.winerror)
    time.sleep(1.5)
    out["children_started"] = len(procs)
    out["children_alive_together"] = sum(1 for p in procs if p.poll() is None)
    out["child_start_errors"] = errors
    for p in procs:
        p.wait(timeout=15)

    try:
        block = bytearray(256 * 1024 * 1024)  # zero-filled, so every page is touched
        out["alloc_256mb"] = "ok"
    except MemoryError:
        block = None
        out["alloc_256mb"] = "MemoryError"

    class PMC(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + \
                   [(n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                                                   "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                                                   "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage",
                                                   "PrivateUsage")]

    pmc = PMC()
    pmc.cb = ctypes.sizeof(pmc)
    k.K32GetProcessMemoryInfo(cur, ctypes.byref(pmc), pmc.cb)
    out["private_mb"] = pmc.PrivateUsage // (1024 * 1024)
    del block

print("ISOJSON " + json.dumps(out))
