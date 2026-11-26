"""Test launcher for the reduced restricting SID measurement (runs/2026-11-26-03.md).

Runs as a measurement sandbox account. The host starts it with CreateProcessWithLogonW (logon flags 0,
CREATE_NO_WINDOW, the same call as Codex elevated starts codex-command-runner.exe). For each launch in
the spec it builds a WRITE_RESTRICTED token from its own token and starts the command on WinSta0\\Default
with CreateProcessAsUserW, inside a Job that kills the remaining processes when the launch ends.

Token, following Codex rust-v0.171.0 windows-sandbox-rs/src/token.rs (create_token_with_caps_from):
  flags              DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED (modes base, reduced)
                     DISABLE_MAX_PRIVILEGE | LUA_TOKEN                    (modes full1, full2: the
                     restricting SIDs are checked for every access, reads included)
  restricting SIDs   base:    capability SID, [turn SIDs], own account SID, logon SID, Everyone  (Codex order)
                     reduced: capability SID, [turn SIDs], own account SID
                     full1:   capability SID, [turn SIDs], own account SID, ALL APPLICATION PACKAGES,
                              Everyone, logon SID
                     full2:   capability SID, [turn SIDs], own account SID, ALL APPLICATION PACKAGES
                     Turn SIDs come from the launch ("extra_sids") or the spec; one token per distinct list.
                     full1, full2 and turn SIDs were added for a follow-up request that was cancelled before
                     it ran; no measurement used them.
  default DACL       logon SID GENERIC_ALL, OWNER RIGHTS READ_CONTROL (Codex set_default_dacl)
                     "account" variant adds the own account SID GENERIC_ALL
  SeChangeNotifyPrivilege enabled
Error mode SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX is set first, as Codex runner_client.rs does
around CreateProcessWithLogonW; the restricted processes inherit it, so a start failure (0xC0000142) shows
no error box on the user's desktop (added 2026-11-26 after the first run showed those boxes).
Differences from Codex: no private desktop (WinSta0\\Default), standard handles are files and an empty
pipe opened here instead of the runner's named pipes, no PID check, one restricted process per launch.

Usage: python launcher.py <spec.json>
Only the launcher's own token is opened. The result JSON is written to spec["result"].
"""
import os
import sys
import json
import time
import ctypes
import subprocess
import importlib.util
from ctypes import wintypes
from pathlib import Path

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
HANDLE, DW, BOOL, VP = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, ctypes.c_void_p

_c = importlib.util.spec_from_file_location("child", Path(__file__).with_name("child.py"))
C = importlib.util.module_from_spec(_c)
_c.loader.exec_module(C)


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", VP), ("Attributes", DW)]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", DW), ("HighPart", wintypes.LONG)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", DW), ("Luid", LUID), ("Attributes", DW)]


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", DW), ("lpSecurityDescriptor", VP), ("bInheritHandle", BOOL)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", DW), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR), ("dwX", DW), ("dwY", DW), ("dwXSize", DW), ("dwYSize", DW),
                ("dwXCountChars", DW), ("dwYCountChars", DW), ("dwFillAttribute", DW), ("dwFlags", DW),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", VP),
                ("hStdInput", HANDLE), ("hStdOutput", HANDLE), ("hStdError", HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", HANDLE), ("hThread", HANDLE), ("dwProcessId", DW), ("dwThreadId", DW)]


class ACCOUNTING(ctypes.Structure):
    _fields_ = [("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong), ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", DW), ("TotalProcesses", DW), ("ActiveProcesses", DW),
                ("TotalTerminatedProcesses", DW)]


for _n, _res, _args in (
        ("CreateRestrictedToken", BOOL, [HANDLE, DW, DW, VP, DW, VP, DW, VP, ctypes.POINTER(HANDLE)]),
        ("ConvertStringSidToSidW", BOOL, [wintypes.LPCWSTR, ctypes.POINTER(VP)]),
        ("ConvertStringSecurityDescriptorToSecurityDescriptorW", BOOL, [wintypes.LPCWSTR, DW, ctypes.POINTER(VP), VP]),
        ("GetSecurityDescriptorDacl", BOOL, [VP, ctypes.POINTER(BOOL), ctypes.POINTER(VP), ctypes.POINTER(BOOL)]),
        ("SetTokenInformation", BOOL, [HANDLE, ctypes.c_int, VP, DW]),
        ("LookupPrivilegeValueW", BOOL, [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]),
        ("AdjustTokenPrivileges", BOOL, [HANDLE, BOOL, VP, DW, VP, VP]),
        ("CreateProcessAsUserW", BOOL, [HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, VP, VP, BOOL, DW, VP,
                                        wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
                                        ctypes.POINTER(PROCESS_INFORMATION)])):
    getattr(adv, _n).restype = _res
    getattr(adv, _n).argtypes = _args
for _n, _res, _args in (
        ("CreatePipe", BOOL, [ctypes.POINTER(HANDLE), ctypes.POINTER(HANDLE), VP, DW]),
        ("SetHandleInformation", BOOL, [HANDLE, DW, DW]),
        ("CreateJobObjectW", HANDLE, [VP, wintypes.LPCWSTR]),
        ("SetInformationJobObject", BOOL, [HANDLE, ctypes.c_int, VP, DW]),
        ("AssignProcessToJobObject", BOOL, [HANDLE, HANDLE]),
        ("ResumeThread", DW, [HANDLE]),
        ("GetExitCodeProcess", BOOL, [HANDLE, ctypes.POINTER(DW)]),
        ("TerminateJobObject", BOOL, [HANDLE, wintypes.UINT]),
        ("TerminateProcess", BOOL, [HANDLE, wintypes.UINT]),
        ("GetCurrentProcess", HANDLE, []),
        ("CreateFileW", HANDLE, [wintypes.LPCWSTR, DW, DW, VP, DW, DW, HANDLE]),
        ("CloseHandle", BOOL, [HANDLE]),
        ("WaitForSingleObject", DW, [HANDLE, DW]),
        ("QueryInformationJobObject", BOOL, [HANDLE, ctypes.c_int, VP, DW, ctypes.POINTER(DW)]),
        ("LocalFree", VP, [VP]),
        ("SetErrorMode", wintypes.UINT, [wintypes.UINT])):
    getattr(k32, _n).restype = _res
    getattr(k32, _n).argtypes = _args
adv.OpenProcessToken.restype = BOOL
adv.OpenProcessToken.argtypes = [HANDLE, DW, ctypes.POINTER(HANDLE)]

TOKEN_ALL_ACCESS = 0xF01FF
DISABLE_MAX_PRIVILEGE, LUA_TOKEN, WRITE_RESTRICTED = 0x1, 0x4, 0x8
EVERYONE, OWNER_RIGHTS, ALL_APP_PACKAGES = "S-1-1-0", "S-1-3-4", "S-1-15-2-1"


def err():
    return f"error:{ctypes.get_last_error()}"


def psid(s):
    p = VP()
    if not adv.ConvertStringSidToSidW(s, ctypes.byref(p)):
        raise OSError(f"ConvertStringSidToSidW {s}: {err()}")
    return p


def own_token():
    h = HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), TOKEN_ALL_ACCESS, ctypes.byref(h)):
        raise OSError(f"OpenProcessToken: {err()}")
    return h


def restricted_token(base, mode, cap_sid, dacl_variant, extra=()):
    """Returns (token handle, record, launcher token info)."""
    info = C.token_info()
    user, logon = info["user"], (info["logon_sids"] or [None])[0]
    if not logon:
        raise OSError("no logon SID in the launcher token")
    tail = {"base": [logon, EVERYONE], "reduced": [], "full1": [ALL_APP_PACKAGES, EVERYONE, logon],
            "full2": [ALL_APP_PACKAGES]}[mode]
    sids = [cap_sid, *extra, user] + tail
    flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN | (WRITE_RESTRICTED if mode in ("base", "reduced") else 0)
    arr = (SID_AND_ATTRIBUTES * len(sids))(*[SID_AND_ATTRIBUTES(psid(s).value, 0) for s in sids])
    new = HANDLE()
    if not adv.CreateRestrictedToken(base, flags, 0, None, 0, None, len(sids), arr, ctypes.byref(new)):
        raise OSError(f"CreateRestrictedToken: {err()}")
    aces = f"(A;;GA;;;{logon})(A;;RC;;;{OWNER_RIGHTS})"
    if dacl_variant == "account":
        aces += f"(A;;GA;;;{user})"
    psd, present, pacl, defaulted = VP(), BOOL(), VP(), BOOL()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:" + aces, 1, ctypes.byref(psd), None):
        raise OSError(f"SDDL: {err()}")
    adv.GetSecurityDescriptorDacl(psd, ctypes.byref(present), ctypes.byref(pacl), ctypes.byref(defaulted))
    tdd = VP(pacl.value)
    if not adv.SetTokenInformation(new, 6, ctypes.byref(tdd), ctypes.sizeof(tdd)):  # TokenDefaultDacl
        raise OSError(f"SetTokenInformation(TokenDefaultDacl): {err()}")
    k32.LocalFree(psd)
    tp = TOKEN_PRIVILEGES(1, LUID(), 0x2)
    adv.LookupPrivilegeValueW(None, "SeChangeNotifyPrivilege", ctypes.byref(tp.Luid))
    adv.AdjustTokenPrivileges(new, False, ctypes.byref(tp), 0, None, None)
    dd = C.tok_raw(new, 6)  # keep the buffer alive while its ACEs are read
    rec = {"restricting_sids": C.tok_groups(new, 11), "default_dacl": C.acl_aces(ctypes.c_void_p.from_buffer(dd, 0).value),
           "flags": "DISABLE_MAX_PRIVILEGE|LUA_TOKEN" + ("|WRITE_RESTRICTED" if flags & WRITE_RESTRICTED else "")}
    return new, rec, info


def env_block(env):
    s = "".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper())) + "\0"
    return ctypes.create_unicode_buffer(s, len(s))


def launch(tok, L, env, cwd):
    sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
    hout = k32.CreateFileW(L["stdout"], 0x40000000, 0x1, ctypes.byref(sa), 2, 0x80, None)
    herr = k32.CreateFileW(L["stderr"], 0x40000000, 0x1, ctypes.byref(sa), 2, 0x80, None)
    rd, wr = HANDLE(), HANDLE()
    k32.CreatePipe(ctypes.byref(rd), ctypes.byref(wr), ctypes.byref(sa), 0)
    k32.SetHandleInformation(wr, 1, 0)  # write end stays here and is closed: the child sees end of input
    desktop = ctypes.create_unicode_buffer("winsta0\\default")
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    si.lpDesktop = ctypes.cast(desktop, wintypes.LPWSTR)
    si.dwFlags = 0x100  # STARTF_USESTDHANDLES
    si.hStdInput, si.hStdOutput, si.hStdError = rd, hout, herr
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline(L["argv"]))
    # CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW (hidden console) or DETACHED_PROCESS (none)
    flags = 0x4 | 0x400 | (0x8 if L.get("console") == "none" else 0x08000000)
    t0 = time.monotonic()
    ok = adv.CreateProcessAsUserW(tok, None, cmd, None, None, True, flags, ctypes.cast(env, VP), cwd,
                                  ctypes.byref(si), ctypes.byref(pi))
    e = ctypes.get_last_error()
    for h in (rd, wr, hout, herr):
        k32.CloseHandle(h)
    if not ok:
        return {"created": f"error:{e}"}
    job = k32.CreateJobObjectW(None, None)
    lim = C.EXT_LIMIT()
    lim.Basic.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    k32.SetInformationJobObject(job, 9, ctypes.byref(lim), ctypes.sizeof(lim))
    in_job = bool(k32.AssignProcessToJobObject(job, pi.hProcess))
    k32.ResumeThread(pi.hThread)
    w = k32.WaitForSingleObject(pi.hProcess, int(L.get("timeout", 60) * 1000))
    code = DW()
    k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
    acct = ACCOUNTING()
    k32.QueryInformationJobObject(job, 1, ctypes.byref(acct), ctypes.sizeof(acct), None)
    r = {"created": "yes", "pid": pi.dwProcessId, "in_job": in_job, "seconds": round(time.monotonic() - t0, 2),
         "console": L.get("console", "hidden"),
         "exit": "timeout" if w == 0x102 else f"0x{code.value:08x}", "job_total_processes": acct.TotalProcesses,
         "job_active_after_main_exit": acct.ActiveProcesses}
    if w == 0x102 or acct.ActiveProcesses:
        k32.TerminateJobObject(job, 1)
    for h in (pi.hThread, pi.hProcess, job):
        k32.CloseHandle(h)
    return r


def main():
    k32.SetErrorMode(0x0001 | 0x0002)  # SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX, inherited by children
    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out = {"spec_tag": spec.get("tag"), "mode": spec["mode"], "dacl_variant": spec.get("dacl", "codex"),
           "pid": os.getpid(), "error_mode": "0x3", "launches": {}}
    tokens = {}
    try:
        base = own_token()

        def token_for(extra):
            key = tuple(extra)
            if key not in tokens:
                tok, rec, info = restricted_token(base, spec["mode"], spec["cap_sid"], spec.get("dacl", "codex"), key)
                tokens[key] = tok
                out.setdefault("restricted_by_extra", {})["|".join(key)] = rec
                out.setdefault("restricted", rec)
                out.setdefault("launcher_token", info)
            return tokens[key]
        token_for(spec.get("extra_sids", []))
        out["launcher_process_sd"] = C.kobj_sddl(k32.GetCurrentProcess())
        env = env_block(spec["env"])
        for L in spec["launches"]:
            try:
                out["launches"][L["id"]] = launch(token_for(L.get("extra_sids", spec.get("extra_sids", []))), L, env,
                                                  spec["cwd"])
            except Exception as e:
                out["launches"][L["id"]] = f"exception:{type(e).__name__}:{e}"
        for tok in tokens.values():
            k32.CloseHandle(tok)
        k32.CloseHandle(base)
    except Exception as e:
        out["error"] = f"{type(e).__name__}:{e}"
    Path(spec["result"]).write_text(json.dumps(out), encoding="utf-8")


if __name__ == "__main__":
    main()
