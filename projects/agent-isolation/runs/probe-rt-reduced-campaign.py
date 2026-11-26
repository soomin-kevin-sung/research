"""Reduced restricting SID measurement, host side (runs/2026-11-26-03.md).

Requested by another session that plans a separate-account Restricted Token shell.
Two WRITE_RESTRICTED token configurations are built by probe-rt-reduced-launcher.py, which the host starts
under a measurement account with CreateProcessWithLogonW (Codex elevated structure, no private desktop):
  base     restricting SIDs: capability SID, account SID, logon SID, Everyone   (Codex elevated)
  reduced  restricting SIDs: capability SID, account SID

Usage (normal, non-elevated session, test venv Python):
  python probe-rt-reduced-campaign.py <group> [<group> ...]
    precheck        one trial of base and reduced (plumbing check, result kept separately)
    main            five trials of base and reduced with iso-rt-sbx1, and the host control
    fix-<name>      reduced with targeted additions for the account (five trials each):
                      desktop        account ACEs on WinSta0 and Default (host, restored after)
                      dacl           account SID GENERIC_ALL added to the token default DACL
                      desktop-dacl   both
                      devices        iso-rt-sbx2: account ACEs on \\Device\\Null, \\Device\\CNG, \\Device\\KsecDD
                                     (added in the UAC step)
                      all            devices + desktop + dacl
                      all-local      all + an account ACE on the session's BaseNamedObjects (Local\\)
                      all-local-bno  all-local after the UAC step bno-add (account ACE on the global
                                     \\BaseNamedObjects, where Git Bash creates its directory)
                      all-local-bno-msys  all-local-bno + an account ACE on the MSYS2 object directory
                                     itself (\\BaseNamedObjects\\msys-2.0S5-<install hash>; the first Git Bash
                                     on the PC creates it and every later one opens it; owner: the user,
                                     restored after)
    state-<label>   state of everything this measurement creates (accounts, group, DACLs, test paths)
Each trial runs three launcher phases: main (shells, tools, holes), window (Notepad from PowerShell and
a test window), squat (the sandbox creates Local\\ objects that the host then creates with the same name).
Only synthetic iso-rt-* names are used. Other processes are only opened and closed by the in-sandbox program.
"""
import os
import sys
import json
import time
import uuid
import base64
import ctypes
import subprocess
import importlib.util
from ctypes import wintypes
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26-rt")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, TOOLS, PY, CHILD, save, load, parse_isojson, token_sids,  # noqa: E402
                                   find_window, start_test_process, dacl_aces, lookup_sid)

_c = importlib.util.spec_from_file_location("isochild", Path(__file__).with_name("probe-token-backends-child.py"))
C = importlib.util.module_from_spec(_c)
_c.loader.exec_module(C)

TRIALS = int(os.environ.get("ISO_TRIALS", "5"))
RT = ROOT / "rt"
WS, OUT, SPECS = RT / "ws-A", RT / "out", RT / "specs"
LAUNCHER = TOOLS / "launcher.py"
HKCU_BASE = r"Software\agent-isolation-rt"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
NOTEPAD = r"C:\Windows\System32\notepad.exe"
NODE = r"C:\Program Files\nodejs\node.exe"
BASH = r"C:\Program Files\Git\usr\bin\bash.exe"
BASH_LAUNCHER = r"C:\Program Files\Git\bin\bash.exe"
GIT = r"C:\Program Files\Git\cmd\git.exe"
NODE_CASES = ("basic", "spawn_pipe", "spawn_inherit", "spawn_async", "exec_shell", "fork_ipc", "worker", "pipe_server")
TYPES = ("event", "mutex", "semaphore", "section")
S = None  # setup.json
ENV = None

PS_BASIC = r"""
"psver=" + $PSVersionTable.PSVersion
"cwd=" + (Get-Location).Path
"items=" + (Get-ChildItem -Force).Count
try { Set-Content -Path ps-basic.txt -Value ok -ErrorAction Stop; "write=" + (Get-Content ps-basic.txt); Remove-Item ps-basic.txt -ErrorAction Stop; "delete=ok" } catch { "write=err:" + $_.Exception.Message }
"user=" + [Environment]::UserName
"proc=" + (Get-Process -Id $PID).ProcessName
"done=ok"
"""
PS_NULL = r"""
function T([string]$n, [scriptblock]$b) { try { $null = & $b; "$n=ok" } catch { "$n=err:" + $_.Exception.GetType().Name + ":" + $_.Exception.Message } }
T 'gt_null' { 'a' > $null }
T 'out_null' { 'b' | Out-Null }
T 'void_cast' { [void]'c' }
T 'assign_null' { $null = 'd' }
T 'err_stream_to_null' { Get-Item -LiteralPath 'C:\iso-rt-none' 2> $null }
T 'gt_nul_device' { 'e' > NUL }
T 'outfile_nul' { 'f' | Out-File -FilePath NUL -ErrorAction Stop }
T 'native_gt_nul' { cmd /d /c "echo g>nul"; if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" } }
T 'native_err_to_nul' { cmd /d /c "(echo h 1>&2) 2>nul"; if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" } }
T 'native_out_null' { cmd /d /c "echo i" | Out-Null }
"done=ok"
"""
PS_WINDOW = r"""
try { $p = Start-Process -FilePath '%s' -PassThru -ErrorAction Stop; "start=ok"; "pid=" + $p.Id } catch { "start=err:" + $_.Exception.Message }
Start-Sleep -Seconds 6
if ($p) { "exited=" + $p.HasExited; try { Stop-Process -Id $p.Id -ErrorAction Stop; "stop=ok" } catch { "stop=err:" + $_.Exception.Message } }
"done=ok"
""" % NOTEPAD


def ps_argv(script):
    return [PS, "-NoProfile", "-NonInteractive", "-EncodedCommand",
            base64.b64encode(script.strip().encode("utf-16-le")).decode()]


# ---------------------------------------------------------------- CreateProcessWithLogonW
adv = ctypes.WinDLL("advapi32", use_last_error=True)
k32 = ctypes.WinDLL("kernel32", use_last_error=True)


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD)]


adv.CreateProcessWithLogonW.restype = wintypes.BOOL
adv.CreateProcessWithLogonW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                        wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
                                        wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOW),
                                        ctypes.POINTER(PROCESS_INFORMATION)]
k32.WaitForSingleObject.restype = wintypes.DWORD
k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
k32.SetErrorMode.restype = wintypes.UINT
k32.SetErrorMode.argtypes = [wintypes.UINT]


def passwords():
    return json.loads((ROOT / "secrets" / "sbx.json").read_text(encoding="utf-8"))


class _SelfProc:
    def __init__(self, p):
        self.p, self.hProcess = p, int(p._handle)


def logon_start(account, spec_path):
    """account "__self__": plumbing check only, the launcher runs as the current user (no logon).
    Otherwise the same call shape as Codex runner_client.rs: logon flags 0, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
    no environment block, STARTF_FORCEOFFFEEDBACK, no desktop name."""
    if account == "__self__":
        return _SelfProc(subprocess.Popen([str(PY), "-I", "-B", str(LAUNCHER), str(spec_path)], cwd=WS,
                                          creationflags=0x08000000)), None
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    si.dwFlags = 0x80  # STARTF_FORCEOFFFEEDBACK
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(PY), "-I", "-B", str(LAUNCHER), str(spec_path)]))
    previous = k32.SetErrorMode(0x0001 | 0x0002)  # as Codex: no error boxes from the runner's start
    ok = adv.CreateProcessWithLogonW(account, ".", passwords()[account], 0, str(PY), cmd, 0x08000000 | 0x400, None,
                                     str(WS), ctypes.byref(si), ctypes.byref(pi))
    e = ctypes.get_last_error()
    k32.SetErrorMode(previous)
    if not ok:
        return None, f"error:{e}"
    k32.CloseHandle(pi.hThread)
    return pi, None


def read_text(p, n=1500):
    try:
        return Path(p).read_bytes().decode("utf-8", "replace")[-n:]
    except OSError as e:
        return f"read_error:{e}"


def kv(text):
    out = {}
    for ln in (text or "").splitlines():
        if "=" in ln and not ln.startswith(" "):
            k, v = ln.split("=", 1)
            if k.strip() and " " not in k.strip():
                out[k.strip()] = v.strip()
    return out


def launch(tag, lid, argv, timeout=90):
    return {"id": lid, "argv": [str(a) for a in argv], "stdout": str(OUT / f"{tag}-{lid}.out"),
            "stderr": str(OUT / f"{tag}-{lid}.err"), "timeout": timeout}


def child_launch(tag, lid, tasks, timeout=300):
    sp = SPECS / f"{tag}-{lid}.json"
    sp.write_text(json.dumps({"tasks": tasks}), encoding="utf-8")
    return launch(tag, lid, [PY, "-I", "-B", CHILD, sp], timeout)


def run_phase(account, mode, launches, tag, dacl="codex", during=None, timeout=600, extra=None):
    spec = {"tag": tag, "mode": mode, "dacl": dacl, "cap_sid": S["cap_sid"], "env": ENV, "cwd": str(WS),
            "launches": launches, "result": str(OUT / f"{tag}-launcher.json"), "extra_sids": extra or []}
    sp = SPECS / f"{tag}-launcher.json"
    sp.write_text(json.dumps(spec), encoding="utf-8")
    t0 = time.monotonic()
    pi, e = logon_start(account, sp)
    if e:
        return {"logon_error": e}
    extra = during(pi.hProcess) if during else None
    w = k32.WaitForSingleObject(pi.hProcess, timeout * 1000)
    if w == 0x102:
        k32.TerminateProcess(pi.hProcess, 1)
    if not isinstance(pi, _SelfProc):
        k32.CloseHandle(pi.hProcess)
    rec = {"seconds": round(time.monotonic() - t0, 2), "launcher_timeout": w == 0x102, "during": extra}
    try:
        res = json.loads(Path(spec["result"]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as ex:
        rec["launcher"] = f"no result: {ex}"
        return rec
    for L in launches:
        r = res["launches"].get(L["id"])
        if isinstance(r, dict):
            so, se = read_text(L["stdout"], 10**7), read_text(L["stderr"])
            parsed = parse_isojson(so)
            r["result"] = parsed if parsed is not None else kv(so)
            r["stdout_tail"] = so[-600:] if parsed is None else None
            r["stderr_tail"] = se[-600:]
    rec["launcher"] = res
    return rec


# ---------------------------------------------------------------- host-side observers
def wts_processes():
    wts = ctypes.WinDLL("wtsapi32")

    class WTS_PROCESS_INFO(ctypes.Structure):
        _fields_ = [("SessionId", ctypes.c_uint32), ("ProcessId", ctypes.c_uint32),
                    ("pProcessName", ctypes.c_wchar_p), ("pUserSid", ctypes.c_void_p)]

    ptr = ctypes.POINTER(WTS_PROCESS_INFO)()
    count = ctypes.c_uint32()
    out = {}
    if not wts.WTSEnumerateProcessesW(None, 0, 1, ctypes.byref(ptr), ctypes.byref(count)):
        return out
    for i in range(count.value):
        e = ptr[i]
        out[e.ProcessId] = (C.sid_str(e.pUserSid) if e.pUserSid else None, e.pProcessName)
    wts.WTSFreeMemory(ptr)
    return out


def sandbox_sids():
    return set((S.get("account_sids") or {}).values()) | ({S["user_sid"]} if SELF_CHECK else set())


def window_poller(title, seconds=60):
    """Top-level windows of processes that belong to the measurement accounts and started after the phase began."""
    user32 = ctypes.WinDLL("user32")
    sandbox = sandbox_sids()
    before = set(wts_processes())

    def during(hproc):
        seen, title_seen = {}, None
        t0 = time.time()
        while time.time() - t0 < seconds:
            procs = wts_processes()
            mine = {pid: name for pid, (sid, name) in procs.items() if sid in sandbox and pid not in before}
            found = []

            @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
            def cb(hwnd, _):
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(ctypes.c_void_p(hwnd), ctypes.byref(pid))
                if pid.value in mine:
                    cls, txt = ctypes.create_unicode_buffer(128), ctypes.create_unicode_buffer(128)
                    user32.GetClassNameW(ctypes.c_void_p(hwnd), cls, 128)
                    user32.GetWindowTextW(ctypes.c_void_p(hwnd), txt, 128)
                    found.append((pid.value, mine[pid.value], cls.value, txt.value,
                                  bool(user32.IsWindowVisible(ctypes.c_void_p(hwnd)))))
                return True
            user32.EnumWindows(cb, None)
            for pid, image, cls, txt, vis in found:
                key = f"{image}|{cls}"
                r = seen.setdefault(key, {"image": image, "class": cls, "visible": False, "title_is_test": False})
                r["visible"] = r["visible"] or vis
                r["title_is_test"] = r["title_is_test"] or txt == title
                if txt == title:
                    title_seen = {"visible": vis}
            if k32.WaitForSingleObject(hproc, 0) == 0:
                break
            time.sleep(0.3)
        return {"sandbox_windows": list(seen.values()), "test_window": title_seen or {"found": False}}
    return during


def squat_host(objs, cp, stop):
    def during(hproc):
        t0 = time.time()
        while time.time() - t0 < 120 and not cp.exists() and k32.WaitForSingleObject(hproc, 0) != 0:
            time.sleep(0.2)
        rec = {"checkpoint": cp.exists()}
        time.sleep(0.3)
        rec["host_create_same_names"] = C.nobj_create(objs, keep=False)
        stop.write_text("stop")
        return rec
    return during


def host_objects(tag):
    objs = [{"type": ty, "name": f"Local\\iso-rt-h-{tag}-{ty}"} for ty in TYPES]
    held, out = [], {}
    for o in objs:
        r = C.nobj_create([{**o, "marker": f"H-{tag}" if o["type"] == "section" else None}], keep=True)
        out.update(r)
        if r[o["name"]].get("created") in ("new", "existing"):
            held.append((o["type"], o["name"], C.KEEP.pop()))
    return objs, held, out


def host_check(held, marker):
    out = {}
    for typ, name, h in held:
        if typ == "section":
            v = C.section_io(h)
            out[name] = {"content": v, "sandbox_marker_seen": v == marker}
        elif typ == "mutex":
            w = C.wait0(h)
            if w in ("signaled", "abandoned"):
                C.k32.ReleaseMutex(h)
            out[name] = {"host_acquire": w}
        else:
            out[name] = {"state": C.wait0(h)}
        C.k32.CloseHandle(h)
    return out


# ---------------------------------------------------------------- tasks
def tool_tasks(tag):
    repo = WS / "repo"
    tasks = [{"id": f"node_{c}", "kind": "run", "argv": [NODE, str(WS / "nodetest.js"), c, tag], "cwd": str(WS),
              "timeout": 25, "stdin": "pipe"} for c in NODE_CASES]
    b = [BASH, "--noprofile", "--norc", "-c"]
    for name, cmd in (("bash_echo", "echo bash-ok"), ("bash_pipe", "echo pipe-ok | cat"),
                      ("bash_subst", 'x=$(echo subst-ok); echo "$x"'), ("bash_bg", "sleep 1 & wait $!; echo bg-ok:$?"),
                      ("bash_devnull", "echo x > /dev/null && echo devnull-ok")):
        tasks.append({"id": name, "kind": "run", "argv": b + ["PATH=/usr/bin:$PATH; " + cmd], "cwd": str(WS),
                      "stdin": "pipe"})
    safe = {"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": str(repo),
            "GIT_CONFIG_KEY_1": "safe.directory", "GIT_CONFIG_VALUE_1": f"{repo}/*"}
    status = [GIT, "--no-optional-locks", "status", "--porcelain"]
    tasks += [{"id": "bash_launcher", "kind": "run", "argv": [BASH_LAUNCHER, "--noprofile", "--norc", "-c", "echo launcher-ok"],
               "cwd": str(WS), "stdin": "pipe"},
              {"id": "git_version", "kind": "run", "argv": [GIT, "--version"], "cwd": str(WS), "stdin": "pipe"},
              {"id": "git_status", "kind": "run", "argv": status, "cwd": str(repo), "stdin": "pipe"},
              {"id": "git_status_safe_directory", "kind": "run", "argv": status, "cwd": str(repo), "stdin": "pipe",
               "env": safe},
              # same, with HOME on a folder the account can read (the user's .gitconfig is not readable to it)
              {"id": "git_status_safe_directory_home", "kind": "run", "argv": status, "cwd": str(repo), "stdin": "pipe",
               "env": {**safe, "HOME": str(RT / "temp")}}]
    return tasks


def compat_tasks(tag):
    g4 = WS / "g4" / tag
    g4.mkdir(parents=True, exist_ok=True)
    nobjs = [{"type": ty, "name": f"{ns}\\iso-rt-c-{tag}-{ty}"} for ns in ("Local", "Global")
             for ty in ("event", "mutex", "section")]
    return [{"id": "token", "kind": "token"},
            {"id": "nul", "kind": "fs", "ops": [
                {"id": "open_read", "op": "open", "path": r"\\.\NUL", "access": 0x80000000},
                {"id": "open_write", "op": "open", "path": r"\\.\NUL", "access": 0x40000000},
                {"id": "python_write_nul", "op": "write", "path": "NUL"}]},
            {"id": "subprocess_devnull", "kind": "run", "argv": [CMD, "/d", "/c", "echo devnull-ok"], "stdin": "devnull",
             "timeout": 20},
            {"id": "subprocess_pipe", "kind": "run", "argv": [CMD, "/d", "/c", "echo pipe-ok"], "stdin": "pipe",
             "timeout": 20},
            {"id": "G4", "kind": "parbuild", "ws": str(g4)},
            {"id": "Q1", "kind": "pipe_steps"},
            *tool_tasks(tag),
            {"id": "nobj_create", "kind": "nobj_create", "objects": nobjs, "keep": False}]


def hole_tasks(tag, host_objs, pids):
    w = {"ws_A": WS, "ws_cap": RT / "ws-cap", "ws_grp": RT / "ws-grp", "ws_acct": RT / "ws-acct",
         "everyone_write": RT / "targets" / "everyone-write", "logon_write": RT / "targets" / "logon-write",
         "user_only": RT / "targets" / "user-only"}
    ops = [{"id": f"{k}_write", "op": "write", "path": str(d / f"w-{tag}.txt")} for k, d in w.items()]
    ops.append({"id": "user_only_read", "op": "read", "path": str(RT / "targets" / "user-only" / "f.txt")})
    keys = [{"id": f"hkcu_{n}", "root": "HKU", "path": rf"{S['user_sid']}\{HKCU_BASE}\{n}", "access": 0x2}
            for n in ("everyone-write", "logon-write", "user-only")]
    return [{"id": "holes_fs", "kind": "fs", "ops": ops},
            {"id": "holes_reg", "kind": "reg", "keys": keys},
            {"id": "host_local_objects", "kind": "nobj_open", "objects": host_objs, "effects": True, "marker": f"S-{tag}"},
            {"id": "proc_user", "kind": "proc_open", "pids": pids},
            {"id": "proc_launcher", "kind": "proc_open_ancestors", "names": ["python.exe"]}]


# ---------------------------------------------------------------- trials
def trial(account, mode, t, ctx, dacl="codex", phases=("main", "window", "squat")):
    tag = f"{mode}-{t}-{uuid.uuid4().hex[:6]}"
    rec = {"trial": t, "tag": tag, "account": account, "mode": mode, "dacl": dacl}
    if "main" in phases:
        hobjs, held, rec["host_objects"] = host_objects(tag)
        launches = [launch(tag, "ps_basic", ps_argv(PS_BASIC)), launch(tag, "ps_null", ps_argv(PS_NULL)),
                    launch(tag, "cmd_basic", [CMD, "/d", "/c", "ver & cd & dir /b /a & (echo cmd-basic> cmd-basic.txt)"
                                              " && type cmd-basic.txt && del cmd-basic.txt && echo write=ok"]),
                    launch(tag, "cmd_null", [CMD, "/d", "/c", str(WS / "null-test.cmd")]),
                    child_launch(tag, "child", compat_tasks(tag) + hole_tasks(tag, hobjs, ctx["pids"]), timeout=480)]
        rec["main"] = run_phase(account, mode, launches, tag, dacl)
        rec["host_check"] = host_check(held, f"S-{tag}")
    if "window" in phases:
        title = f"iso-rt-win-{tag}"
        launches = [launch(tag, "ps_window", ps_argv(PS_WINDOW), 40),
                    child_launch(tag, "child_window", [{"id": "window", "kind": "window", "seconds": 6, "title": title}], 40)]
        rec["window"] = run_phase(account, mode, launches, tag + "-w", dacl, during=window_poller(title))
    if "squat" in phases:
        objs = [{"type": "event", "name": f"Local\\iso-rt-s-{tag}-event", "signaled": True},
                {"type": "section", "name": f"Local\\iso-rt-s-{tag}-section", "marker": f"SQ-{tag}"}]
        cp, hb, stop = OUT / f"{tag}-sq.cp", OUT / f"{tag}-sq.hb", OUT / f"{tag}-sq.stop"
        launches = [child_launch(tag, "child_squat", [
            {"id": "create", "kind": "nobj_create", "objects": objs},
            {"id": "cp", "kind": "checkpoint", "path": str(cp)},
            {"id": "hold", "kind": "hold", "seconds": 60, "heartbeat": str(hb), "stop": str(stop)}], 120)]
        plain = [{"type": o["type"], "name": o["name"]} for o in objs]
        rec["squat"] = run_phase(account, mode, launches, tag + "-s", dacl, during=squat_host(plain, cp, stop))
    return rec


def host_control(t):
    """The same shells and tools run directly by the user (no sandbox), same environment and folder."""
    tag = f"host-{t}-{uuid.uuid4().hex[:6]}"
    out = {"trial": t, "tag": tag}
    for lid, argv in (("ps_basic", ps_argv(PS_BASIC)), ("ps_null", ps_argv(PS_NULL)),
                      ("cmd_null", [CMD, "/d", "/c", str(WS / "null-test.cmd")])):
        p = subprocess.run(argv, cwd=WS, env=ENV, input=b"", capture_output=True, timeout=90)
        out[lid] = {"exit": p.returncode, "result": kv(p.stdout.decode("utf-8", "replace"))}
    sp = SPECS / f"{tag}-child.json"
    sp.write_text(json.dumps({"tasks": compat_tasks(tag)}), encoding="utf-8")
    p = subprocess.run([str(PY), "-I", "-B", str(CHILD), str(sp)], cwd=WS, env=ENV, input=b"", capture_output=True,
                       timeout=480)
    out["child"] = {"exit": p.returncode, "result": parse_isojson(p.stdout.decode("utf-8", "replace"))}
    return out


# ---------------------------------------------------------------- window object ACEs (fix-desktop)
def window_objects():
    import win32api
    import win32service
    return {"winsta": win32service.GetProcessWindowStation(),
            "desktop": win32service.GetThreadDesktop(win32api.GetCurrentThreadId())}


def window_sddl():
    import win32security
    out = {}
    for n, h in window_objects().items():
        sd = win32security.GetSecurityInfo(h, win32security.SE_WINDOW_OBJECT, win32security.DACL_SECURITY_INFORMATION)
        out[n] = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            sd, win32security.SDDL_REVISION_1, win32security.DACL_SECURITY_INFORMATION)
    return out


def window_set(sddls):
    import win32security
    for n, h in window_objects().items():
        sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddls[n], win32security.SDDL_REVISION_1)
        win32security.SetSecurityInfo(h, win32security.SE_WINDOW_OBJECT, win32security.DACL_SECURITY_INFORMATION,
                                      None, None, sd.GetSecurityDescriptorDacl(), None)


def window_add(account_sid):
    """Account ACEs with the masks the user's logon SID has: WinSta0 0xf037f, Default 0xf01ff."""
    orig = window_sddl()
    new = {"winsta": orig["winsta"] + f"(A;;0xf037f;;;{account_sid})",
           "desktop": orig["desktop"] + f"(A;;0xf01ff;;;{account_sid})"}
    window_set(new)
    return orig


# ---------------------------------------------------------------- Local\ directory ACE (fix-all-local)
MSYS_DIR = "\\BaseNamedObjects\\msys-2.0S5-1888ae32e00d56aa"  # from the Git Bash error of this installation


def local_dir(access, path=None):
    sess = C.DW()
    C.k32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sess))
    path = path or rf"\Sessions\{sess.value}\BaseNamedObjects"

    class US(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", ctypes.c_void_p)]

    class OA(ctypes.Structure):
        _fields_ = [("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE), ("ObjectName", ctypes.POINTER(US)),
                    ("Attributes", wintypes.ULONG), ("SecurityDescriptor", ctypes.c_void_p),
                    ("SecurityQualityOfService", ctypes.c_void_p)]
    b = ctypes.create_unicode_buffer(path)
    us = US(len(path) * 2, len(path) * 2 + 2, ctypes.cast(b, ctypes.c_void_p))
    oa = OA(ctypes.sizeof(OA), None, ctypes.pointer(us), 0x40, None, None)
    h = C.HANDLE()
    st = C.ntdll.NtOpenDirectoryObject(ctypes.byref(h), access, ctypes.byref(oa))
    if st:
        raise OSError(f"NtOpenDirectoryObject {path}: 0x{st & 0xffffffff:08x}")
    return h


def local_sddl(path=None):
    import win32security
    h = local_dir(0x20000, path)
    try:
        sd = win32security.GetSecurityInfo(h.value, win32security.SE_KERNEL_OBJECT, win32security.DACL_SECURITY_INFORMATION)
        return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            sd, win32security.SDDL_REVISION_1, win32security.DACL_SECURITY_INFORMATION)
    finally:
        C.ntdll.NtClose(h)


def local_set(sddl, path=None):
    import win32security
    sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, win32security.SDDL_REVISION_1)
    h = local_dir(0x20000 | 0x40000, path)
    try:
        win32security.SetSecurityInfo(h.value, win32security.SE_KERNEL_OBJECT, win32security.DACL_SECURITY_INFORMATION,
                                      None, None, sd.GetSecurityDescriptorDacl(), None)
    finally:
        C.ntdll.NtClose(h)


def local_add(account_sid):
    """The account gets what the user's logon SID has on the directory itself: query, traverse, create object,
    create subdirectory, read control (no inheritable ACE)."""
    orig = local_sddl()
    local_set(orig + f"(A;;CCDCLCSWRC;;;{account_sid})")
    return orig


# ---------------------------------------------------------------- groups
# name: (account, default DACL variant, desktop ACEs, Local\ ACE)
FIXES = {"fix-desktop": ("iso-rt-sbx1", "codex", True, False), "fix-dacl": ("iso-rt-sbx1", "account", False, False),
         "fix-desktop-dacl": ("iso-rt-sbx1", "account", True, False),
         "fix-devices": ("iso-rt-sbx2", "codex", False, False), "fix-all": ("iso-rt-sbx2", "account", True, False),
         "fix-all-local": ("iso-rt-sbx2", "account", True, True),
         # same as fix-all-local, run after probe-rt-reduced-accounts.py bno-add (account ACE on \BaseNamedObjects)
         "fix-all-local-bno": ("iso-rt-sbx2", "account", True, True),
         "fix-all-local-bno-msys": ("iso-rt-sbx2", "account", True, True)}
SELF_CHECK = False



def explorer_pid():
    procs = wts_processes()
    return next((pid for pid, (sid, name) in procs.items() if name.lower() == "explorer.exe" and sid == S["user_sid"]), None)


def run_group(g, ctx):
    if g == "precheck":
        return [trial("iso-rt-sbx1", m, 0, ctx) for m in ("base", "reduced")]
    if g == "main":
        out = {"base": [], "reduced": [], "host": []}
        for t in range(1, TRIALS + 1):
            for m in ("base", "reduced"):
                out[m].append(trial("iso-rt-sbx1", m, t, ctx))
                save("main-partial.json", out)
                print(f"main {m} trial {t} done", flush=True)
            out["host"].append(host_control(t))
        return out
    if g in FIXES:
        account, dacl, desk, loc = FIXES[g]
        sid = S["account_sids"][account]
        out = {"account": account, "dacl": dacl, "desktop_aces": desk, "local_ace": loc, "trials": []}
        orig_w = window_add(sid) if desk else None
        orig_l = orig_m = None
        try:
            orig_l = local_add(sid) if loc else None
            if g.endswith("-msys"):
                orig_m = local_sddl(MSYS_DIR)
                local_set(orig_m + f"(A;;CCDCLCSWRC;;;{sid})", MSYS_DIR)
                out["msys_dir_before"] = orig_m
            for t in range(1, TRIALS + 1):
                out["trials"].append(trial(account, "reduced", t, ctx, dacl))
                print(f"{g} trial {t} done", flush=True)
        finally:
            if orig_w:
                window_set(orig_w)
                out["window_objects_restored"] = window_sddl() == orig_w
            if orig_l:
                local_set(orig_l)
                out["local_dir_restored"] = local_sddl() == orig_l
            if orig_m:
                local_set(orig_m, MSYS_DIR)
                out["msys_dir_restored"] = local_sddl(MSYS_DIR) == orig_m
        return out
    if g.startswith("state-"):
        return state()
    raise SystemExit(f"unknown group {g}")


def state():
    import winreg
    st = {"accounts": {n: lookup_sid(n) for n in ("iso-rt-sbx1", "iso-rt-sbx2")}, "group": lookup_sid("iso-rt-sbx-users"),
          "user_dirs": sorted(p.name for p in Path(r"C:\Users").iterdir() if p.name.lower().startswith("iso-rt")),
          "root_exists": ROOT.exists(), "window_objects": window_sddl(), "local_dir": local_sddl()}
    import win32file
    import win32security
    h = win32file.CreateFile(r"\\.\NUL", 0x20000, 3, None, 3, 0, None)
    sd = win32security.GetSecurityInfo(h.handle, 6, win32security.DACL_SECURITY_INFORMATION)
    h.Close()
    st["nul"] = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
        sd, win32security.SDDL_REVISION_1, win32security.DACL_SECURITY_INFORMATION)
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, HKCU_BASE).Close()
        st["hkcu_keys"] = True
    except OSError:
        st["hkcu_keys"] = False
    if ROOT.exists():
        st["rt_dacls"] = {str(p): dacl_aces(p) for p in [RT, *RT.iterdir(), *(RT / "targets").iterdir()]}
    procs = wts_processes()
    sandbox = {s for s in st["accounts"].values() if s}
    st["sandbox_processes"] = sum(1 for sid, _ in procs.values() if sid in sandbox)
    return st


def main():
    global S, ENV
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("run in the normal (non-elevated) session")
    groups = sys.argv[1:]
    S = load("setup.json")
    if not all(g.startswith("state-") for g in groups):
        import win32api
        import win32con
        import win32profile
        import win32security
        tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY | win32con.TOKEN_DUPLICATE)
        ENV = dict(win32profile.CreateEnvironmentBlock(tok, False))
        ENV["TEMP"] = ENV["TMP"] = str(RT / "temp")
        user, logon = token_sids()
        if user != S["user_sid"] or logon != S["logon_sid"]:
            raise SystemExit("user or logon SID differs from setup.json (new logon session?)")
    for g in groups:
        ctx = {}
        test = None
        if not g.startswith("state-"):
            hb = OUT / f"testproc-{g}.hb"
            test = start_test_process(3600, f"iso-rt-marker-{uuid.uuid4().hex[:8]}", hb)
            time.sleep(1)
            ctx["pids"] = [test.pid, explorer_pid()]
        print(f"{g} ...", flush=True)
        t0 = time.monotonic()
        try:
            res = run_group(g, ctx)
        finally:
            if test:
                test.kill()
        save(f"{g}.json", {"group": g, "trials": TRIALS, "seconds": round(time.monotonic() - t0, 1),
                           "env_keys": sorted(ENV) if ENV else None, "result": res})
        print(f"{g} done in {round(time.monotonic() - t0, 1)}s", flush=True)


if __name__ == "__main__":
    main()
