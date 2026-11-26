r"""Installed tools and Git Bash start order under the Codex elevated structure (runs/2026-11-26-04.md).

Requested by another session that keeps the Codex elevated restricting SID list. Uses the test launcher
and helpers of probe-rt-reduced-campaign.py with mode "base" (capability SID, account, logon SID, Everyone;
WRITE_RESTRICTED; Codex default DACL) and the measurement account iso-rt-sbx1. Run with ISO_DATE=2026-11-26-rt2
and ISO_ROOT=%USERPROFILE%\\agent-isolation-rt2 in the normal (non-elevated) session.

Usage: python probe-rt2-campaign.py tools | gitbash | pwsh
  tools    five trials: the user's own Python install under the profile (as it is, no ACE added), the
           WindowsApps python.exe alias (with an argument, so no Store window opens), npm --version,
           npm run of a script that starts a child with stdio pipes (with and without a writable npm cache),
           python -m unittest (user Python and the test runtime). Each trial also runs on the host (control).
  gitbash  five trials of each start order. Git Bash instances of one installation share one object directory
           \\BaseNamedObjects\\msys-2.0S5-<install hash>; Git Bash terminals of the user are always running on
           this PC, so the installed Git covers only order A. Orders B-D use a copy of Git's MSYS2 files under
           tools\\gitcopy, whose directory no other process uses.
             A_real  user Git Bash already running (installed Git) -> sandbox Git Bash
             A_copy  user Git Bash (copy) started and held -> sandbox Git Bash (copy)
             B       sandbox Git Bash (copy) started and held -> user Git Bash (copy)
             C       two sandbox Git Bash (copy) at the same time, different workspaces and capability SIDs
             D       no Git Bash of the copy running -> sandbox Git Bash (copy)
           While a phase runs, the host reads the owner and DACL of the MSYS2 directory and of the objects in
           it (READ_CONTROL only).
  pwsh     PowerShell 5.1 start location and relative paths (requested after AppContainer needed list rights on
           admin-owned parents). Workspace rt\pwsh\p1\p2\ws (capability SID + group modify) under two test
           parents p1, p2 and the test root, none of which gives the sandbox any right; an allowed folder
           outside it, rt\pwsh\q\allowed (group read). Two conditions, five trials each:
             none          no list ACE on any parent
             user-parents  group list ACE (0x1200a1, not inherited) on the user-owned test parents: the test
                           root, rt, rt\pwsh, p1, p2, q. The real profile folder is not changed.
           PowerShell, cmd and Python start in the workspace; the in-sandbox program also lists each parent from
           C:\ down to the workspace to show which ones the account can list.
"""
import os
import sys
import json
import time
import uuid
import ctypes
import threading
import subprocess
import importlib.util
from ctypes import wintypes
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26-rt2")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import ROOT, TOOLS, PY, CHILD, save, load, parse_isojson, token_sids  # noqa: E402

_r = importlib.util.spec_from_file_location("rtcamp", Path(__file__).with_name("probe-rt-reduced-campaign.py"))
R = importlib.util.module_from_spec(_r)
_r.loader.exec_module(R)
C = R.C

TRIALS = int(os.environ.get("ISO_TRIALS", "5"))
ACCOUNT = "iso-rt-sbx1"
LA = Path(os.environ["LOCALAPPDATA"])
USERPY = LA / "Programs" / "Python" / "Python312" / "python.exe"
ALIAS = LA / "Microsoft" / "WindowsApps" / "python.exe"
NPM = r"C:\Program Files\nodejs\npm.cmd"
BASH_REAL = r"C:\Program Files\Git\usr\bin\bash.exe"
BASH_REAL_LAUNCHER = r"C:\Program Files\Git\bin\bash.exe"
COPY = TOOLS / "gitcopy"
BASH_COPY, BASH_COPY_LAUNCHER = COPY / "usr" / "bin" / "bash.exe", COPY / "bin" / "bash.exe"
REAL_NS = "msys-2.0S5-1888ae32e00d56aa"  # the installed Git's directory on this PC (2026-11-26-03)
S = ENV = None
LABELS = {}


# ---------------------------------------------------------------- launcher phases (base mode)
def run_phase(launches, tag, cap, cwd, during=None, timeout=600):
    spec = {"tag": tag, "mode": "base", "dacl": "codex", "cap_sid": cap, "env": ENV, "cwd": str(cwd),
            "launches": launches, "result": str(R.OUT / f"{tag}-launcher.json"), "extra_sids": []}
    sp = R.SPECS / f"{tag}-launcher.json"
    sp.write_text(json.dumps(spec), encoding="utf-8")
    t0 = time.monotonic()
    pi, e = R.logon_start(ACCOUNT, sp)
    if e:
        return {"logon_error": e}
    extra = during(pi.hProcess) if during else None
    w = R.k32.WaitForSingleObject(pi.hProcess, timeout * 1000)
    if w == 0x102:
        R.k32.TerminateProcess(pi.hProcess, 1)
    R.k32.CloseHandle(pi.hProcess)
    rec = {"seconds": round(time.monotonic() - t0, 2), "during": extra}
    try:
        res = json.loads(Path(spec["result"]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as ex:
        rec["launcher"] = f"no result: {ex}"
        return rec
    for L in launches:
        r = res["launches"].get(L["id"])
        if isinstance(r, dict):
            r["result"] = parse_isojson(R.read_text(L["stdout"], 10**7))
            r["stderr_tail"] = R.read_text(L["stderr"])[-400:]
    rec["launcher"] = res
    return rec


def child(tag, lid, tasks, timeout=300):
    return R.child_launch(tag, lid, tasks, timeout)


def run(tid, argv, cwd, timeout=60, env=None):
    t = {"id": tid, "kind": "run", "argv": [str(a) for a in argv], "cwd": str(cwd), "timeout": timeout, "stdin": "pipe"}
    if env:
        t["env"] = env
    return t


def host_run(tasks):
    """The same run tasks as the user, directly."""
    out = {}
    for t in tasks:
        env = {**ENV, **t.get("env", {})}
        t0 = time.monotonic()
        try:
            p = subprocess.run(t["argv"], cwd=t["cwd"], env=env, input=b"", capture_output=True, timeout=t["timeout"])
            out[t["id"]] = {"exit": p.returncode, "seconds": round(time.monotonic() - t0, 2),
                            "stdout": p.stdout.decode("utf-8", "replace")[-600:],
                            "stderr": p.stderr.decode("utf-8", "replace")[-600:]}
        except subprocess.TimeoutExpired:
            out[t["id"]] = {"exit": "timeout"}
        except OSError as e:
            out[t["id"]] = {"exit": f"oserror:{getattr(e, 'winerror', None) or e.errno}"}
    return out


# ---------------------------------------------------------------- tools
def tool_tasks():
    ws = R.WS
    tests = ws / "tests"
    return [run("userpy_version", [USERPY, "-c", "import sys, ssl, sqlite3; print('userpy-ok', sys.version.split()[0])"], ws),
            run("userpy_unittest", [USERPY, "-m", "unittest", "discover", "-s", tests, "-v"], ws),
            run("pyrt_unittest", [PY, "-m", "unittest", "discover", "-s", tests, "-v"], ws),
            run("alias_python", [ALIAS, "--version"], ws),
            run("npm_version", [NPM, "--version"], ws),
            run("npm_run", [NPM, "run", "spawnpipe"], ws),
            run("npm_run_cache", [NPM, "run", "spawnpipe"], ws, env={"npm_config_cache": str(R.RT / "temp" / "npm-cache")})]


def g_tools():
    out = []
    for t in range(1, TRIALS + 1):
        tag = f"tools-{t}-{uuid.uuid4().hex[:6]}"
        rec = {"trial": t, "tag": tag}
        rec["sandbox"] = run_phase([child(tag, "child", [{"id": "token", "kind": "token"}, *tool_tasks()], 600)],
                                   tag, S["cap_sid"], R.WS)
        rec["host"] = host_run(tool_tasks())
        out.append(rec)
        print(f"tools trial {t} done", flush=True)
    return out


# ---------------------------------------------------------------- MSYS2 directory (READ_CONTROL only)
ntdll = C.ntdll


class US(ctypes.Structure):
    _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", ctypes.c_void_p)]


class OA(ctypes.Structure):
    _fields_ = [("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE), ("ObjectName", ctypes.POINTER(US)),
                ("Attributes", wintypes.ULONG), ("SecurityDescriptor", ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p)]


def _oa(name, root=None):
    b = ctypes.create_unicode_buffer(name)
    us = US(len(name) * 2, len(name) * 2 + 2, ctypes.cast(b, ctypes.c_void_p))
    return OA(ctypes.sizeof(OA), root, ctypes.pointer(us), 0x40, None, None), b, us


def _open(fn, name, access, root=None):
    oa, b, us = _oa(name, root)
    h = wintypes.HANDLE()
    st = getattr(ntdll, fn)(ctypes.byref(h), access, ctypes.byref(oa))
    return (h, None) if st == 0 else (None, f"0x{st & 0xffffffff:08x}")


def _sddl(h):
    import win32security
    info = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    try:
        sd = win32security.GetSecurityInfo(h.value, win32security.SE_KERNEL_OBJECT, info)
        s = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, info)
    except Exception as e:
        return f"error:{e}"
    for sid, name in LABELS.items():
        s = s.replace(sid, name)
    return s


def _list(h):
    names, ctx = [], wintypes.ULONG(0)
    buf = ctypes.create_string_buffer(1 << 16)
    while True:
        ret = wintypes.ULONG()
        st = ntdll.NtQueryDirectoryObject(h, buf, len(buf), False, False, ctypes.byref(ctx), ctypes.byref(ret))
        if st not in (0, 0x105):
            break
        off = 0
        while True:
            ln = ctypes.c_ushort.from_buffer(buf, off).value
            if ln == 0:
                break
            name = ctypes.wstring_at(ctypes.c_void_p.from_buffer(buf, off + 8).value, ln // 2)
            tl = ctypes.c_ushort.from_buffer(buf, off + 16).value
            typ = ctypes.wstring_at(ctypes.c_void_p.from_buffer(buf, off + 24).value, tl // 2)
            names.append((name, typ))
            off += 32
        if st == 0:
            break
    return names


OPENERS = {"Section": "NtOpenSection", "Event": "NtOpenEvent", "Mutant": "NtOpenMutant", "Semaphore": "NtOpenSemaphore",
           "Directory": "NtOpenDirectoryObject"}


def msys_dirs():
    h, e = _open("NtOpenDirectoryObject", "\\BaseNamedObjects", 0x1)
    if not h:
        return []
    try:
        return sorted(n for n, t in _list(h) if n.startswith("msys-") and t == "Directory")
    finally:
        ntdll.NtClose(h)


def msys_snapshot(ns):
    h, e = _open("NtOpenDirectoryObject", f"\\BaseNamedObjects\\{ns}", 0x20000 | 0x1)
    if not h:
        return {"exists": False, "error": e}
    try:
        snap = {"exists": True, "dir": _sddl(h), "objects": {}}
        for name, typ in _list(h):
            label = name
            for sid, lab in LABELS.items():
                label = label.replace(sid, f"<{lab}>")
            fn = OPENERS.get(typ)
            if not fn:
                snap["objects"][label] = {"type": typ}
                continue
            oh, oe = _open(fn, name, 0x20000, root=h)
            snap["objects"][label] = {"type": typ, "sd": _sddl(oh) if oh else f"open:{oe}"}
            if oh:
                ntdll.NtClose(oh)
        return snap
    finally:
        ntdll.NtClose(h)


def copy_ns(before):
    new = [n for n in msys_dirs() if n != REAL_NS and n not in before]
    return new[0] if new else None


def poller(select, limit=120):
    """Snapshots of the MSYS2 directory while a launcher phase runs: first one seen and the one with most objects."""
    def during(hproc):
        first = most = None
        t0 = time.time()
        while time.time() - t0 < limit:
            ns = select()
            if ns:
                snap = msys_snapshot(ns)
                if snap.get("exists"):
                    snap["ns"] = ns
                    first = first or snap
                    if most is None or len(snap["objects"]) > len(most["objects"]):
                        most = snap
            if R.k32.WaitForSingleObject(hproc, 0) == 0:
                break
            time.sleep(0.2)
        return {"first": first, "most_objects": most}
    return during


def wait_absent(ns_known, seconds=30):
    t0 = time.time()
    while time.time() - t0 < seconds:
        if not [n for n in msys_dirs() if n != REAL_NS]:
            return True
        time.sleep(0.5)
    return False


# ---------------------------------------------------------------- Git Bash orders
def t5(bash, launcher, cwd, prefix=""):
    b = [bash, "--noprofile", "--norc", "-c"]
    cmds = (("bash_echo", "echo bash-ok"), ("bash_pipe", "echo pipe-ok | cat"), ("bash_subst", 'x=$(echo subst-ok); echo "$x"'),
            ("bash_bg", "sleep 1 & wait $!; echo bg-ok:$?"))
    tasks = [run(prefix + n, b + ["PATH=/usr/bin:$PATH; " + c], cwd, 30) for n, c in cmds]
    if launcher:  # Git's bin\bash.exe needs the whole Git folder ("Top-level not found" in the copy): installed Git only
        tasks.append(run(prefix + "bash_launcher", [launcher, "--noprofile", "--norc", "-c", "echo launcher-ok"], cwd, 30))
    return tasks


def hold(bash, cwd, secs):
    return run("bash_hold", [bash, "--noprofile", "--norc", "-c", f"PATH=/usr/bin:$PATH; sleep {secs}; echo hold-ok"], cwd, secs + 30)


def case_a_real(t, tag):
    rec = {"real_dir_before": msys_snapshot(REAL_NS)}
    rec["sandbox"] = run_phase([child(tag, "child", t5(BASH_REAL, BASH_REAL_LAUNCHER, R.WS), 300)], tag, S["cap_sid"], R.WS,
                               during=poller(lambda: REAL_NS))
    return rec


def case_a_copy(t, tag):
    rec = {"absent_before": wait_absent(None)}
    before = set(msys_dirs())
    user = subprocess.Popen([str(BASH_COPY), "--noprofile", "--norc", "-c", "PATH=/usr/bin:$PATH; sleep 40; echo hold-ok"],
                            env=ENV, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ns = None
    for _ in range(50):
        ns = copy_ns(before)
        if ns:
            break
        time.sleep(0.2)
    rec["ns"], rec["dir_after_user_start"] = ns, msys_snapshot(ns) if ns else None
    rec["sandbox"] = run_phase([child(tag, "child", t5(BASH_COPY, None, R.WS), 300)], tag, S["cap_sid"], R.WS,
                               during=poller(lambda: ns))
    user.kill()
    user.communicate()
    return rec


def case_b(t, tag):
    rec = {"absent_before": wait_absent(None)}
    before = set(msys_dirs())

    def during(hproc):
        ns = None
        t0 = time.time()
        while time.time() - t0 < 30 and not ns:
            ns = copy_ns(before)
            if not ns:
                time.sleep(0.2)
        out = {"ns": ns, "dir_after_sandbox_start": msys_snapshot(ns) if ns else None}
        out["user_bash"] = host_run(t5(BASH_COPY, None, R.WS))
        out["dir_after_user_run"] = msys_snapshot(ns) if ns else None
        return out
    rec["sandbox"] = run_phase([child(tag, "child", [hold(BASH_COPY, R.WS, 20)], 120)], tag, S["cap_sid"], R.WS, during=during)
    return rec


def case_c(t, tag):
    rec = {"absent_before": wait_absent(None)}
    before = set(msys_dirs())
    results = {}
    ws_b = R.RT / "ws-B"

    def go(key, cap, cwd, during):
        tasks = t5(BASH_COPY, None, cwd) + [hold(BASH_COPY, cwd, 6)]
        results[key] = run_phase([child(f"{tag}-{key}", "child", tasks, 300)], f"{tag}-{key}", cap, cwd, during=during)
    th = [threading.Thread(target=go, args=("A", S["cap_sid"], R.WS, poller(lambda: copy_ns(before)))),
          threading.Thread(target=go, args=("B", S["cap_sid_b"], ws_b, None))]
    for x in th:
        x.start()
    for x in th:
        x.join()
    rec.update(results)
    return rec


def case_d(t, tag):
    rec = {"absent_before": wait_absent(None)}
    before = set(msys_dirs())
    tasks = t5(BASH_COPY, None, R.WS) + [hold(BASH_COPY, R.WS, 4)]
    rec["sandbox"] = run_phase([child(tag, "child", tasks, 300)], tag, S["cap_sid"], R.WS, during=poller(lambda: copy_ns(before)))
    return rec


CASES = {"A_real": case_a_real, "A_copy": case_a_copy, "B": case_b, "C": case_c, "D": case_d}


def g_gitbash():
    out = {k: [] for k in CASES}
    for t in range(1, TRIALS + 1):
        for k, fn in CASES.items():
            tag = f"gb-{k}-{t}-{uuid.uuid4().hex[:6]}"
            out[k].append({"trial": t, "tag": tag, **fn(t, tag)})
            save("gitbash-partial.json", out)
            print(f"gitbash {k} trial {t} done", flush=True)
    return out


# ---------------------------------------------------------------- PowerShell start location and relative paths
LIST_ACE = 0x1200A1  # SYNCHRONIZE | READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | FILE_LIST_DIRECTORY


def pwsh_paths():
    base = R.RT / "pwsh"
    return base, base / "p1", base / "p1" / "p2", base / "p1" / "p2" / "ws", base / "q", base / "q" / "allowed"


def pwsh_prepare():
    """Host side, once: folders with protected DACLs (user, SYSTEM, Administrators) and the two grants."""
    _s = importlib.util.spec_from_file_location("rtsetup", Path(__file__).with_name("probe-rt-reduced-setup.py"))
    su = importlib.util.module_from_spec(_s)
    _s.loader.exec_module(su)
    from token_backends_common import protect
    base, p1, p2, ws, q, allowed = pwsh_paths()
    if not base.exists():
        for d in (base, p1, p2, ws, q, allowed):
            d.mkdir()
        for d in (base, p1, p2, ws, q, allowed):
            protect(d, S["user_sid"])
        su.grant(ws, [(S["cap_sid"], su.MODIFY), (S["group_sid"], su.MODIFY)])
        su.grant(allowed, [(S["group_sid"], su.READ_EXEC)])
        (ws / "a.txt").write_text("a-original\n")
        (allowed / "c.txt").write_text("allowed-original\n")
        (ws / "cmdtest.cmd").write_text("\r\n".join([
            "@echo off", "echo cwd=%CD%", "(dir /b >nul 2>&1) && echo dir=ok || echo dir=fail",
            "(type a.txt >nul 2>&1) && echo type=ok || echo type=fail",
            f'cd /d "{allowed}" 2>nul && echo cd_allowed=ok || echo cd_allowed=fail', "echo cwd_after=%CD%",
            "(dir /b >nul 2>&1) && echo dir_after=ok || echo dir_after=fail", "echo done=ok", ""]), encoding="ascii")
    import win32security
    owners = {}
    for d in parents_of(ws):
        sd = win32security.GetNamedSecurityInfo(str(d), win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION)
        sid = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
        owners[str(d).replace(str(Path(os.environ["USERPROFILE"])), "%USERPROFILE%")] = (
            LABELS.get(sid) or {"S-1-5-18": "SYSTEM", "S-1-5-32-544": "Administrators"}.get(sid)
            or ("TrustedInstaller" if sid.startswith("S-1-5-80-956008885") else sid))
    return {"owners": owners,
            "dacl": {str(d): [{"sid": LABELS.get(a["sid"], a["sid"]), "mask": a["mask"], "inherited": bool(a["flags"] & 0x10)}
                              for a in R.dacl_aces(d)] for d in pwsh_paths()}}


def parents_of(ws):
    out, d = [], ws
    while True:
        out.append(d)
        if d.parent == d:
            break
        d = d.parent
    return list(reversed(out))


def list_aces(add):
    """Not-inherited group list ACEs on the user-owned test parents (the real profile folder is left alone)."""
    import win32security
    base, p1, p2, ws, q, allowed = pwsh_paths()
    targets = [ROOT, R.RT, base, p1, p2, q]
    grp = win32security.ConvertStringSidToSid(S["group_sid"])
    info = win32security.DACL_SECURITY_INFORMATION
    for d in targets:
        sd = win32security.GetNamedSecurityInfo(str(d), win32security.SE_FILE_OBJECT, info)
        protected = bool(sd.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED)
        old = sd.GetSecurityDescriptorDacl()
        new = win32security.ACL()
        for i in range(old.GetAceCount()):
            (atype, aflags), mask, sid = old.GetAce(i)
            if aflags & 0x10:
                continue
            if sid == grp and mask & 0xffffffff == LIST_ACE and aflags == 0:
                continue  # our list ACE: dropped on removal, re-added below on add
            new.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, aflags, mask, sid)
        if add:
            new.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, 0, LIST_ACE, grp)
        flag = (win32security.PROTECTED_DACL_SECURITY_INFORMATION if protected
                else win32security.UNPROTECTED_DACL_SECURITY_INFORMATION)
        win32security.SetNamedSecurityInfo(str(d), win32security.SE_FILE_OBJECT, info | flag, None, None, new, None)
    return [str(d) for d in targets]


PS_PWSH = r"""
"pwd=" + $PWD.Path
try { "gci=" + (Get-ChildItem . -ErrorAction Stop | Measure-Object).Count } catch { "gci=err:" + $_.Exception.Message }
try { "gc=" + (Get-Content .\a.txt -ErrorAction Stop) } catch { "gc=err:" + $_.Exception.Message }
try { New-Item .\b-%TAG%.txt -ItemType File -ErrorAction Stop | Out-Null; "ni=ok" } catch { "ni=err:" + $_.Exception.Message }
try { "rp=" + (Resolve-Path ..\ws -ErrorAction Stop).Path } catch { "rp=err:" + $_.Exception.Message }
try { Push-Location '%ALLOWED%' -ErrorAction Stop; "pl_allowed=" + $PWD.Path; "pl_gc=" + (Get-Content .\c.txt -ErrorAction Stop); Pop-Location } catch { "pl_allowed=err:" + $_.Exception.Message }
try { Set-Location '%ALLOWED%' -ErrorAction Stop; "sl_allowed=" + $PWD.Path } catch { "sl_allowed=err:" + $_.Exception.Message }
try { Set-Location 'C:\Program Files' -ErrorAction Stop; "sl_pf=" + $PWD.Path } catch { "sl_pf=err:" + $_.Exception.Message }
"done=ok"
"""


def g_pwsh():
    prep = pwsh_prepare()
    base, p1, p2, ws, q, allowed = pwsh_paths()
    out = {"prepare": prep, "none": [], "user-parents": []}
    try:
        for cond in ("none", "user-parents"):
            out[f"targets_{cond}"] = list_aces(cond == "user-parents")
            for t in range(1, TRIALS + 1):
                tag = f"pw-{cond}-{t}-{uuid.uuid4().hex[:6]}"
                script = PS_PWSH.replace("%TAG%", tag).replace("%ALLOWED%", str(allowed))
                py = ("import os; print('cwd=' + os.getcwd()); print('read=' + open('a.txt').read().strip()); "
                      "open('p-%s.txt' % os.getpid(), 'w').write('x'); print('write=ok')")
                child_tasks = [{"id": "parents", "kind": "fs", "ops": [
                    {"id": str(d), "op": "list", "path": str(d)} for d in parents_of(ws)] + [
                    {"id": str(d) + " (allowed)", "op": "list", "path": str(d)} for d in (q, allowed)]},
                    run("py_rel", [PY, "-c", py], ws, 30)]
                launches = [R.launch(tag, "ps", R.ps_argv(script), 60),
                            R.launch(tag, "cmd", [R.CMD, "/d", "/c", str(ws / "cmdtest.cmd")], 30),
                            child(tag, "child", child_tasks, 120)]
                rec = run_phase(launches, tag, S["cap_sid"], ws)
                L1 = rec.get("launcher")
                if isinstance(L1, dict):
                    for lid in ("ps", "cmd"):
                        r = L1["launches"].get(lid)
                        if isinstance(r, dict):
                            r["result"] = R.kv(R.read_text(next(x["stdout"] for x in launches if x["id"] == lid), 10**6))
                out[cond].append({"trial": t, "tag": tag, **rec})
                print(f"pwsh {cond} trial {t} done", flush=True)
    finally:
        list_aces(False)
        out["aces_removed"] = True
    return out


def main():
    global S, ENV
    if ctypes.windll.shell32.IsUserAnAdmin():
        raise SystemExit("run in the normal (non-elevated) session")
    if not os.environ.get("ISO_ROOT"):
        raise SystemExit("set ISO_ROOT to the 2026-11-26-04 test root")
    import win32api
    import win32con
    import win32profile
    import win32security
    S = R.S = load("setup.json")
    tok = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY | win32con.TOKEN_DUPLICATE)
    ENV = dict(win32profile.CreateEnvironmentBlock(tok, False))
    ENV["TEMP"] = ENV["TMP"] = str(R.RT / "temp")
    R.ENV = ENV
    user, logon = token_sids()
    if user != S["user_sid"] or logon != S["logon_sid"]:
        raise SystemExit("user or logon SID differs from setup.json")
    LABELS.update({S["user_sid"]: "user", S["logon_sid"]: "user_logon", **{v: k for k, v in S["account_sids"].items()},
                   S["cap_sid"]: "cap_A", S["cap_sid_b"]: "cap_B"})
    for g in sys.argv[1:]:
        t0 = time.monotonic()
        res = {"tools": g_tools, "gitbash": g_gitbash, "pwsh": g_pwsh}[g]()
        save(f"{g}.json", {"group": g, "trials": TRIALS, "seconds": round(time.monotonic() - t0, 1), "result": res})
        print(f"{g} done in {round(time.monotonic() - t0, 1)}s", flush=True)


if __name__ == "__main__":
    main()
