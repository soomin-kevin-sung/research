"""Schannel HTTPS in the Codex elevated structure: profile load or restricting SIDs (runs/2026-11-26-05.md).

Requested by another session as a follow-up to 2026-11-26-04 section 4, where curl (schannel) and
Invoke-WebRequest failed (SEC_E_NO_CREDENTIALS) for the Codex online account and Python urllib worked.
Host side, run with the test venv Python. Data goes to local/2026-11-26-tls.

Usage: python probe-tls-profile.py prep | control | acl | run | state <label> | cleanup | summary
  prep     before the UAC step. Creates %USERPROFILE%\\agent-isolation-tls (not directly under C:\\):
             tools\\  test Python (copy of the venv base, stdlib only), child.py, launcher.py, tls_child.py;
                     Users read and run
             secrets\\tls.json   random password of the measurement account; user and SYSTEM only
             rt\\{ws, temp, out, specs}   user, SYSTEM, Administrators (acl adds the account)
           and a random capability SID in the Codex format.
  control  no UAC, current user. Restricted copies of the current user's token (VARIANTS). Per variant 5 trials of
             impersonation  AcquireCredentialsHandleW on this thread while it impersonates the token
             process        a child started with the token (CreateProcessAsUserW, the launcher's launch(),
                            WinSta0\\Default) that runs the sspi task, curl, Invoke-WebRequest, git ls-remote
                            (schannel) and Python urllib
  acl      after the account exists: account read and run on rt, modify on ws, temp, out.
  run      the measurement account through CreateProcessWithLogonW, as Codex starts its runner. Cells
             A   logon flags 0             commands with the logon token (CreateRestrictedToken copy, no change)
             B   logon flags 0             Codex token: DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED,
                                           capability SID, account, logon SID, Everyone; Codex default DACL
             C   LOGON_WITH_PROFILE        as A
             D   LOGON_WITH_PROFILE        as B
             A2, B2  logon flags 0 after the profile exists
           Order: A and B alternating (no profile yet), then D and C alternating (D1 is the first profile
           logon), then A2 and B2. 5 trials each. After every trial the host records the profile folder, the
           ProfileList entry and whether HKU still has the account's hive, and waits up to 120 s for it to unload.
  state    non-admin PC state: local accounts, measurement profile, loaded hives, process count, Codex
           accounts' last logon.
  cleanup  after the admin cleanup: deletes %USERPROFILE%\\agent-isolation-tls.
curl gets --ssl-revoke-best-effort: on the run day curl.exe on the host itself failed the revocation check for
example.com (CRYPT_E_NO_REVOCATION_CHECK); credential acquisition comes before that step.
The commands reach https://example.com/ and https://github.com/octocat/Hello-World.git only. The current user's
files, keys and accounts are not changed; the only registry writes are the test values the child writes into
the measurement account's own hive (tls_child.py hkcu).
"""
import os
import sys
import json
import time
import ctypes
import random
import shutil
import subprocess
import winreg
import importlib.util
from ctypes import wintypes
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26-tls")
os.environ.setdefault("ISO_ROOT", str(Path(os.environ["USERPROFILE"]) / "agent-isolation-tls"))
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, TOOLS, PYRT, PY, CHILD, LOCAL, token_sids, lookup_sid, icacls,  # noqa: E402
                                   protect, dacl_aces, save, load, parse_isojson, SID_EVERYONE)

import win32net  # noqa: E402

ACCOUNT = "iso-rt-tls1"
RT = ROOT / "rt"
WS, TEMP, OUT, SPECS = RT / "ws", RT / "temp", RT / "out", RT / "specs"
LAUNCHER, TLSCHILD = TOOLS / "launcher.py", TOOLS / "tls_child.py"
SECRETS = ROOT / "secrets" / "tls.json"
URL = "https://example.com/"
GIT_REPO = "https://github.com/octocat/Hello-World.git"
CURL = r"C:\Windows\System32\curl.exe"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
GIT = r"C:\Program Files\Git\cmd\git.exe"
IWR = ("$ProgressPreference='SilentlyContinue'; try { $r = Invoke-WebRequest -UseBasicParsing -Uri '" + URL +
       "' -TimeoutSec 25; 'status=' + $r.StatusCode } catch { $e = $_.Exception; 'error=' + $e.GetType().FullName + "
       "': ' + $e.Message; while ($e.InnerException) { $e = $e.InnerException; 'inner=' + $e.GetType().FullName + "
       "': ' + $e.Message }; exit 1 }")
URLLIB = ("import urllib.request as u; r = u.urlopen('" + URL + "', timeout=25); print('status=%d' % r.status)")
CELLS = {"A": (0, "none"), "B": (0, "base"), "C": (1, "none"), "D": (1, "base"), "A2": (0, "none"), "B2": (0, "base")}
TRIALS = int(os.environ.get("TLS_TRIALS", "5"))  # 1 for the smoke check before the real run
DMP, LUA, WR = 0x1, 0x4, 0x8


def tools_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def log(msg):
    LOCAL.mkdir(parents=True, exist_ok=True)
    with open(LOCAL / "run.log", "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    print(msg, flush=True)


# ---------------------------------------------------------------- prep, acl, cleanup
def prep():
    if ROOT.exists():
        sys.exit(f"{ROOT} already exists; refusing to overwrite")
    setup = importlib.util.spec_from_file_location("setup", Path(__file__).with_name("probe-rt-reduced-setup.py"))
    S = importlib.util.module_from_spec(setup)
    setup.loader.exec_module(S)
    user_sid, logon_sid = token_sids()
    rec = {"user_sid": user_sid, "logon_sid": logon_sid, "account": ACCOUNT,
           "cap_sid": "S-1-5-21-" + "-".join(str(random.SystemRandom().randrange(1, 2**32)) for _ in range(4))}
    ROOT.mkdir()
    protect(ROOT, user_sid)
    TOOLS.mkdir()
    src = Path(sys.base_prefix)
    PYRT.mkdir()
    for f in ("python.exe", "python3.dll", "python312.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        shutil.copy2(src / f, PYRT / f)
    shutil.copytree(src / "DLLs", PYRT / "DLLs")
    shutil.copytree(src / "Lib", PYRT / "Lib", ignore=shutil.ignore_patterns(
        "site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3", "__pycache__", "pydoc_data"))
    here = Path(__file__).parent
    shutil.copy2(here / "probe-token-backends-child.py", CHILD)
    shutil.copy2(here / "probe-rt-reduced-launcher.py", LAUNCHER)
    shutil.copy2(here / "probe-tls-profile-child.py", TLSCHILD)
    icacls(TOOLS, "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F",
           "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")
    (ROOT / "secrets").mkdir()
    icacls(ROOT / "secrets", "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
    SECRETS.write_text(json.dumps({ACCOUNT: S.password()}), encoding="utf-8")
    RT.mkdir()
    protect(RT, user_sid)
    for d in (WS, TEMP, OUT, SPECS):
        d.mkdir()
    rec["dacl_prep"] = {str(p): dacl_aces(p) for p in [ROOT, TOOLS, ROOT / "secrets", RT, *RT.iterdir()]}
    print(save("setup.json", rec))


def acl():
    setup = importlib.util.spec_from_file_location("setup", Path(__file__).with_name("probe-rt-reduced-setup.py"))
    S = importlib.util.module_from_spec(setup)
    setup.loader.exec_module(S)
    rec = load("setup.json")
    sid = lookup_sid(ACCOUNT)
    if not sid:
        sys.exit(f"{ACCOUNT} does not exist")
    S.grant(RT, [(sid, S.READ_EXEC)])
    for d in (WS, TEMP, OUT):
        S.grant(d, [(sid, S.MODIFY)])
    rec["account_sid"] = sid
    rec["dacl_acl"] = {str(p): dacl_aces(p) for p in [ROOT, RT, *RT.iterdir()]}
    print(save("setup.json", rec))


def cleanup():
    if lookup_sid(ACCOUNT):
        sys.exit(f"{ACCOUNT} still exists; run the admin cleanup first")
    shutil.rmtree(ROOT)
    print("removed", ROOT, "exists:", ROOT.exists())


# ---------------------------------------------------------------- state
def hku_names():
    out, i = [], 0
    while True:
        try:
            out.append(winreg.EnumKey(winreg.HKEY_USERS, i))
        except OSError:
            return out
        i += 1


def profile_state(sid):
    entry = None
    if sid:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}") as k:
                entry = winreg.QueryValueEx(k, "ProfileImagePath")[0]
        except OSError as e:
            entry = None if e.winerror == 2 else f"error:{e.winerror}"
    return {"user_dirs": sorted(p.name for p in Path(r"C:\Users").iterdir() if p.name.lower().startswith("iso-rt")),
            "profilelist": entry,
            "hku_loaded": [n for n in hku_names() if sid and n.upper().startswith(sid.upper())]}


def state(label):
    user_sid, _ = token_sids()
    sid = lookup_sid(ACCOUNT)
    names, resume = [], 0
    while True:
        data, _, resume = win32net.NetUserEnum(None, 0, 0, resume)
        names += [d["name"] for d in data]
        if not resume:
            break
    st = {"label": label, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "local_accounts": sorted(names),
          "measurement_account_sid": sid, "profile": profile_state(sid), "root_exists": ROOT.exists()}
    cat = {}
    for n in hku_names():
        base = n.removesuffix("_Classes")
        c = ("user" if base == user_sid else "measurement" if sid and base == sid else
             base if base in (".DEFAULT", "S-1-5-18", "S-1-5-19", "S-1-5-20") else "other")
        cat[c] = cat.get(c, 0) + 1
    st["hku_by_kind"] = cat
    for n in ("CodexSandboxOffline", "CodexSandboxOnline"):
        try:
            st.setdefault("codex_last_logon", {})[n] = win32net.NetUserGetInfo(None, n, 2)["last_logon"]
        except win32net.error as e:
            st.setdefault("codex_last_logon", {})[n] = f"error:{e.winerror}"
    r = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True)
    st["process_count"] = len(r.stdout.splitlines())
    print(save(f"state-{label}.json", st))


# ---------------------------------------------------------------- shared task lists
def tool_tasks():
    git_env = {"HOME": str(WS), "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
    return [
        {"id": "curl", "kind": "run", "argv": [CURL, "-sS", "-o", "NUL", "-w", "http=%{http_code}", "--max-time", "25",
                                                "--ssl-revoke-best-effort", URL], "cwd": str(WS), "timeout": 60},
        {"id": "iwr", "kind": "run", "argv": [PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                               "-Command", IWR], "cwd": str(WS), "timeout": 60},
        {"id": "git", "kind": "run", "argv": [GIT, "-c", "http.sslBackend=schannel", "ls-remote", GIT_REPO, "HEAD"],
         "cwd": str(WS), "timeout": 60, "env": git_env},
        {"id": "urllib", "kind": "run", "argv": [str(PY), "-I", "-c", URLLIB], "cwd": str(WS), "timeout": 60},
    ]


ENV_NAMES = ["USERNAME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "HOMEDRIVE", "HOMEPATH"]


def child_spec(tag, extra):
    sp = SPECS / f"{tag}-child.json"
    tasks = [{"id": "token", "kind": "token"}, {"id": "env", "kind": "env", "names": ENV_NAMES},
             {"id": "sspi", "kind": "sspi"}, *extra, *tool_tasks()]
    sp.write_text(json.dumps({"tag": tag, "out": str(OUT / f"{tag}-child.json"), "tasks": tasks}), encoding="utf-8")
    return {"id": "child", "argv": [str(PY), "-I", "-B", str(TLSCHILD), str(sp)],
            "stdout": str(OUT / f"{tag}-child.out"), "stderr": str(OUT / f"{tag}-child.err"), "timeout": 300}


def read_text(p, n=3000):
    try:
        return Path(p).read_bytes().decode("utf-8", "replace")[-n:]
    except OSError as e:
        return f"read_error:{e}"


# ---------------------------------------------------------------- control (current user, no UAC)
def control():
    L = tools_module("launcher", LAUNCHER)
    T = tools_module("tls_child", TLSCHILD)
    adv, k32 = L.adv, L.k32
    adv.DuplicateTokenEx.restype = wintypes.BOOL
    adv.DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                     ctypes.POINTER(wintypes.HANDLE)]
    adv.SetThreadToken.argtypes = [ctypes.c_void_p, wintypes.HANDLE]
    adv.OpenThreadToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, ctypes.POINTER(wintypes.HANDLE)]
    adv.IsTokenRestricted.argtypes = [wintypes.HANDLE]
    k32.GetCurrentThread.restype = wintypes.HANDLE
    k32.SetErrorMode(0x0001 | 0x0002)  # no error boxes if a restricted child cannot start; children inherit it
    rec = load("setup.json")
    base = L.own_token()
    info = L.C.token_info()
    user, logon = info["user"], info["logon_sids"][0]
    groups = []
    for g in info["groups"]:
        if not g["sid"].startswith("S-1-16-") and g["sid"] not in groups:
            groups.append(g["sid"])
    variants = [("copy", 0, []), ("lua", DMP | LUA, []), ("everyone", 0, [SID_EVERYONE]),
                ("everyone_wr", WR, [SID_EVERYONE]), ("codex", None, None),
                ("allgroups_wr", WR, [user] + groups), ("allgroups", 0, [user] + groups)]

    def make(flags, sids):
        arr = (L.SID_AND_ATTRIBUTES * max(len(sids), 1))(*[L.SID_AND_ATTRIBUTES(L.psid(s).value, 0) for s in sids])
        new = wintypes.HANDLE()
        if not adv.CreateRestrictedToken(base, flags, 0, None, 0, None, len(sids), arr if sids else None,
                                         ctypes.byref(new)):
            raise OSError(f"CreateRestrictedToken: {L.err()}")
        return new

    def impersonated(tok):
        imp = wintypes.HANDLE()
        if not adv.DuplicateTokenEx(tok, 0x02000000, None, 2, 2, ctypes.byref(imp)):  # SecurityImpersonation
            return f"DuplicateTokenEx:{L.err()}"
        if not adv.SetThreadToken(None, imp):
            k32.CloseHandle(imp)
            return f"SetThreadToken:{L.err()}"
        try:
            th = wintypes.HANDLE()
            lvl = None
            restricted = None
            if adv.OpenThreadToken(k32.GetCurrentThread(), 0x8, True, ctypes.byref(th)):
                b = L.C.tok_raw(th, 9)  # TokenImpersonationLevel
                lvl = ctypes.c_int.from_buffer(b).value if b is not None else None
                restricted = bool(adv.IsTokenRestricted(th))
                k32.CloseHandle(th)
            return {"impersonation_level": lvl, "thread_token_restricted": restricted, "sspi": T.sspi_all()}
        finally:
            adv.SetThreadToken(None, None)
            k32.CloseHandle(imp)

    env = L.env_block({**os.environ, "TEMP": str(TEMP), "TMP": str(TEMP)})
    out = {"user_groups_used": len(groups), "variants": {}}
    for name, flags, sids in variants:
        log(f"control {name}")
        if name == "codex":
            tok, trec, _ = L.restricted_token(base, "base", rec["cap_sid"], "codex")
        else:
            tok = make(flags, sids)
            trec = {"flags": hex(flags), "restricting_count": len(sids)}
        trec["is_token_restricted"] = bool(adv.IsTokenRestricted(tok))
        trials = []
        for t in range(1, TRIALS + 1):
            tag = f"ctl-{name}-{t}"
            r = {"impersonation": impersonated(tok)}
            Ld = child_spec(tag, [])
            r["process"] = L.launch(tok, Ld, env, str(WS))
            r["child"] = parse_isojson(read_text(Ld["stdout"], 200000))
            if r["child"] is None:
                r["child_stdout"], r["child_stderr"] = read_text(Ld["stdout"], 600), read_text(Ld["stderr"], 600)
            trials.append(r)
        out["variants"][name] = {"token": trec, "trials": trials}
        k32.CloseHandle(tok)
    k32.CloseHandle(base)
    print(save("control.json", out))


# ---------------------------------------------------------------- run (measurement account)
def run():
    L = tools_module("launcher", LAUNCHER)
    adv, k32 = L.adv, L.k32
    adv.CreateProcessWithLogonW.restype = wintypes.BOOL
    adv.CreateProcessWithLogonW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                            wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
                                            wintypes.LPCWSTR, ctypes.POINTER(L.STARTUPINFOW),
                                            ctypes.POINTER(L.PROCESS_INFORMATION)]
    rec = load("setup.json")
    sid = lookup_sid(ACCOUNT)
    if not sid or rec.get("account_sid") != sid:
        sys.exit("account missing or acl not run")
    pw = json.loads(SECRETS.read_text(encoding="utf-8"))[ACCOUNT]
    out = {"account_sid_kind": "measurement", "before": profile_state(sid), "trials": {}}
    if out["before"]["user_dirs"] or out["before"]["profilelist"]:
        sys.exit("a profile of the measurement account already exists")

    def trial(cell, t):
        flags, mode = CELLS[cell]
        tag = f"{cell}-{t}"
        hk = {"id": "hkcu", "kind": "hkcu", "write": cell, "data": tag, "read": list(CELLS)}
        lspec = {"tag": tag, "mode": mode, "cap_sid": rec["cap_sid"], "dacl": "codex", "env_inherit": True,
                 "env": {"TEMP": str(TEMP), "TMP": str(TEMP)}, "cwd": str(WS),
                 "result": str(OUT / f"{tag}-launcher.json"), "launches": [child_spec(tag, [hk])]}
        sp = SPECS / f"{tag}-launcher.json"
        sp.write_text(json.dumps(lspec), encoding="utf-8")
        si = L.STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        si.dwFlags = 0x80  # STARTF_FORCEOFFFEEDBACK, as Codex runner_client.rs
        pi = L.PROCESS_INFORMATION()
        cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(PY), "-I", "-B", str(LAUNCHER), str(sp)]))
        r = {"cell": cell, "logon_flags": flags, "mode": mode, "profile_before": profile_state(sid)}
        previous = k32.SetErrorMode(0x0001 | 0x0002)
        t0 = time.monotonic()
        ok = adv.CreateProcessWithLogonW(ACCOUNT, ".", pw, flags, str(PY), cmd, 0x08000000 | 0x400, None, str(WS),
                                         ctypes.byref(si), ctypes.byref(pi))
        e = ctypes.get_last_error()
        r["logon_call_seconds"] = round(time.monotonic() - t0, 2)
        k32.SetErrorMode(previous)
        if not ok:
            r["logon"] = f"error:{e}"
            return r
        r["profile_while_running"] = profile_state(sid)
        w = k32.WaitForSingleObject(pi.hProcess, 600 * 1000)
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
        if w == 0x102:
            k32.TerminateProcess(pi.hProcess, 1)
        r["launcher_exit"] = "timeout" if w == 0x102 else f"0x{code.value:08x}"
        r["seconds"] = round(time.monotonic() - t0, 2)
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)
        try:
            r["launcher"] = json.loads((OUT / f"{tag}-launcher.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as ex:
            r["launcher"] = f"read_error:{ex}"
        r["child"] = parse_isojson(read_text(OUT / f"{tag}-child.out", 400000))
        if r["child"] is None:
            r["child_stdout"] = read_text(OUT / f"{tag}-child.out", 800)
            r["child_stderr"] = read_text(OUT / f"{tag}-child.err", 800)
        r["profile_after_exit"] = profile_state(sid)
        t1 = time.monotonic()
        while profile_state(sid)["hku_loaded"] and time.monotonic() - t1 < 120:
            time.sleep(1)
        r["hive_unload_wait_seconds"] = round(time.monotonic() - t1, 1)
        r["profile_after_wait"] = profile_state(sid)
        return r

    phases = {"AB": ("A", "B"), "DC": ("D", "C"), "A2B2": ("A2", "B2")}
    for phase in (phases[x] for x in os.environ.get("TLS_PHASES", "AB,DC,A2B2").split(",")):  # AB only: smoke check
        for t in range(1, TRIALS + 1):
            for cell in phase:
                log(f"run {cell} trial {t}")
                out["trials"].setdefault(cell, []).append(trial(cell, t))
                save("run-partial.json", out)
    out["after"] = profile_state(sid)
    print(save("run.json", out))


# ---------------------------------------------------------------- summary
def ok_run(v, needle):
    return isinstance(v, dict) and v.get("exit") == 0 and needle in (v.get("stdout") or "")


CHECKS = [("curl.exe(schannel)", lambda c: ok_run(c.get("curl"), "http=200")),
          ("PowerShell 5.1 `Invoke-WebRequest`", lambda c: ok_run(c.get("iwr"), "status=200")),
          ("`git -c http.sslBackend=schannel ls-remote`", lambda c: ok_run(c.get("git"), "HEAD")),
          ("Python urllib(OpenSSL, 대조군)", lambda c: ok_run(c.get("urllib"), "status=200")),
          ("`AcquireCredentialsHandleW` schannel `SCHANNEL_CRED`", lambda c: (c.get("sspi") or {}).get("schannel_v4") == "0x00000000"),
          ("`AcquireCredentialsHandleW` schannel `SCH_CREDENTIALS`", lambda c: (c.get("sspi") or {}).get("schannel_v5") == "0x00000000"),
          ("`AcquireCredentialsHandleW` schannel, 인증 데이터 없음", lambda c: (c.get("sspi") or {}).get("schannel_null") == "0x00000000"),
          ("`AcquireCredentialsHandleW` Negotiate", lambda c: (c.get("sspi") or {}).get("negotiate_null") == "0x00000000")]


def count(vals):
    vals = list(vals)
    return f"{sum(1 for v in vals if v)}/{len(vals)}"


def summary():
    sys.stdout.reconfigure(encoding="utf-8") if hasattr(sys.stdout, "reconfigure") else None
    if (LOCAL / "control.json").exists():
        d = load("control.json")
        names = list(d["variants"])
        print("## control\n| 항목 | " + " | ".join(names) + " |\n| --- |" + " --- |" * len(names))
        print("| 스레드 가장 ACH schannel v4 | " + " | ".join(count(
            isinstance(t["impersonation"], dict) and t["impersonation"]["sspi"]["schannel_v4"] == "0x00000000"
            for t in d["variants"][n]["trials"]) for n in names) + " |")
        print("| 스레드 가장 ACH Negotiate | " + " | ".join(count(
            isinstance(t["impersonation"], dict) and t["impersonation"]["sspi"]["negotiate_null"] == "0x00000000"
            for t in d["variants"][n]["trials"]) for n in names) + " |")
        print("| 자식 시작 | " + " | ".join(count(t["child"] is not None for t in d["variants"][n]["trials"])
                                       for n in names) + " |")
        for label, fn in CHECKS:
            print(f"| {label} | " + " | ".join(count(fn(t["child"] or {}) for t in d["variants"][n]["trials"])
                                               for n in names) + " |")
        for n in names:
            t = d["variants"][n]["trials"][0]
            print(n, d["variants"][n]["token"].get("is_token_restricted"),
                  json.dumps(t["impersonation"])[:300], t["process"].get("exit") if isinstance(t["process"], dict) else t["process"])
            c = t["child"] or {}
            print("   sspi", c.get("sspi"), "| curl", (c.get("curl") or {}).get("stderr", "")[-200:].strip(),
                  "| iwr", (c.get("iwr") or {}).get("stdout", "")[-300:].strip(),
                  "| git", (c.get("git") or {}).get("stderr", "")[-200:].strip())
    if (LOCAL / "run.json").exists() or (LOCAL / "run-partial.json").exists():
        d = load("run.json") if (LOCAL / "run.json").exists() else load("run-partial.json")
        cells = [c for c in CELLS if c in d["trials"]]
        print("\n## run\n| 항목 | " + " | ".join(cells) + " |\n| --- |" + " --- |" * len(cells))
        print("| 셸 시작 | " + " | ".join(count(t.get("child") is not None for t in d["trials"][c]) for c in cells) + " |")
        for label, fn in CHECKS:
            print(f"| {label} | " + " | ".join(count(fn(t.get("child") or {}) for t in d["trials"][c]) for c in cells) + " |")
        for c in cells:
            for t in d["trials"][c]:
                ch = t.get("child") or {}
                hk = ch.get("hkcu") or {}
                tok = ch.get("token") or {}
                print(c, "logon", t.get("logon_call_seconds"), "s exit", t.get("launcher_exit"),
                      "| restricted", tok.get("is_token_restricted"), "| hkcu", hk.get("hkcu", "")[-60:] if isinstance(hk.get("hkcu"), str) else hk.get("hkcu"),
                      "own", hk.get("own_hive"), "write", hk.get("write"), "read", hk.get("read"),
                      "| profile before", t.get("profile_before"), "running", t.get("profile_while_running"),
                      "after", t.get("profile_after_exit"), "unload", t.get("hive_unload_wait_seconds"))
            ch = d["trials"][c][0].get("child") or {}
            print("   ", c, "env", ch.get("env"), "sspi", ch.get("sspi"))
            print("    curl", (ch.get("curl") or {}).get("stderr", "")[-200:].strip(),
                  "| iwr", (ch.get("iwr") or {}).get("stdout", "")[-300:].strip(),
                  "| git", (ch.get("git") or {}).get("stderr", "")[-200:].strip())


if __name__ == "__main__":
    step = sys.argv[1]
    if step == "state":
        state(sys.argv[2])
    else:
        {"prep": prep, "control": control, "acl": acl, "run": run, "cleanup": cleanup, "summary": summary}[step]()
