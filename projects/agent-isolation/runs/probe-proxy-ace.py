"""Local proxy, profile read ACE and HKLM key DACL for the separate-account Restricted Token shell
(runs/2026-11-27-02.md). Requested by the same session as 2026-11-27-01. Host side, run with the test venv Python.
Data goes to local/2026-11-27-pxa.

Usage: python probe-proxy-ace.py prep | acl | run | state <label> | cleanup | summary
  prep     before the UAC step. Creates %USERPROFILE%\\agent-isolation-pxa (not directly under C:\\; user, SYSTEM and
           Administrators only, inheritance removed):
             tools\\     test Python (copy of the venv base, stdlib only), child.py, launcher.py, ux_child.py,
                        pa_child.py; Users read and run
             secrets\\pxa.json         random passwords of iso-rt-pxa1 and iso-rt-pxb1; user and SYSTEM only
             secrets\\proxy-auth.txt   "proxy:<32 random bytes, base64url>" for the A3 proxy
             rt\\{ws, temp, out, specs} launcher folders (acl adds the two accounts)
             codex\\{ws, temp}         workspace of the `codex sandbox` cells
             b1\\tree   100 folders, each with 10 files and 99 subfolders of 10 files: 10,000 folders and 100,000
                        files, plus d00\\prot (inheritance removed: user, SYSTEM, Administrators) with one file
             b2\\parent DACL user, SYSTEM, Administrators full control, inheritance removed (the Windows default of
                        a profile root; this PC's profile root inherits Users and Everyone read, 2026-11-25-01).
                        child\\f.txt, child\\sub\\g.txt, other\\o.txt
           and a random capability SID in the Codex format.
  acl      after the admin create: the two accounts read and run on rt, modify on ws, temp, out; inheritable read
           and run for iso-rt-pxg and CodexSandboxUsers on b2\\parent\\child (b2\\parent gets nothing).
  run      groups (PXA_GROUPS, default a1,a3,b2,c,b1; PXA_TRIALS, default 5)
    a1     proxy without authentication. Cells CX-off and host, alternating. The shell: TCP listener table
           (is the proxy port listed with its PID), direct HTTP and HTTPS to example.com, through the proxy an
           absolute-form HTTP request and CONNECT + TLS (Python), curl -x for plain HTTP, and the proxy's refusal of
           127.0.0.1 targets. The proxy's name resolutions are counted from its event log.
    a3     proxy with Basic authentication. Cells CX-off and host: no header and a wrong value, HTTP and CONNECT;
           host also the correct value (Python HTTP, CONNECT + TLS, curl --proxy-user). Then host-only malformed
           headers over raw sockets for both forms; after each the proxy process must still run and answer 407
           to a request without the header, and every trial ends with one correct relay.
    b2     cells X-base, X-none, CX-off: files under b2\\parent\\child by full path (Python, cmd type,
           PowerShell Get-Content), by relative path after changing into child (PowerShell Set-Location, cmd cd,
           Python os.chdir), listing parent and child, and other\\o.txt (no ACE).
    c      cells host (the current user: an administrator with the UAC filtered token), X-base, X-none, B-none,
           CX-off: KEY_READ and KEY_QUERY_VALUE opens of both test keys and the value comparison.
    b1     per trial both attach methods in alternating order: Win32 SetNamedSecurityInfo on b1\\tree with the two
           inheritable read and run ACEs (iso-rt-pxg, CodexSandboxUsers) and icacls /grant of the same ACEs. Each
           attach and detach is timed, followed by a sample of 200 fixed paths (inherited ACE present) and reads by
           X-base and CX-off.
  Cells    X-base  iso-rt-pxa1 (CreateProcessWithLogonW, logon flags 0), Codex-style WRITE_RESTRICTED token
                   (launcher "base": capability SID, account, logon SID, Everyone), WinSta0\\Default
           X-none  same account, unrestricted copy of its logon token (the launcher token)
           B-none  iso-rt-pxb1 (second standard user), unrestricted
           CX-off  installed Codex CLI `codex sandbox`, windows.sandbox="elevated", network disabled
                   (CodexSandboxOffline with Codex's firewall rules and WFP filters)
           host    the current user, no sandbox
  state    non-admin PC state.
  cleanup  after the admin cleanup: stops leftover proxy processes started here and deletes the test folder.
Only example.com is contacted outside the PC. A2 (port takeover) is not run: the user chose a source and
documentation check only.
"""
import os
import sys
import json
import time
import ctypes
import base64
import random
import shutil
import socket
import secrets
import subprocess
import importlib.util
from ctypes import wintypes
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-27-pxa")
os.environ.setdefault("ISO_ROOT", str(Path(os.environ["USERPROFILE"]) / "agent-isolation-pxa"))
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, TOOLS, PYRT, PY, CHILD, LOCAL, token_sids, lookup_sid,  # noqa: E402
                                   icacls, protect, dacl_aces, save, load, parse_isojson)

import win32net  # noqa: E402
import win32security  # noqa: E402

HERE = Path(__file__).parent


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


UX = module("uxnet", "probe-ux-net.py")  # log, ps, codex_env, codex_state, read_text, tcp_rows, tools_module
SU = module("rtsetup", "probe-rt-reduced-setup.py")  # password, grant, READ_EXEC, MODIFY
log, ps = UX.log, UX.ps

SHELL, USER_B, GROUP, CODEX_GROUP = "iso-rt-pxa1", "iso-rt-pxb1", "iso-rt-pxg", "CodexSandboxUsers"
RT = ROOT / "rt"
WS, TEMP, OUT, SPECS = RT / "ws", RT / "temp", RT / "out", RT / "specs"
CXWS, CXTEMP = ROOT / "codex" / "ws", ROOT / "codex" / "temp"
LAUNCHER, UXCHILD, PACHILD = TOOLS / "launcher.py", TOOLS / "ux_child.py", TOOLS / "pa_child.py"
SECRETS, PROXY_AUTH = ROOT / "secrets" / "pxa.json", ROOT / "secrets" / "proxy-auth.txt"
PROXY_JS = HERE / "probe-local-proxy.mjs"
NODE = r"C:\Program Files\nodejs\node.exe"
CURL = r"C:\Windows\System32\curl.exe"
PSH = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
B1 = ROOT / "b1" / "tree"
B2 = ROOT / "b2" / "parent"
B2_TEXT, B1_TEXT = "iso-b2-ok", "iso-b1-ok"
KEY_PARENT = r"SOFTWARE\AgentIsolationMeasure"
KEYS = ("pw-installer-me", "pw-installer-b")
DUMMY = "iso-dummy-not-a-password"
EXAMPLE, EXPECT = "example.com", "Example Domain"
TRIALS = int(os.environ.get("PXA_TRIALS", "5"))
# account cells: (kind, account, launcher mode)
CELLS = {"X-base": ("account", SHELL, "base"), "X-none": ("account", SHELL, "none"),
         "B-none": ("account", USER_B, "none"), "CX-off": ("codex",), "host": ("host",)}


# ---------------------------------------------------------------- prep, acl, cleanup
def build_tree():
    t0 = time.monotonic()
    for i in range(100):
        d = B1 / f"d{i:02d}"
        d.mkdir(parents=True)
        for f in range(10):
            (d / f"f{f}.txt").write_text(B1_TEXT, encoding="utf-8")
        for j in range(99):
            s = d / f"s{j:02d}"
            s.mkdir()
            for f in range(10):
                (s / f"f{f}.txt").write_text(B1_TEXT, encoding="utf-8")
    prot = B1 / "d00" / "prot"
    prot.mkdir()
    (prot / "p.txt").write_text(B1_TEXT, encoding="utf-8")
    return round(time.monotonic() - t0, 1)


def prep():
    if ROOT.exists():
        sys.exit(f"{ROOT} already exists; refusing to overwrite")
    user_sid, logon_sid = token_sids()
    rec = {"user_sid": user_sid, "logon_sid": logon_sid,
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
    shutil.copy2(HERE / "probe-token-backends-child.py", CHILD)
    shutil.copy2(HERE / "probe-rt-reduced-launcher.py", LAUNCHER)
    shutil.copy2(HERE / "probe-ux-net-child.py", UXCHILD)
    shutil.copy2(HERE / "probe-proxy-ace-child.py", PACHILD)
    icacls(TOOLS, "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F",
           "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")
    (ROOT / "secrets").mkdir()
    icacls(ROOT / "secrets", "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
    SECRETS.write_text(json.dumps({SHELL: SU.password(), USER_B: SU.password()}), encoding="utf-8")
    PROXY_AUTH.write_text("proxy:" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="),
                          encoding="utf-8")
    for d in (WS, TEMP, OUT, SPECS, CXWS, CXTEMP):
        d.mkdir(parents=True)
    # b2: parent with the Windows default profile root DACL, child gets the group ACE in acl()
    (B2 / "child" / "sub").mkdir(parents=True)
    (B2 / "other").mkdir()
    for p in (B2 / "child" / "f.txt", B2 / "child" / "sub" / "g.txt", B2 / "other" / "o.txt"):
        p.write_text(B2_TEXT, encoding="utf-8")
    protect(B2, user_sid)
    rec["b1_build_seconds"] = build_tree()
    protect(B1 / "d00" / "prot", user_sid)
    rec["dacl_prep"] = {str(p): dacl_aces(p) for p in [ROOT, TOOLS, ROOT / "secrets", RT, B1, B1 / "d00" / "prot",
                                                     B2, B2 / "child"]}
    print(save("setup.json", rec))


def acl():
    rec = load("setup.json")
    sids = {n: lookup_sid(n) for n in (SHELL, USER_B, GROUP, CODEX_GROUP)}
    if not all(sids.values()):
        sys.exit(f"missing: {[n for n, s in sids.items() if not s]}")
    SU.grant(RT, [(sids[SHELL], SU.READ_EXEC), (sids[USER_B], SU.READ_EXEC)])
    for d in (WS, TEMP, OUT):
        SU.grant(d, [(sids[SHELL], SU.MODIFY), (sids[USER_B], SU.MODIFY)])
    SU.grant(B2 / "child", [(sids[GROUP], SU.READ_EXEC), (sids[CODEX_GROUP], SU.READ_EXEC)])
    rec["sids"] = sids
    rec["dacl_acl"] = {str(p): dacl_aces(p) for p in [RT, WS, TEMP, OUT, B2, B2 / "child", B2 / "child" / "f.txt"]}
    print(save("setup.json", rec))


def cleanup():
    if lookup_sid(SHELL) or lookup_sid(USER_B):
        sys.exit("measurement accounts still exist; run the admin cleanup first")
    r = subprocess.run(ps("Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | Where-Object CommandLine -like "
                          "'*probe-local-proxy.mjs*' | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; "
                          "$_.ProcessId }"), capture_output=True)
    print("stopped proxy processes:", r.stdout.decode().split())
    t0 = time.monotonic()
    shutil.rmtree(ROOT)
    print("removed", ROOT, "exists:", ROOT.exists(), "seconds:", round(time.monotonic() - t0, 1))


# ---------------------------------------------------------------- runner
def codex_argv(spec):
    prof = '{":root"="read", ":tmpdir"="write", ":workspace_roots"={"."="write"}}'
    return [str(UX.CODEX), "sandbox", "-c", 'windows.sandbox="elevated"', "-c", f"permissions.iso.filesystem={prof}",
            "-c", "permissions.iso.network.enabled=false", "-P", "iso", "-C", str(CXWS), "--",
            str(PY), "-I", "-B", str(PACHILD), str(spec)]


class Runner:
    def __init__(self):
        self.L = UX.tools_module("launcher", LAUNCHER)
        L = self.L
        L.adv.CreateProcessWithLogonW.restype = wintypes.BOOL
        L.adv.CreateProcessWithLogonW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                                  wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
                                                  wintypes.LPCWSTR, ctypes.POINTER(L.STARTUPINFOW),
                                                  ctypes.POINTER(L.PROCESS_INFORMATION)]
        self.rec = load("setup.json")
        for n in (SHELL, USER_B):
            if lookup_sid(n) != (self.rec.get("sids") or {}).get(n):
                sys.exit(f"{n} missing or acl not run")
        self.pw = json.loads(SECRETS.read_text(encoding="utf-8"))

    def trial(self, cell, tag, tasks, timeout=300):
        kind = CELLS[cell]
        d = CXWS if kind[0] == "codex" else OUT
        for old in [*d.glob(f"{tag}-*"), *SPECS.glob(f"{tag}-*")]:
            old.unlink()
        sp = (CXWS if kind[0] == "codex" else SPECS) / f"{tag}-child.json"
        sp.write_text(json.dumps({"tag": tag, "out": str(d / f"{tag}-child.json"), "tasks": tasks}), encoding="utf-8")
        r = {"cell": cell, "tag": tag}
        t0 = time.monotonic()
        if kind[0] == "account":
            L, k32 = self.L, self.L.k32
            _, account, mode = kind
            launch = {"id": "child", "argv": [str(PY), "-I", "-B", str(PACHILD), str(sp)],
                      "stdout": str(OUT / f"{tag}-child.out"), "stderr": str(OUT / f"{tag}-child.err"),
                      "timeout": timeout}
            lspec = {"tag": tag, "mode": mode, "cap_sid": self.rec["cap_sid"], "dacl": "codex", "env_inherit": True,
                     "env": {"TEMP": str(TEMP), "TMP": str(TEMP)}, "cwd": str(WS),
                     "result": str(OUT / f"{tag}-launcher.json"), "launches": [launch]}
            lp = SPECS / f"{tag}-launcher.json"
            lp.write_text(json.dumps(lspec), encoding="utf-8")
            si = L.STARTUPINFOW()
            si.cb = ctypes.sizeof(si)
            si.dwFlags = 0x80  # STARTF_FORCEOFFFEEDBACK, as Codex runner_client.rs
            pi = L.PROCESS_INFORMATION()
            cmd = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(PY), "-I", "-B", str(LAUNCHER), str(lp)]))
            previous = k32.SetErrorMode(0x0001 | 0x0002)
            ok = L.adv.CreateProcessWithLogonW(account, ".", self.pw[account], 0, str(PY), cmd, 0x08000000 | 0x400,
                                               None, str(WS), ctypes.byref(si), ctypes.byref(pi))
            e = ctypes.get_last_error()
            k32.SetErrorMode(previous)
            if not ok:
                r["logon"] = f"error:{e}"
                return r
            w = k32.WaitForSingleObject(pi.hProcess, (timeout + 60) * 1000)
            code = wintypes.DWORD()
            k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
            if w == 0x102:
                k32.TerminateProcess(pi.hProcess, 1)
            r["launcher_exit"] = "timeout" if w == 0x102 else f"0x{code.value:08x}"
            k32.CloseHandle(pi.hThread)
            k32.CloseHandle(pi.hProcess)
            try:
                lr = json.loads((OUT / f"{tag}-launcher.json").read_text(encoding="utf-8"))
                lr.pop("launcher_process_sd", None)
                r["launcher"] = {"restricted": lr.get("restricted"), "launcher_token": lr.get("launcher_token"),
                                 "launch": (lr.get("launches") or {}).get("child"), "error": lr.get("error")}
            except (OSError, ValueError) as ex:
                r["launcher"] = f"read_error:{ex}"
            text, err_text = UX.read_text(OUT / f"{tag}-child.out", 400000), UX.read_text(OUT / f"{tag}-child.err", 800)
        else:
            if kind[0] == "codex":
                argv, env, cwd = codex_argv(sp), UX.codex_env(), CXWS
            else:
                argv, cwd = [str(PY), "-I", "-B", str(PACHILD), str(sp)], WS
                env = {**os.environ, "TEMP": str(TEMP), "TMP": str(TEMP)}
            p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                so, se = p.communicate(timeout=timeout + 60)
                r["exit"] = p.returncode
            except subprocess.TimeoutExpired:
                p.kill()
                so, se = p.communicate()
                r["exit"] = "timeout"
            text, err_text = so.decode("utf-8", "replace"), se.decode("utf-8", "replace")[-800:]
        r["seconds"] = round(time.monotonic() - t0, 1)
        r["child"] = parse_isojson(text)
        if r["child"] is None:
            r["child_stdout"], r["child_stderr"] = text[-800:], err_text
        return r


def order(cells, t):
    return list(cells) if t % 2 else list(reversed(cells))


def save_group(name, rec):
    save(f"{name}-partial.json", rec)


# ---------------------------------------------------------------- proxy
class Proxy:
    def __init__(self, label, auth):
        self.pf, self.ev = LOCAL / f"proxy-{label}-port.json", LOCAL / f"proxy-{label}-events.jsonl"
        for f in (self.pf, self.ev):
            f.unlink(missing_ok=True)
        argv = [NODE, str(PROXY_JS), str(self.pf), str(self.ev)] + ([str(PROXY_AUTH)] if auth else [])
        self.p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=0x08000000)
        end = time.monotonic() + 15
        while not self.pf.exists() and time.monotonic() < end:
            time.sleep(0.1)
        info = json.loads(self.pf.read_text(encoding="utf-8"))
        self.port, self.pid = info["port"], info["pid"]

    def events(self):
        try:
            return [json.loads(ln) for ln in self.ev.read_text(encoding="utf-8").splitlines() if ln.strip()]
        except OSError:
            return []

    def picks(self):
        return sum(1 for e in self.events() if e.get("ev") == "pick")

    def alive(self):
        return self.p.poll() is None

    def stop(self):
        alive = self.alive()
        if alive:
            self.p.terminate()
        try:
            _, se = self.p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            _, se = self.p.communicate()
        return {"alive_at_stop": alive, "stderr": se.decode("utf-8", "replace")[-600:]}


def a1_tasks(px):
    return [
        {"id": "token", "kind": "token"},
        {"id": "tcp_table", "kind": "tcp_table", "port": px.port, "pid": px.pid},
        {"id": "direct_http", "kind": "http", "url": f"http://{EXAMPLE}/", "expect": EXPECT},
        {"id": "direct_https", "kind": "http", "url": f"https://{EXAMPLE}/", "expect": EXPECT},
        {"id": "proxy_http", "kind": "proxy_http", "port": px.port, "host": EXAMPLE, "expect": EXPECT},
        {"id": "proxy_connect", "kind": "proxy_connect", "port": px.port, "host": EXAMPLE, "tls": True, "expect": EXPECT},
        {"id": "curl_proxy_http", "kind": "run", "argv": [CURL, "-s", "-o", "NUL", "-w", "%{http_code}", "--max-time",
                                                           "15", "-x", f"http://127.0.0.1:{px.port}", f"http://{EXAMPLE}/"],
         "timeout": 30, "ok_if": "200"},
        {"id": "proxy_private_http", "kind": "proxy_http", "port": px.port, "host": "127.0.0.1:9"},
        {"id": "proxy_private_connect", "kind": "proxy_connect", "port": px.port, "host": "127.0.0.1",
         "target_port": 445},
    ]


def a1_group(R):
    px = Proxy("a1", auth=False)
    out = {"proxy": {"port_is_ephemeral": px.port >= 49152}, "trials": {}}
    try:
        for t in range(1, TRIALS + 1):
            for cell in order(("CX-off", "host"), t):
                before = px.picks()
                r = R.trial(cell, f"a1-{cell}-{t}", a1_tasks(px))
                r["proxy_picks"] = px.picks() - before
                r["proxy_alive"] = px.alive()
                out["trials"].setdefault(cell, []).append(r)
                log(f"a1 {cell} {t}: {short(r)}")
                save_group("a1", out)
    finally:
        out["proxy"]["stop"] = px.stop()
        out["proxy"]["events"] = summarize_events(px.events())
    print(save("a1.json", out))


def b64(s):
    return base64.b64encode(s.encode()).decode()


def raw(port, payload, read_timeout=10):
    res = {}
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=read_timeout)
    except OSError as e:
        return {"connect": UX.oserr(e)}
    try:
        s.sendall(payload)
    except OSError as e:
        res["send"] = UX.oserr(e)
    try:
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        head = buf.partition(b"\r\n\r\n")[0].decode("latin-1", "replace")
        res["status"] = head.split("\r\n")[0][:60] if head else "closed_without_response"
        res["proxy_authenticate"] = "proxy-authenticate:" in head.lower()
    except socket.timeout:
        res["status"] = "timeout"
    except OSError as e:
        res["status"] = UX.oserr(e)
    s.close()
    return res


def request_bytes(form, auth):
    lines = ([f"GET http://{EXAMPLE}/ HTTP/1.1", f"Host: {EXAMPLE}", "Connection: close"] if form == "http"
             else [f"CONNECT {EXAMPLE}:443 HTTP/1.1", f"Host: {EXAMPLE}:443"])
    for a in ([] if auth is None else auth if isinstance(auth, list) else [auth]):
        lines.append(f"Proxy-Authorization: {a}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def a3_group(R):
    cred = PROXY_AUTH.read_text(encoding="utf-8").strip()
    user, password = cred.split(":", 1)
    good = "Basic " + b64(cred)
    wrong = "Basic " + b64(user + ":" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))
    px = Proxy("a3", auth=True)
    out = {"proxy": {}, "trials": {}, "malformed": []}

    def tasks(cell):
        ts = [{"id": "http_none", "kind": "proxy_http", "port": px.port, "host": EXAMPLE, "expect": EXPECT},
              {"id": "connect_none", "kind": "proxy_connect", "port": px.port, "host": EXAMPLE, "tls": True,
               "expect": EXPECT},
              {"id": "http_wrong", "kind": "proxy_http", "port": px.port, "host": EXAMPLE, "auth": wrong, "expect": EXPECT},
              {"id": "connect_wrong", "kind": "proxy_connect", "port": px.port, "host": EXAMPLE, "auth": wrong,
               "tls": True, "expect": EXPECT}]
        if cell == "host":
            ts += [{"id": "http_good", "kind": "proxy_http", "port": px.port, "host": EXAMPLE, "auth": good,
                    "expect": EXPECT},
                   {"id": "connect_good", "kind": "proxy_connect", "port": px.port, "host": EXAMPLE, "auth": good,
                    "tls": True, "expect": EXPECT},
                   {"id": "curl_good", "kind": "run", "argv": [CURL, "-s", "-o", "NUL", "-w", "%{http_code}",
                                                               "--max-time", "15", "-x", f"http://127.0.0.1:{px.port}",
                                                               "--proxy-user", cred, f"http://{EXAMPLE}/"],
                    "timeout": 30, "ok_if": "200"}]
        return ts

    cases = {"none": None, "wrong": wrong, "bearer": "Bearer " + password, "broken_base64": "Basic !!not*base64%%",
             "empty_basic": "Basic ", "scheme_only": "Basic", "no_colon": "Basic " + b64(password),
             "lowercase_scheme_correct": "basic " + b64(cred), "long_8k": "Basic " + "A" * 8000,
             "long_64k": "Basic " + "A" * 65536, "long_1m": "Basic " + "A" * (1 << 20),
             "duplicate_wrong_then_correct": [wrong, good], "duplicate_correct_then_wrong": [good, wrong]}
    try:
        for t in range(1, TRIALS + 1):
            for cell in order(("CX-off", "host"), t):
                before = px.picks()
                r = R.trial(cell, f"a3-{cell}-{t}", tasks(cell))
                r["proxy_picks"] = px.picks() - before
                r["proxy_alive"] = px.alive()
                out["trials"].setdefault(cell, []).append(r)
                log(f"a3 {cell} {t}: {short(r)}")
            trial = {"trial": t, "cases": {}}
            for name, auth in cases.items():
                for form in ("http", "connect"):
                    before = px.picks()
                    res = raw(px.port, request_bytes(form, auth))
                    res["picks"] = px.picks() - before
                    res["alive"] = px.alive()
                    res["probe_without_header"] = raw(px.port, request_bytes("http", None)).get("status") if res["alive"] else None
                    trial["cases"][f"{name}/{form}"] = res
            before = px.picks()
            trial["final_correct_relay"] = raw(px.port, request_bytes("http", good), read_timeout=20)
            trial["final_correct_relay"]["picks"] = px.picks() - before
            trial["alive_at_end"] = px.alive()
            out["malformed"].append(trial)
            log(f"a3 malformed {t}: alive={trial['alive_at_end']} final={trial['final_correct_relay'].get('status')}")
            save_group("a3", out)
    finally:
        out["proxy"]["stop"] = px.stop()
        out["proxy"]["events"] = summarize_events(px.events())
    print(save("a3.json", out))


def summarize_events(evs):
    from collections import Counter
    c = Counter()
    for e in evs:
        key = e.get("ev")
        if key == "auth":
            key = f"auth:{e.get('kind')}:{e.get('result')}"
        elif key == "pick":
            key = f"pick:{e.get('host')}:{'public' if e.get('public') else 'refused'}"
        elif key in ("client_error", "upstream_error"):
            key = f"{key}:{e.get('code')}"
        c[key] += 1
    return dict(c)


# ---------------------------------------------------------------- b2, c
def b2_tasks():
    f, g, o, child = B2 / "child" / "f.txt", B2 / "child" / "sub" / "g.txt", B2 / "other" / "o.txt", B2 / "child"
    return [
        {"id": "token", "kind": "token"},
        {"id": "read_child_file", "kind": "readfile", "path": str(f), "expect": B2_TEXT},
        {"id": "read_grandchild_file", "kind": "readfile", "path": str(g), "expect": B2_TEXT},
        {"id": "read_other_file", "kind": "readfile", "path": str(o), "expect": B2_TEXT},
        {"id": "list_parent", "kind": "listdir", "path": str(B2)},
        {"id": "list_child", "kind": "listdir", "path": str(child)},
        {"id": "list_root", "kind": "listdir", "path": str(ROOT)},
        {"id": "cmd_type", "kind": "run", "argv": [CMD, "/d", "/c", "type", str(f)], "timeout": 30, "ok_if": B2_TEXT},
        {"id": "ps_get_content", "kind": "run", "argv": [PSH, "-NoProfile", "-NonInteractive", "-Command",
                                                          f"Get-Content -LiteralPath '{f}'"], "timeout": 60,
         "ok_if": B2_TEXT},
        {"id": "ps_set_location", "kind": "run", "argv": [PSH, "-NoProfile", "-NonInteractive", "-Command",
                                                           f"Set-Location -LiteralPath '{child}'; Get-Content f.txt"],
         "timeout": 60, "ok_if": B2_TEXT},
        # added after the smoke run: PowerShell Set-Location failed in every cell (as in 2026-11-26-04), so the
        # relative path is also tried with cmd cd and Python os.chdir
        # no quotes: list2cmdline turns inner quotes into \" which cmd cannot read (smoke run); the path has no spaces
        {"id": "cmd_cd", "kind": "run", "argv": [CMD, "/d", "/c", "cd", "/d", str(child), "&&", "type", "f.txt"],
         "timeout": 30, "ok_if": B2_TEXT},
        {"id": "py_chdir", "kind": "run", "argv": [str(PY), "-I", "-c",
                                                    f"import os; os.chdir(r'{child}'); print(open('f.txt').read())"],
         "timeout": 30, "ok_if": B2_TEXT},
    ]


def b2_group(R):
    out = {"trials": {}}
    for t in range(1, TRIALS + 1):
        for cell in order(("X-base", "X-none", "CX-off"), t):
            r = R.trial(cell, f"b2-{cell}-{t}", b2_tasks())
            out["trials"].setdefault(cell, []).append(r)
            log(f"b2 {cell} {t}: {short(r)}")
        save_group("b2", out)
    print(save("b2.json", out))


def c_tasks():
    ts = [{"id": "token", "kind": "token"}]
    for k in KEYS:
        path = KEY_PARENT + "\\" + k
        ts.append({"id": f"{k}/read", "kind": "reg_read", "path": path, "value": "pw", "expect": DUMMY,
                   "access": 0x20019})
        ts.append({"id": f"{k}/query_value", "kind": "reg_read", "path": path, "value": "pw", "expect": DUMMY,
                   "access": 0x0001})
    ts.append({"id": "parent/read", "kind": "reg_read", "path": KEY_PARENT, "value": "none", "expect": "",
               "access": 0x20019})
    return ts


def c_group(R):
    out = {"trials": {}}
    for t in range(1, TRIALS + 1):
        for cell in order(("host", "X-base", "X-none", "B-none", "CX-off"), t):
            r = R.trial(cell, f"c-{cell}-{t}", c_tasks())
            out["trials"].setdefault(cell, []).append(r)
            log(f"c {cell} {t}: {short(r)}")
        save_group("c", out)
    print(save("c.json", out))


# ---------------------------------------------------------------- b1
B1_SAMPLE_SEED = 20261127


def b1_sample():
    rnd = random.Random(B1_SAMPLE_SEED)
    out = []
    for _ in range(200):
        i, j, f = rnd.randrange(100), rnd.randrange(100), rnd.randrange(10)
        d = B1 / f"d{i:02d}" if j == 99 else B1 / f"d{i:02d}" / f"s{j:02d}"
        out.append(d if rnd.random() < 0.2 else d / f"f{f}.txt")
    return out


def inherited_count(paths, sids):
    want = set(sids)  # string SIDs (PySID is not hashable)
    n = 0
    for p in paths:
        dacl = win32security.GetNamedSecurityInfo(str(p), win32security.SE_FILE_OBJECT,
                                                  win32security.DACL_SECURITY_INFORMATION).GetSecurityDescriptorDacl()
        found = set()
        for i in range(dacl.GetAceCount()):
            (atype, aflags), _, sid = dacl.GetAce(i)
            s = win32security.ConvertSidToStringSid(sid)
            if atype == 0 and aflags & win32security.INHERITED_ACE and s in want:
                found.add(s)
        n += len(found) == len(want)
    return n


def revoke(path, sids):
    """Removes the explicit allow ACEs of the given SIDs and sets the DACL again (Win32 propagation)."""
    info = win32security.DACL_SECURITY_INFORMATION
    sd = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, info)
    old = sd.GetSecurityDescriptorDacl()
    drop = set(sids)
    new = win32security.ACL()
    for i in range(old.GetAceCount()):
        (atype, aflags), mask, sid = old.GetAce(i)
        if aflags & win32security.INHERITED_ACE or win32security.ConvertSidToStringSid(sid) in drop:
            continue
        new.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, aflags, mask, sid)
    win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                                       info | win32security.UNPROTECTED_DACL_SECURITY_INFORMATION, None, None, new, None)


def b1_tasks():
    files = {"child_file": B1 / "d00" / "f0.txt", "grandchild_file": B1 / "d00" / "s00" / "f0.txt",
             "last_file": B1 / "d99" / "s98" / "f9.txt", "protected_folder_file": B1 / "d00" / "prot" / "p.txt"}
    ts = [{"id": k, "kind": "readfile", "path": str(p), "expect": B1_TEXT} for k, p in files.items()]
    ts += [{"id": "list_tree", "kind": "listdir", "path": str(B1)},
           {"id": "list_deep", "kind": "listdir", "path": str(B1 / "d00" / "s00")}]
    return ts


def b1_group(R):
    rec = load("setup.json")
    g, cg = rec["sids"][GROUP], rec["sids"][CODEX_GROUP]
    sample = b1_sample()
    prot = [B1 / "d00" / "prot" / "p.txt"]
    out = {"tree": {"build_seconds": rec.get("b1_build_seconds"), "sample_paths": len(sample)}, "trials": []}
    out["tree"]["sample_before"] = inherited_count(sample, [g, cg])

    def attach(method):
        if method == "setnamed":
            SU.grant(B1, [(g, SU.READ_EXEC), (cg, SU.READ_EXEC)])
            return None
        r = subprocess.run(["icacls", str(B1), "/grant", f"*{g}:(OI)(CI)RX", f"*{cg}:(OI)(CI)RX"], capture_output=True)
        return {"exit": r.returncode, "stdout": r.stdout.decode("cp949", "replace").strip()[-200:]}

    def detach(method):
        if method == "setnamed":
            revoke(B1, [g, cg])
            return None
        r = subprocess.run(["icacls", str(B1), "/remove:g", f"*{g}", f"*{cg}"], capture_output=True)
        return {"exit": r.returncode, "stdout": r.stdout.decode("cp949", "replace").strip()[-200:]}

    for t in range(1, TRIALS + 1):
        for method in order(("setnamed", "icacls"), t):
            row = {"trial": t, "method": method}
            for step, fn in (("attach", attach), ("detach", detach)):
                t0 = time.monotonic()
                row[f"{step}_tool"] = fn(method)
                row[f"{step}_seconds"] = round(time.monotonic() - t0, 2)
                row[f"{step}_sample_with_ace"] = inherited_count(sample, [g, cg])
                row[f"{step}_protected_with_ace"] = inherited_count(prot, [g, cg])
                row[f"{step}_root_explicit"] = [a for a in dacl_aces(B1) if not a["flags"] & 0x10
                                                and a["sid"] in (g, cg)]
                row[f"{step}_reads"] = {cell: R.trial(cell, f"b1-{cell}-{t}-{method}-{step}", b1_tasks())
                                        for cell in ("X-base", "CX-off")}
            out["trials"].append(row)
            log(f"b1 {t} {method}: attach {row['attach_seconds']} s ({row['attach_sample_with_ace']}/200), "
                f"detach {row['detach_seconds']} s ({row['detach_sample_with_ace']}/200)")
            save_group("b1", out)
    print(save("b1.json", out))


# ---------------------------------------------------------------- run, state, summary
def short(r):
    c = r.get("child")
    if not isinstance(c, dict):
        return f"no child result {r.get('logon') or r.get('child_stdout', '')[:120]}"
    parts = []
    for k, v in c.items():
        if k == "token":
            continue
        if isinstance(v, dict):
            v = v.get("status") or v.get("result") or v.get("open") or v.get("ok") or v.get("exit")
            if isinstance(v, dict):
                v = next(iter(v.values()), v)
        parts.append(f"{k}={str(v)[:28]}")
    return " ".join(parts)[:600]


def run():
    R = Runner()
    groups = os.environ.get("PXA_GROUPS", "a1,a3,b2,c,b1").split(",")
    for name, fn in (("a1", a1_group), ("a3", a3_group), ("b2", b2_group), ("c", c_group), ("b1", b1_group)):
        if name in groups:
            log(f"group {name} start")
            fn(R)
    log("run done")


def state(label):
    names, resume = [], 0
    while True:
        data, _, resume = win32net.NetUserEnum(None, 0, 0, resume)
        names += [d["name"] for d in data]
        if not resume:
            break
    groups, resume = [], 0
    while True:
        data, _, resume = win32net.NetLocalGroupEnum(None, 0, resume)
        groups += [d["name"] for d in data]
        if not resume:
            break
    import winreg
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY_PARENT, 0, winreg.KEY_READ))
        key = "exists"
    except OSError as e:
        key = f"error:{e.winerror}"
    r = subprocess.run(ps("@(Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | Where-Object CommandLine -like "
                          "'*probe-local-proxy.mjs*').Count"), capture_output=True)
    st = {"label": label, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "local_accounts": sorted(names),
          "local_groups": sorted(groups), "measurement_accounts": {n: lookup_sid(n) for n in (SHELL, USER_B)},
          "measurement_group": lookup_sid(GROUP), "test_key": key, "root_exists": ROOT.exists(),
          "proxy_processes": r.stdout.decode().strip(),
          "listening_tcp": len([x for x in UX.tcp_rows() if x[0] == "LISTEN"])}
    for n in ("CodexSandboxOffline", "CodexSandboxOnline"):
        try:
            st.setdefault("codex_last_logon", {})[n] = win32net.NetUserGetInfo(None, n, 2)["last_logon"]
        except win32net.error as e:
            st.setdefault("codex_last_logon", {})[n] = f"error:{e.winerror}"
    try:
        st["codex"] = UX.codex_state()
    except OSError as e:
        st["codex"] = f"error:{e}"
    r = subprocess.run(ps("@(Get-NetFirewallRule).Count"), capture_output=True, timeout=120)
    st["firewall_rule_count"] = r.stdout.decode().strip()
    r = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True)
    st["process_count"] = len(r.stdout.splitlines())
    print(save(f"state-{label}.json", st))


def summary():
    """Counts per cell and task from the group JSON files (prints; writes summary.json)."""
    from collections import Counter

    def outcome(v):
        if not isinstance(v, dict):
            return str(v)[:40]
        if "status" in v and isinstance(v["status"], str):
            s = v["status"].split(" ")[1] if v["status"].startswith("HTTP/") else v["status"]
            if v.get("proxy_authenticate"):
                s += "+PA"
            if "body_ok" in v:
                s += "+body" if v["body_ok"] else "-body"
            if isinstance(v.get("tls"), dict):
                t = v["tls"]
                s += f" tls:{(t.get('status') or t.get('error', ''))[9:12] or t.get('error', '')[:30]}{'+body' if t.get('body_ok') else ''}"
            return s
        if "status" in v:
            return f"{v['status']}{'+body' if v.get('body_ok') else '-body'}"
        if "error" in v:
            return v["error"][:40]
        if "open" in v:
            return v["open"] + ("" if "value_match" not in v else ("+match" if v["value_match"] else "-match"))
        if "ok" in v:
            return "ok" if v["ok"] else f"fail:exit={v.get('exit')}"
        if "result" in v:
            r = v["result"]
            return ("match" if r.get("match") else "nomatch") if isinstance(r, dict) and "match" in r else \
                (f"entries={r.get('entries')}" if isinstance(r, dict) else str(r))
        if "port_pid_match" in v:
            return f"listed={v['port_listed']} pid={v['port_pid_match']} loopback_listeners={v['loopback_listeners']}"
        return json.dumps(v)[:60]

    out = {}
    for g in ("a1", "a3", "b2", "c"):
        p = LOCAL / f"{g}.json"
        if not p.exists():
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        res = {}
        for cell, rs in d["trials"].items():
            cnt = {}
            for r in rs:
                c = r.get("child") or {}
                for k, v in c.items():
                    if k == "token":
                        v = f"restricted={v.get('is_token_restricted')}"
                    cnt.setdefault(k, Counter())[outcome(v) if k != "token" else v] += 1
                if "proxy_picks" in r:
                    cnt.setdefault("proxy_picks", Counter())[r["proxy_picks"]] += 1
                if not c:
                    cnt.setdefault("no_child", Counter())[r.get("logon") or r.get("child_stderr", "")[:60]] += 1
            res[cell] = {k: dict(v) for k, v in cnt.items()}
        if g == "a3":
            mal = {}
            for tr in d["malformed"]:
                for k, v in tr["cases"].items():
                    m = mal.setdefault(k, Counter())
                    m[f"{outcome(v)} picks={v['picks']} alive={v['alive']} probe={str(v['probe_without_header'])[9:12]}"] += 1
                mal.setdefault("final_correct_relay", Counter())[outcome(tr["final_correct_relay"])] += 1
                mal.setdefault("alive_at_end", Counter())[tr["alive_at_end"]] += 1
            res["malformed"] = {k: dict(v) for k, v in mal.items()}
        if "proxy" in d:
            res["proxy"] = {"events": d["proxy"].get("events"), "stop": d["proxy"].get("stop")}
        out[g] = res
    p = LOCAL / "b1.json"
    if p.exists():
        d = json.loads(p.read_text(encoding="utf-8"))
        rows = []
        reads = {}
        for row in d["trials"]:
            rows.append({k: row[k] for k in ("trial", "method", "attach_seconds", "detach_seconds",
                                             "attach_sample_with_ace", "detach_sample_with_ace",
                                             "attach_protected_with_ace", "detach_protected_with_ace")}
                        | {"attach_root_explicit": len(row["attach_root_explicit"]),
                           "detach_root_explicit": len(row["detach_root_explicit"])})
            for step in ("attach", "detach"):
                for cell, r in row[f"{step}_reads"].items():
                    for k, v in (r.get("child") or {"no_child": r.get("logon")}).items():
                        reads.setdefault(f"{row['method']}/{step}/{cell}", {}).setdefault(k, Counter())[outcome(v)] += 1
        out["b1"] = {"tree": d["tree"], "rows": rows,
                     "reads": {k: {t: dict(c) for t, c in v.items()} for k, v in reads.items()}}
    print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
    save("summary.json", out)


if __name__ == "__main__":
    step = sys.argv[1]
    if step == "state":
        state(sys.argv[2])
    else:
        {"prep": prep, "acl": acl, "run": run, "cleanup": cleanup, "summary": summary}[step]()
