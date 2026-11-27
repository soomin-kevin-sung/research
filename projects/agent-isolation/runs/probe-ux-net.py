"""Recycle bin, clipboard, in-PC connections, shared folders and BITS for the separate-account Restricted Token
shell (runs/2026-11-27-01.md). Requested by another session that is moving its shell to the Codex elevated
structure. Host side, run with the test venv Python. Data goes to local/2026-11-27-ux.

Usage: python probe-ux-net.py prep | acl | run | state <label> | cleanup | summary
  prep     before the UAC step. Creates %USERPROFILE%\\agent-isolation-ux (not directly under C:\\):
             tools\\     test Python (copy of the venv base, stdlib only), child.py, launcher.py, ux_child.py;
                        Users read and run
             secrets\\ux.json   random password of the measurement account; user and SYSTEM only
             rt\\{ws, temp, out, specs, rb}   user, SYSTEM, Administrators (acl adds the account). rb is the folder
                        the user "allowed": the account gets modify on it
             share\\     hello.txt for the temporary share iso-ux-share (Users read)
             codex\\{ws, temp}   workspace of the `codex sandbox` cells
           and a random capability SID in the Codex format.
  acl      after the account exists: account read and run on rt, modify on ws, temp, out, rb.
  run      groups (UX_GROUPS, default clip,rb,net; UX_TRIALS, default 5)
    clip   cells X-base, X-none, X-job, CX-off, alternating per trial. The host puts a random marker text on the
           clipboard; the shell reads it (Python, Get-Clipboard) and writes three markers (Set-Clipboard, clip.exe,
           Python); after each write the host reads the clipboard. The user's clipboard text is saved in memory
           first and put back at the end (other formats are not kept); its content is never logged.
    rb     RB_ORDER, 5 trials each in that order (the first deletion that reaches the bin creates the account's
           recycle bin folder, so the order is part of the result). Per trial the host creates three files in rb;
           the shell sends one to the recycle bin with SHFileOperationW, one with the VisualBasic DeleteFile,
           and removes one with Remove-Item; the host then checks its own Explorer recycle bin
           (Shell.Application namespace 10, our names and the item count only) and the account's bin folder; the
           shell empties its recycle bin (guarded: skipped if it can list the user's).
           The first full run (local/.../run1-stale-markers) had X-base, X-none and X-base again, all with logon
           flags 0 and VisualBasic only after a SHFileOperationW item reached the bin; no item did.
    net    cells CX-off, X-base, X-none, host, alternating per trial. Host HTTP servers on 127.0.0.1, ::1 and the
           PC's LAN address (answer only clients with this PC's addresses) and a TCP table poller (owner PIDs of
           connections to 192.0.2.1, example.com and SMB ports). The shell runs: HTTPS to example.com (blocked
           check), curl / Invoke-WebRequest / Python to the three host servers, its own loopback listeners for the
           host to connect to, TCP to port 445 (loopback, LAN address, 192.0.2.1), \\\\localhost\\iso-ux-share and
           \\\\<LAN address>\\iso-ux-share, \\\\localhost\\C$, \\\\192.0.2.1\\iso (documentation address, no host
           answers), \\\\example.com@SSL\\DavWWWRoot (WebDAV through the WebClient service), and BITS downloads of
           https://example.com/ with Start-BitsTransfer and bitsadmin. The host cell skips 192.0.2.1 and WebDAV.
  Cells    X-base  measurement account (CreateProcessWithLogonW, flags 0), Codex-style WRITE_RESTRICTED token
                   (launcher "base": capability SID, account, logon SID, Everyone), WinSta0\\Default
           X-none  same account, unrestricted copy of its logon token
           X-job   as X-base inside a Job with JOB_OBJECT_UILIMIT_READCLIPBOARD | WRITECLIPBOARD
           P-base, P-none  as X-base, X-none with LOGON_WITH_PROFILE (rb only; creates the account's profile)
           P-base2, X-base2, X-none2  the same cells again after the account's recycle bin folder exists (rb only)
           CX-off  installed Codex CLI `codex sandbox`, windows.sandbox="elevated", network disabled
                   (CodexSandboxOffline with Codex's firewall rules and WFP filters)
           host    the current user, no sandbox
  Each trial first deletes stage files left by an earlier run with the same tag (the first full run reused the
  smoke check's tags, so the host answered stale stage files in trial 1; that run is kept apart).
  state    non-admin PC state.
  cleanup  after the admin cleanup: deletes %USERPROFILE%\\agent-isolation-ux.
Only example.com and 192.0.2.1 are contacted outside the PC; no SMB connection to another host is made.
"""
import os
import sys
import json
import time
import ctypes
import random
import shutil
import socket
import struct
import threading
import subprocess
import http.server
import importlib.util
from ctypes import wintypes
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-27-ux")
os.environ.setdefault("ISO_ROOT", str(Path(os.environ["USERPROFILE"]) / "agent-isolation-ux"))
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, TOOLS, PYRT, PY, CHILD, LOCAL, CODEX, REAL_CODEX_HOME, token_sids,  # noqa: E402
                                   lookup_sid, icacls, protect, dacl_aces, save, load, parse_isojson, sha256)

import win32net  # noqa: E402
import win32service  # noqa: E402

ACCOUNT = "iso-rt-ux1"
RT = ROOT / "rt"
WS, TEMP, OUT, SPECS, RB = RT / "ws", RT / "temp", RT / "out", RT / "specs", RT / "rb"
SHARE, SHARE_NAME, SHARE_TEXT = ROOT / "share", "iso-ux-share", "iso-share-ok"
CXWS, CXTEMP = ROOT / "codex" / "ws", ROOT / "codex" / "temp"
LAUNCHER, UXCHILD = TOOLS / "launcher.py", TOOLS / "ux_child.py"
SECRETS = ROOT / "secrets" / "ux.json"
TESTNET, URL, EXAMPLE = "192.0.2.1", "https://example.com/", "example.com"
CURL = r"C:\Windows\System32\curl.exe"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
BITSADMIN = r"C:\Windows\System32\bitsadmin.exe"
TRIALS = int(os.environ.get("UX_TRIALS", "5"))
# account cells: (kind, launcher mode, Job UI limits, CreateProcessWithLogonW logon flags)
CELLS = {"X-base": ("account", "base", 0, 0), "X-none": ("account", "none", 0, 0), "X-job": ("account", "base", 0x6, 0),
         "P-base": ("account", "base", 0, 1), "P-none": ("account", "none", 0, 1), "P-base2": ("account", "base", 0, 1),
         "X-base2": ("account", "base", 0, 0), "X-none2": ("account", "none", 0, 0),
         "CX-off": ("codex",), "host": ("host",)}
RB_ORDER = ("X-base", "X-none", "P-base", "P-none", "P-base2", "X-base2", "X-none2")
SERVICES = ("BITS", "WebClient", "Dnscache", "LanmanWorkstation", "LanmanServer")


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


def ps(script):
    return [PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]


def oserr(e):
    return f"error:{getattr(e, 'winerror', None) or e.errno or type(e).__name__}"


def lan_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # route lookup only, UDP connect sends nothing
    s.connect((TESTNET, 9))
    a = s.getsockname()[0]
    s.close()
    return a


def services():
    out = {}
    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    for n in SERVICES:
        try:
            h = win32service.OpenService(scm, n, win32service.SERVICE_QUERY_STATUS)
            st = win32service.QueryServiceStatusEx(h)
            win32service.CloseServiceHandle(h)
            out[n] = {"state": st["CurrentState"], "pid": st["ProcessId"]}
        except win32service.error as e:
            out[n] = f"error:{e.winerror}"
    win32service.CloseServiceHandle(scm)
    return out


# ---------------------------------------------------------------- prep, acl, cleanup
def prep():
    if ROOT.exists():
        sys.exit(f"{ROOT} already exists; refusing to overwrite")
    setup = importlib.util.spec_from_file_location("setup", Path(__file__).with_name("probe-rt-reduced-setup.py"))
    S = importlib.util.module_from_spec(setup)
    setup.loader.exec_module(S)
    user_sid, logon_sid = token_sids()
    rec = {"user_sid": user_sid, "logon_sid": logon_sid, "account": ACCOUNT, "lan": lan_address(),
           "services_before": services(),
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
    shutil.copy2(here / "probe-ux-net-child.py", UXCHILD)
    icacls(TOOLS, "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F",
           "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")
    (ROOT / "secrets").mkdir()
    icacls(ROOT / "secrets", "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
    SECRETS.write_text(json.dumps({ACCOUNT: S.password()}), encoding="utf-8")
    RT.mkdir()
    protect(RT, user_sid)
    for d in (WS, TEMP, OUT, SPECS, RB):
        d.mkdir()
    SHARE.mkdir()
    icacls(SHARE, "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F",
           "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")
    (SHARE / "hello.txt").write_text(SHARE_TEXT, encoding="utf-8")
    for d in (CXWS, CXTEMP):
        d.mkdir(parents=True)
    rec["dacl_prep"] = {str(p): dacl_aces(p) for p in [ROOT, TOOLS, ROOT / "secrets", RT, *RT.iterdir(), SHARE]}
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
    for d in (WS, TEMP, OUT, RB):
        S.grant(d, [(sid, S.MODIFY)])
    rec["account_sid"] = sid
    rec["dacl_acl"] = {str(p): dacl_aces(p) for p in [ROOT, RT, *RT.iterdir()]}
    print(save("setup.json", rec))


def cleanup():
    if lookup_sid(ACCOUNT):
        sys.exit(f"{ACCOUNT} still exists; run the admin cleanup first")
    shutil.rmtree(ROOT)
    print("removed", ROOT, "exists:", ROOT.exists())


# ---------------------------------------------------------------- host-side observations
EXPLORER_PS = ("$s = New-Object -ComObject Shell.Application; $items = @($s.Namespace(10).Items()); "
               "'total=' + $items.Count; foreach ($i in $items) { if ($i.Name -like 'iso-rb-*') { 'item=' + $i.Name } }")


def explorer_view():
    r = subprocess.run(ps(EXPLORER_PS), capture_output=True, timeout=120)
    out = {"total": None, "iso_items": []}
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("total="):
            out["total"] = int(line[6:])
        elif line.startswith("item="):
            out["iso_items"].append(line[5:])
    if r.returncode:
        out["error"] = r.stderr.decode("utf-8", "replace")[-300:]
    return out


def host_listdir(path):
    try:
        return {"entries": len(os.listdir(path))}
    except OSError as e:
        return oserr(e)


def recycle_root():
    try:
        names = os.listdir("C:\\$Recycle.Bin")
    except OSError as e:
        return oserr(e)
    return names


def bits_user_jobs():
    r = subprocess.run(ps("$j = @(Get-BitsTransfer); 'total=' + $j.Count; "
                          "'iso=' + @($j | Where-Object DisplayName -like 'iso-ux-*').Count"), capture_output=True, timeout=60)
    return r.stdout.decode("utf-8", "replace").split()


TCP_STATES = {1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED", 6: "FIN_WAIT1",
              7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}
iph = ctypes.WinDLL("iphlpapi")
iph.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL, wintypes.ULONG,
                                    ctypes.c_int, wintypes.ULONG]
hk32 = ctypes.WinDLL("kernel32", use_last_error=True)
hk32.OpenProcess.restype = wintypes.HANDLE
hk32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
hk32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                            ctypes.POINTER(wintypes.DWORD)]
hk32.CloseHandle.argtypes = [wintypes.HANDLE]


def tcp_rows():
    rows = []
    for af in (2, 23):
        size = wintypes.DWORD(0)
        iph.GetExtendedTcpTable(None, ctypes.byref(size), False, af, 5, 0)  # TCP_TABLE_OWNER_PID_ALL
        buf = ctypes.create_string_buffer(size.value + 8192)
        size = wintypes.DWORD(len(buf))
        if iph.GetExtendedTcpTable(buf, ctypes.byref(size), False, af, 5, 0):
            continue
        n = struct.unpack_from("<I", buf, 0)[0]
        for i in range(n):
            if af == 2:
                st, la, lp, ra, rp, pid = struct.unpack_from("<6I", buf, 4 + 24 * i)
                rows.append((TCP_STATES.get(st, st), socket.inet_ntoa(struct.pack("<I", la)), socket.ntohs(lp & 0xffff),
                             socket.inet_ntoa(struct.pack("<I", ra)), socket.ntohs(rp & 0xffff), pid))
            else:
                off = 4 + 56 * i
                la, ra = bytes(buf[off:off + 16]), bytes(buf[off + 24:off + 40])
                lp = struct.unpack_from("<I", buf, off + 20)[0]
                rp, st, pid = struct.unpack_from("<3I", buf, off + 44)
                rows.append((TCP_STATES.get(st, st), socket.inet_ntop(socket.AF_INET6, la), socket.ntohs(lp & 0xffff),
                             socket.inet_ntop(socket.AF_INET6, ra), socket.ntohs(rp & 0xffff), pid))
    return rows


def pid_name(pid, svc):
    if pid == 4:
        return "System"
    hosted = [n for n, v in svc.items() if isinstance(v, dict) and v.get("pid") == pid]
    if hosted:
        return "svchost:" + "+".join(hosted)
    h = hk32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return f"unopenable:{ctypes.get_last_error()}"
    buf = ctypes.create_unicode_buffer(520)
    n = wintypes.DWORD(520)
    ok = hk32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n))
    hk32.CloseHandle(h)
    return Path(buf.value).name if ok else "noname"


class Poller(threading.Thread):
    """Connections to 192.0.2.1 or example.com and SMB (445, 139) connections to this PC, with the owner process."""

    def __init__(self, remotes, local_addrs):
        super().__init__(daemon=True)
        self.remotes, self.local_addrs = set(remotes), set(local_addrs)
        self.stop, self.seen, self.t0 = threading.Event(), {}, time.monotonic()

    def run(self):
        svc, last = services(), 0.0
        while not self.stop.is_set():
            now = time.monotonic()
            if now - last > 1.0:
                svc, last = services(), now
            for r in tcp_rows():
                st, la, lp, ra, rp, pid = r
                if r[0] == "LISTEN":
                    continue
                hit = ra in self.remotes or (rp in (445, 139) and ra in self.local_addrs)
                if hit and r not in self.seen:
                    self.seen[r] = {"t": round(now - self.t0, 2), "state": st, "local": f"{la}:{lp}",
                                    "remote": f"{ra}:{rp}", "owner": pid_name(pid, svc)}
            time.sleep(0.1)

    def result(self):
        self.stop.set()
        self.join(5)
        return list(self.seen.values())


# ---------------------------------------------------------------- host HTTP servers (net group)
HTTP_LOG = []


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        HTTP_LOG.append({"t": time.time(), "server": self.server.server_address[0], "client": self.client_address[0],
                         "path": self.path})
        body = b"iso-host-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def start_servers(lan):
    allowed = {"127.0.0.1", "::1", lan, "::ffff:127.0.0.1", f"::ffff:{lan}"}

    class Srv(http.server.ThreadingHTTPServer):
        daemon_threads = True

        def verify_request(self, request, client_address):
            ok = client_address[0] in allowed
            if not ok:
                HTTP_LOG.append({"t": time.time(), "server": self.server_address[0], "client": "other", "refused": True})
            return ok

    class Srv6(Srv):
        address_family = socket.AF_INET6

    for _ in range(50):
        port = random.randrange(41000, 49000)
        made = []
        try:
            for cls, addr in ((Srv, "127.0.0.1"), (Srv6, "::1"), (Srv, lan)):
                made.append(cls((addr, port), Handler))
        except OSError:
            for s in made:
                s.server_close()
            continue
        for s in made:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        return port, made
    raise SystemExit("no free port for the host servers")


# ---------------------------------------------------------------- clipboard (host)
def clip_helpers():
    U = tools_module("ux_child", UXCHILD)

    def get_text():
        hwnd = U.msg_window()
        e = U.clip_open(hwnd)
        if e:
            return {"kind": "open_error", "error": e}, None
        try:
            formats = U.u32.CountClipboardFormats()
            h = U.u32.GetClipboardData(U.CF_UNICODETEXT)
            if not h:
                return {"kind": "no_text", "formats": formats}, None
            p = U.k32.GlobalLock(h)
            s = ctypes.wstring_at(p) if p else None
            U.k32.GlobalUnlock(h)
            return {"kind": "text", "formats": formats}, s
        finally:
            U.u32.CloseClipboard()
            U.u32.DestroyWindow(hwnd)

    def empty():
        hwnd = U.msg_window()
        e = U.clip_open(hwnd)
        if e:
            return e
        r = "ok" if U.u32.EmptyClipboard() else U.err()
        U.u32.CloseClipboard()
        U.u32.DestroyWindow(hwnd)
        return r
    return U, get_text, empty


# ---------------------------------------------------------------- launching
def codex_argv(spec):
    prof = '{":root"="read", ":tmpdir"="write", ":workspace_roots"={"."="write"}}'
    return [str(CODEX), "sandbox", "-c", 'windows.sandbox="elevated"', "-c", f"permissions.iso.filesystem={prof}",
            "-c", "permissions.iso.network.enabled=false", "-P", "iso", "-C", str(CXWS), "--",
            str(PY), "-I", "-B", str(UXCHILD), str(spec)]


def codex_env():
    env = os.environ.copy()
    env.pop("CODEX_WINDOWS_REGISTERED_CORE", None)
    env.update(CODEX_HOME=str(REAL_CODEX_HOME), TEMP=str(CXTEMP), TMP=str(CXTEMP))
    return env


def read_text(p, n=3000):
    try:
        return Path(p).read_bytes().decode("utf-8", "replace")[-n:]
    except OSError as e:
        return f"read_error:{e}"


def drive(stages, alive, rec, timeout=300):
    """Answers the shell's stage files: waits for stage["wait"], runs stage["do"](), writes stage["go"]."""
    for st in stages:
        end = time.monotonic() + timeout
        while not Path(st["wait"]).exists():
            if not alive() or time.monotonic() > end:
                rec[st["id"]] = "no_stage"
                return
            time.sleep(0.1)
        try:
            rec[st["id"]] = st["do"]()
        except Exception as e:  # noqa: BLE001
            rec[st["id"]] = f"exception:{type(e).__name__}:{e}"
        if st.get("go"):
            Path(st["go"]).write_text("1", encoding="utf-8")


class Runner:
    def __init__(self):
        self.L = tools_module("launcher", LAUNCHER)
        L, adv = self.L, self.L.adv
        adv.CreateProcessWithLogonW.restype = wintypes.BOOL
        adv.CreateProcessWithLogonW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                                wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, ctypes.c_void_p,
                                                wintypes.LPCWSTR, ctypes.POINTER(L.STARTUPINFOW),
                                                ctypes.POINTER(L.PROCESS_INFORMATION)]
        self.rec = load("setup.json")
        self.sid = lookup_sid(ACCOUNT)
        if not self.sid or self.rec.get("account_sid") != self.sid:
            sys.exit("account missing or acl not run")
        self.pw = json.loads(SECRETS.read_text(encoding="utf-8"))[ACCOUNT]

    @staticmethod
    def mdir(cell):
        return CXWS if CELLS[cell][0] == "codex" else OUT

    def trial(self, cell, tag, tasks, stages, timeout=900):
        kind = CELLS[cell]
        d = self.mdir(cell)
        for old in [*d.glob(f"{tag}-*"), *SPECS.glob(f"{tag}-*")]:  # stage files of an earlier run with the same tag
            old.unlink()
        sp = (CXWS if kind[0] == "codex" else SPECS) / f"{tag}-child.json"
        sp.write_text(json.dumps({"tag": tag, "out": str(d / f"{tag}-child.json"), "tasks": tasks}), encoding="utf-8")
        r, staged = {"cell": cell, "tag": tag}, {}
        t0 = time.monotonic()
        if kind[0] == "account":
            L, k32 = self.L, self.L.k32
            _, mode, job_ui, logon_flags = kind
            r["logon_flags"] = logon_flags
            launch = {"id": "child", "argv": [str(PY), "-I", "-B", str(UXCHILD), str(sp)],
                      "stdout": str(OUT / f"{tag}-child.out"), "stderr": str(OUT / f"{tag}-child.err"),
                      "timeout": timeout}
            if job_ui:
                launch["job_ui"] = job_ui
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
            ok = L.adv.CreateProcessWithLogonW(ACCOUNT, ".", self.pw, logon_flags, str(PY), cmd, 0x08000000 | 0x400, None,
                                               str(WS), ctypes.byref(si), ctypes.byref(pi))
            e = ctypes.get_last_error()
            k32.SetErrorMode(previous)
            if not ok:
                r["logon"] = f"error:{e}"
                return r
            th = threading.Thread(target=drive, args=(stages, lambda: k32.WaitForSingleObject(pi.hProcess, 0) == 0x102,
                                                       staged), daemon=True)
            th.start()
            w = k32.WaitForSingleObject(pi.hProcess, (timeout + 60) * 1000)
            code = wintypes.DWORD()
            k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
            if w == 0x102:
                k32.TerminateProcess(pi.hProcess, 1)
            r["launcher_exit"] = "timeout" if w == 0x102 else f"0x{code.value:08x}"
            k32.CloseHandle(pi.hThread)
            k32.CloseHandle(pi.hProcess)
            th.join(10)
            try:
                r["launcher"] = json.loads((OUT / f"{tag}-launcher.json").read_text(encoding="utf-8"))
                r["launcher"].pop("launcher_process_sd", None)
            except (OSError, ValueError) as ex:
                r["launcher"] = f"read_error:{ex}"
            text, err_text = read_text(OUT / f"{tag}-child.out", 400000), read_text(OUT / f"{tag}-child.err", 800)
        else:
            if kind[0] == "codex":
                argv, env, cwd = codex_argv(sp), codex_env(), CXWS
            else:
                argv, cwd = [str(PY), "-I", "-B", str(UXCHILD), str(sp)], WS
                env = {**os.environ, "TEMP": str(TEMP), "TMP": str(TEMP)}
            p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            th = threading.Thread(target=drive, args=(stages, lambda: p.poll() is None, staged), daemon=True)
            th.start()
            try:
                so, se = p.communicate(timeout=timeout + 60)
                r["exit"] = p.returncode
            except subprocess.TimeoutExpired:
                p.kill()
                so, se = p.communicate()
                r["exit"] = "timeout"
            th.join(10)
            text, err_text = so.decode("utf-8", "replace"), se.decode("utf-8", "replace")[-800:]
        r["seconds"] = round(time.monotonic() - t0, 1)
        r["child"] = parse_isojson(text)
        if r["child"] is None:
            r["child_stdout"], r["child_stderr"] = text[-800:], err_text
        r["stages"] = staged
        return r


# ---------------------------------------------------------------- groups
def clip_group(R, trials):
    U, get_text, empty = clip_helpers()
    saved_meta, saved = get_text()
    out = {"saved": saved_meta, "trials": {}}
    cells = ("X-base", "X-none", "X-job", "CX-off")
    try:
        for t in range(1, trials + 1):
            for cell in cells:
                tag = f"clip-{cell}-{t}"
                d = R.mdir(cell)
                m = {i: f"iso-clip-{i}-{random.SystemRandom().randrange(16**8):08x}" for i in range(4)}
                log(f"clip {cell} trial {t}")
                pre = U.clip_write({"data": m[0]})
                ps_read = ("try { $t = Get-Clipboard -Raw; if ($null -eq $t) { 'read=none' } elseif ($t.Trim() -eq '"
                           + m[0] + "') { 'read=match' } elseif ($t.Trim() -eq '') { 'read=empty' } else "
                           "{ 'read=other:len=' + $t.Length } } catch { 'error=' + $_.Exception.GetType().FullName + "
                           "': ' + $_.Exception.Message; exit 1 }")
                ps_write = ("try { Set-Clipboard -Value '" + m[1] + "'; 'set=ok' } catch { 'error=' + "
                            "$_.Exception.GetType().FullName + ': ' + $_.Exception.Message; exit 1 }")
                tasks = [{"id": "token", "kind": "token"}, {"id": "winsta", "kind": "winsta"},
                         {"id": "read_py", "kind": "clip_read", "expect": m[0]},
                         {"id": "read_ps", "kind": "run", "argv": ps(ps_read), "timeout": 60, "ok_if": "read=match"},
                         {"id": "write_ps", "kind": "run", "argv": ps(ps_write), "timeout": 60},
                         {"id": "s1", "kind": "mark", "path": str(d / f"{tag}-s1")},
                         {"id": "g1", "kind": "wait", "path": str(d / f"{tag}-g1"), "timeout": 60},
                         {"id": "write_clipexe", "kind": "run", "argv": [CMD, "/d", "/c", f"echo {m[2]}| clip.exe"],
                          "timeout": 60},
                         {"id": "s2", "kind": "mark", "path": str(d / f"{tag}-s2")},
                         {"id": "g2", "kind": "wait", "path": str(d / f"{tag}-g2"), "timeout": 60},
                         {"id": "write_py", "kind": "clip_write", "data": m[3]},
                         {"id": "s3", "kind": "mark", "path": str(d / f"{tag}-s3")},
                         {"id": "g3", "kind": "wait", "path": str(d / f"{tag}-g3"), "timeout": 60}]
                stages = [{"id": f"host_after_{w}", "wait": str(d / f"{tag}-{s}"), "go": str(d / f"{tag}-{g}"),
                           "do": (lambda mm=m[i]: U.clip_read({"expect": mm}))}
                          for s, g, w, i in (("s1", "g1", "ps", 1), ("s2", "g2", "clipexe", 2), ("s3", "g3", "py", 3))]
                r = R.trial(cell, tag, tasks, stages, timeout=300)
                r["host_set"] = pre
                out["trials"].setdefault(cell, []).append(r)
                save("clip-partial.json", out)
    finally:
        if saved_meta.get("kind") == "text":
            out["restore"] = U.clip_write({"data": saved})
        elif saved_meta.get("kind") == "no_text":
            out["restore"] = {"emptied": empty(), "note": "clipboard had no text; non-text formats are not restored"}
        else:
            out["restore"] = "not_saved"
        saved = None
    save("clip.json", out)
    return out


def rb_group(R, trials, user_sid):
    acct_bin = Path("C:\\$Recycle.Bin") / R.sid
    out = {"account_bin_before": acct_bin.exists(), "order": RB_ORDER, "trials": {}}
    for cell in RB_ORDER:
        for t in range(1, trials + 1):
            tag = f"rb-{cell}-{t}"
            d = R.mdir(cell)
            files = {m: RB / f"iso-rb-{cell}-{t}-{m}.txt" for m in ("sh", "vb", "rm")}
            for f in files.values():
                f.write_text("iso-rb", encoding="utf-8")
            log(f"rb {cell} trial {t}")
            vb = ("try { Add-Type -AssemblyName Microsoft.VisualBasic; [Microsoft.VisualBasic.FileIO.FileSystem]::"
                  f"DeleteFile('{files['vb']}', 'OnlyErrorDialogs', 'SendToRecycleBin'); 'vb=ok' }} catch {{ 'error=' + "
                  "$_.Exception.GetType().FullName + ': ' + $_.Exception.Message; exit 1 }")
            rm = (f"try {{ Remove-Item -LiteralPath '{files['rm']}' -ErrorAction Stop; 'rm=ok' }} catch {{ 'error=' + "
                  "$_.Exception.GetType().FullName + ': ' + $_.Exception.Message; exit 1 }")
            tasks = [{"id": "token", "kind": "token"},
                     {"id": "env", "kind": "env", "names": ["USERPROFILE", "APPDATA"]},
                     {"id": "hkcu", "kind": "hkcu_name"},
                     {"id": "bin_before", "kind": "rb_list"},
                     {"id": "rb_sh", "kind": "rb_shfileop", "path": str(files["sh"])},
                     {"id": "bin_after_sh", "kind": "rb_list"},
                     # run unconditionally: SHFileOperationW with no UI returned 0 in every cell of the first run
                     {"id": "rb_vb", "kind": "run", "argv": ps(vb), "timeout": 90},
                     {"id": "rb_rm", "kind": "run", "argv": ps(rm), "timeout": 60},
                     {"id": "exists_after", "kind": "exists", "paths": [str(f) for f in files.values()]},
                     {"id": "bin_after", "kind": "rb_list"},
                     {"id": "s1", "kind": "mark", "path": str(d / f"{tag}-s1")},
                     {"id": "g1", "kind": "wait", "path": str(d / f"{tag}-g1"), "timeout": 120},
                     {"id": "rb_empty", "kind": "rb_empty", "guard_sid": user_sid},
                     {"id": "bin_final", "kind": "rb_list"}]
            stages = [{"id": "host_check", "wait": str(d / f"{tag}-s1"), "go": str(d / f"{tag}-g1"),
                       "do": lambda: {"explorer": explorer_view(), "host_list_account_bin": host_listdir(acct_bin),
                                      "account_bin_exists": acct_bin.exists()}}]
            before = explorer_view()
            r = R.trial(cell, tag, tasks, stages, timeout=300)
            r["user_bin_total_before"], r["user_bin_after"] = before["total"], explorer_view()
            r["account_bin_exists_after"] = acct_bin.exists()
            r["profile_dir_exists"] = Path(r"C:\Users", ACCOUNT).exists()
            out["trials"].setdefault(cell, []).append(r)
            for f in files.values():
                if f.exists():
                    f.unlink()
            save("rb-partial.json", out)
    save("rb.json", out)
    return out


def net_tasks(d, tag, lan, port, host_cell):
    def url(h, tool):
        return f"http://{h}:{port}/{tag}/{tool}"
    tasks = [{"id": "token", "kind": "token"},
             {"id": "direct_https", "kind": "http", "url": URL, "expect": "Example Domain", "timeout": 10}]
    for name, h in (("v4", "127.0.0.1"), ("v6", "[::1]"), ("lan", lan)):
        tasks += [{"id": f"curl_{name}", "kind": "run", "ok_if": "http=200", "timeout": 30,
                   "argv": [CURL, "-sS", "-o", "NUL", "-w", "http=%{http_code}", "--max-time", "8", "--noproxy", "*",
                            url(h, "curl")]},
                  {"id": f"iwr_{name}", "kind": "run", "ok_if": "status=200", "timeout": 40,
                   "argv": ps("$ProgressPreference='SilentlyContinue'; try { $r = Invoke-WebRequest -UseBasicParsing "
                              f"-Uri '{url(h, 'iwr')}' -TimeoutSec 8; 'status=' + $r.StatusCode }} catch {{ 'error=' + "
                              "$_.Exception.Message; exit 1 }")},
                  {"id": f"py_{name}", "kind": "http", "url": url(h, "py"), "expect": "iso-host-ok", "timeout": 8}]
    tasks += [{"id": "listen", "kind": "listen", "ready": str(d / f"{tag}-ready.json"), "go": str(d / f"{tag}-go"),
               "timeout": 40},
              {"id": "smb_tcp_v4", "kind": "tcp", "host": "127.0.0.1", "port": 445, "timeout": 5},
              {"id": "smb_tcp_lan", "kind": "tcp", "host": lan, "port": 445, "timeout": 5},
              {"id": "unc_share_py", "kind": "readfile", "path": f"\\\\localhost\\{SHARE_NAME}\\hello.txt",
               "expect": SHARE_TEXT, "timeout": 60},
              {"id": "unc_share_cmd", "kind": "run", "ok_if": "hello.txt", "timeout": 60,
               "argv": [CMD, "/d", "/c", "dir", "/b", f"\\\\localhost\\{SHARE_NAME}"]},
              {"id": "unc_share_lan", "kind": "readfile", "path": f"\\\\{lan}\\{SHARE_NAME}\\hello.txt",
               "expect": SHARE_TEXT, "timeout": 60},
              {"id": "unc_admin_share", "kind": "listdir", "path": "\\\\localhost\\C$", "timeout": 60},
              # which account the shell's SMB connections authenticated as (read only, own logon session)
              {"id": "smb_conn", "kind": "run", "timeout": 60,
               "argv": ps("try { Get-SmbConnection -ErrorAction Stop | ForEach-Object { 'conn=' + $_.ServerName + '|' + "
                          "$_.ShareName + '|' + $_.UserName + '|' + $_.Credential + '|' + $_.Dialect } } catch { "
                          "'error=' + $_.Exception.Message; exit 1 }")}]
    if not host_cell:
        # WebDAV: `net use` goes through the WebDAV network provider, which can start the WebClient service
        # (stopped, manual start on this PC); the plain folder open alone did not start it in the smoke check
        tasks += [{"id": "smb_tcp_testnet", "kind": "tcp", "host": TESTNET, "port": 445, "timeout": 5},
                  {"id": "unc_testnet", "kind": "listdir", "path": f"\\\\{TESTNET}\\iso", "timeout": 75},
                  {"id": "webdav_netuse", "kind": "run", "timeout": 90,
                   "argv": [CMD, "/d", "/c", f"net use \\\\{EXAMPLE}@SSL\\DavWWWRoot /persistent:no"]},
                  {"id": "webdav", "kind": "listdir", "path": f"\\\\{EXAMPLE}@SSL\\DavWWWRoot", "timeout": 75},
                  {"id": "webdav_netuse_delete", "kind": "run", "timeout": 30,
                   "argv": [CMD, "/d", "/c", f"net use \\\\{EXAMPLE}@SSL\\DavWWWRoot /delete /y"]}]
    dest_ps, dest_adm = d / f"{tag}-bits-ps.html", d / f"{tag}-bits-adm.html"
    bits_ps = ("$ProgressPreference='SilentlyContinue'; try { Import-Module BitsTransfer -ErrorAction Stop; "
               f"$j = Start-BitsTransfer -Source '{URL}' -Destination '{dest_ps}' -Asynchronous "
               f"-DisplayName 'iso-ux-ps-{tag}' -ErrorAction Stop; $end = (Get-Date).AddSeconds(45); "
               "do { Start-Sleep -Milliseconds 500; $j = Get-BitsTransfer -JobId $j.JobId } "
               "while ((Get-Date) -lt $end -and $j.JobState -notin 'Transferred','Error'); "
               "'state=' + $j.JobState; if ($j.JobState -eq 'Transferred') { Complete-BitsTransfer -BitsJob $j; "
               f"'bytes=' + (Get-Item -LiteralPath '{dest_ps}').Length }} else {{ 'error=' + $j.ErrorDescription; "
               "'context=' + $j.ErrorContext; 'condition=' + $j.ErrorCondition; Remove-BitsTransfer -BitsJob $j } "
               "} catch { 'exception=' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message; exit 1 }")
    tasks += [{"id": "bits_ps", "kind": "run", "argv": ps(bits_ps), "timeout": 90, "ok_if": "state=Transferred"},
              {"id": "bits_admin", "kind": "run", "timeout": 60,
               "argv": [BITSADMIN, "/transfer", f"iso-ux-adm-{tag}", "/download", "/priority", "FOREGROUND", URL,
                        str(dest_adm)]},
              {"id": "bits_files", "kind": "exists", "paths": [str(dest_ps), str(dest_adm)]},
              {"id": "bits_cancel_adm", "kind": "run", "timeout": 30, "argv": [BITSADMIN, "/cancel", f"iso-ux-adm-{tag}"]},
              {"id": "bits_left", "kind": "run", "timeout": 60,
               "argv": ps("try { $j = @(Get-BitsTransfer | Where-Object DisplayName -like 'iso-ux-*'); "
                          "$j | Remove-BitsTransfer; 'removed=' + $j.Count; 'left=' + "
                          "@(Get-BitsTransfer | Where-Object DisplayName -like 'iso-ux-*').Count } catch { 'error=' + "
                          "$_.Exception.Message; exit 1 }")}]
    return tasks


def connect_shell(ready):
    try:
        ports = json.loads(Path(ready).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return f"read_error:{e}"
    res = {}
    for addr, p in ports.items():
        if not isinstance(p, int):
            res[addr] = {"result": "not_bound", "detail": p}
            continue
        t0 = time.monotonic()
        try:
            s = socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((addr, p))
            s.sendall(b"iso-host-ping")
            res[addr] = {"result": "ok", "reply": s.recv(64).decode("utf-8", "replace")}
            s.close()
        except socket.timeout:
            res[addr] = {"result": "timeout"}
        except OSError as e:
            res[addr] = {"result": oserr(e)}
        res[addr]["seconds"] = round(time.monotonic() - t0, 2)
    return res


def net_group(R, trials, lan):
    try:
        ex = sorted({a[4][0] for a in socket.getaddrinfo(EXAMPLE, 443, proto=socket.IPPROTO_TCP)})
    except OSError:
        ex = []
    port, servers = start_servers(lan)
    out = {"port": port, "example_addresses": len(ex), "trials": {}}
    try:
        for t in range(1, trials + 1):
            for cell in ("CX-off", "X-base", "X-none", "host"):
                tag = f"net-{cell}-{t}"
                d = R.mdir(cell)
                log(f"net {cell} trial {t}")
                stages = [{"id": "host_connect", "wait": str(d / f"{tag}-ready.json"), "go": str(d / f"{tag}-go"),
                           "do": lambda dd=d, tg=tag: connect_shell(dd / f"{tg}-ready.json")}]
                n0 = len(HTTP_LOG)
                svc_before = {k: (v.get("state") if isinstance(v, dict) else v) for k, v in services().items()}
                poller = Poller([TESTNET, *ex], ["127.0.0.1", "::1", lan])
                poller.start()
                r = R.trial(cell, tag, net_tasks(d, tag, lan, port, cell == "host"), stages, timeout=900)
                r["tcp_seen"] = poller.result()
                r["http_log"] = [{k: v for k, v in e.items() if k != "t"} for e in HTTP_LOG[n0:]]
                r["services_before"] = svc_before
                r["services_after"] = {k: (v.get("state") if isinstance(v, dict) else v) for k, v in services().items()}
                out["trials"].setdefault(cell, []).append(r)
                save("net-partial.json", out)
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()
    out["http_refused_other_clients"] = sum(1 for e in HTTP_LOG if e.get("refused"))
    save("net.json", out)
    return out


def run():
    R = Runner()
    groups = os.environ.get("UX_GROUPS", "clip,rb,net").split(",")
    rec = load("setup.json")
    user_sid = rec["user_sid"]
    if "clip" in groups:
        clip_group(R, TRIALS)
    if "rb" in groups:
        rb_group(R, TRIALS, user_sid)
    if "net" in groups:
        net_group(R, TRIALS, rec["lan"])
    log("run done")


# ---------------------------------------------------------------- state
def codex_state():
    h = REAL_CODEX_HOME
    st = {"config_sha": sha256(h / "config.toml"), "cap_sid_size": (h / "cap_sid").stat().st_size}
    try:
        cap = json.loads((h / "cap_sid").read_text())
        st["cap_sid_counts"] = {k: (len(v) if isinstance(v, (dict, list)) else 1) for k, v in cap.items()}
    except (ValueError, OSError) as e:
        st["cap_sid_counts"] = f"error:{e}"
    sec = h / ".sandbox-secrets"
    st["secrets"] = {p.name: {"mtime": p.stat().st_mtime, "sha256": sha256(p)} for p in sorted(sec.iterdir())}
    return st


def state(label):
    sid = lookup_sid(ACCOUNT)
    names, resume = [], 0
    while True:
        data, _, resume = win32net.NetUserEnum(None, 0, 0, resume)
        names += [d["name"] for d in data]
        if not resume:
            break
    shares, resume = [], 0
    while True:
        data, _, resume = win32net.NetShareEnum(None, 0, resume)
        shares += [d["netname"] for d in data]
        if not resume:
            break
    root = recycle_root()
    st = {"label": label, "time": time.strftime("%Y-%m-%d %H:%M:%S"), "local_accounts": sorted(names),
          "measurement_account_sid": sid, "root_exists": ROOT.exists(), "shares": sorted(shares),
          "services": {k: (v.get("state") if isinstance(v, dict) else v) for k, v in services().items()},
          "bits_user_jobs": bits_user_jobs(),
          "recycle_root_count": len(root) if isinstance(root, list) else root,
          "account_bin_exists": bool(sid) and isinstance(root, list) and sid in root,
          "user_bin_total": explorer_view()["total"],
          "listening_tcp": len([r for r in tcp_rows() if r[0] == "LISTEN"])}
    for n in ("CodexSandboxOffline", "CodexSandboxOnline"):
        try:
            st.setdefault("codex_last_logon", {})[n] = win32net.NetUserGetInfo(None, n, 2)["last_logon"]
        except win32net.error as e:
            st.setdefault("codex_last_logon", {})[n] = f"error:{e.winerror}"
    try:
        st["codex"] = codex_state()
    except OSError as e:
        st["codex"] = f"error:{e}"
    r = subprocess.run(ps("@(Get-NetFirewallRule).Count"), capture_output=True, timeout=120)
    st["firewall_rule_count"] = r.stdout.decode().strip()
    r = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True)
    st["process_count"] = len(r.stdout.splitlines())
    print(save(f"state-{label}.json", st))


# ---------------------------------------------------------------- summary
def summary():
    sys.stdout.reconfigure(encoding="utf-8")

    def cnt(vals):
        vals = list(vals)
        return f"{sum(1 for v in vals if v)}/{len(vals)}"

    def g(r, *keys):
        v = r.get("child") or {}
        for k in keys:
            v = v.get(k) if isinstance(v, dict) else None
        return v

    if (LOCAL / "clip.json").exists() or (LOCAL / "clip-partial.json").exists():
        d = load("clip.json") if (LOCAL / "clip.json").exists() else load("clip-partial.json")
        cells = list(d["trials"])
        print("## clip  saved:", d.get("saved"), "restore:", d.get("restore"))
        print("| 항목 | " + " | ".join(cells) + " |\n| --- |" + " --- |" * len(cells))
        rows = [("셸 시작", lambda r: r.get("child") is not None),
                ("Python 읽기 일치", lambda r: (g(r, "read_py") or {}).get("data") == "match"),
                ("Get-Clipboard 일치", lambda r: (g(r, "read_ps") or {}).get("ok")),
                ("Set-Clipboard → 호스트", lambda r: (r["stages"].get("host_after_ps") or {}).get("data") == "match"),
                ("clip.exe → 호스트", lambda r: (r["stages"].get("host_after_clipexe") or {}).get("data") == "match"),
                ("Python 쓰기 → 호스트", lambda r: (r["stages"].get("host_after_py") or {}).get("data") == "match")]
        for label, fn in rows:
            print(f"| {label} | " + " | ".join(cnt(fn(r) for r in d["trials"][c]) for c in cells) + " |")
        for c in cells:
            r = d["trials"][c][0]
            print(c, "winsta", g(r, "winsta"), "restricted", g(r, "token", "is_token_restricted"),
                  "user", (g(r, "token", "user") or "")[-6:])
            print("   read_py", g(r, "read_py"), "| read_ps", (g(r, "read_ps") or {}).get("stdout", "")[-160:].strip(),
                  "| write_ps", (g(r, "write_ps") or {}).get("stdout", "")[-160:].strip(),
                  "| clipexe", g(r, "write_clipexe"), "| write_py", g(r, "write_py"), "| stages", r["stages"],
                  "| job", (r.get("launcher") or {}).get("launches", {}).get("child", {}).get("job_ui")
                  if isinstance(r.get("launcher"), dict) else None)
    if (LOCAL / "rb.json").exists() or (LOCAL / "rb-partial.json").exists():
        d = load("rb.json") if (LOCAL / "rb.json").exists() else load("rb-partial.json")
        print("\n## rb  account bin before:", d.get("account_bin_before"))
        cells = list(d["trials"])
        print("| 항목 | " + " | ".join(cells) + " |\n| --- |" + " --- |" * len(cells))

        def stg(r):
            return (r.get("stages") or {}).get("host_check") or {}
        rows = [("셸 시작", lambda r: r.get("child") is not None),
                ("SHFileOperationW 반환 0, 원본 없어짐", lambda r: (g(r, "rb_sh") or {}).get("ret") == "0x0"
                 and not (g(r, "rb_sh") or {}).get("file_exists_after")),
                ("SHFileOperationW 파일이 셸 휴지통에 있음", lambda r: (g(r, "rb_sh") or {}).get("in_own_bin")),
                ("VB DeleteFile 성공", lambda r: "vb=ok" in ((g(r, "rb_vb") or {}).get("stdout") or "")),
                ("Remove-Item 성공", lambda r: "rm=ok" in ((g(r, "rb_rm") or {}).get("stdout") or "")),
                ("셸 휴지통 폴더 있음(삭제 뒤)", lambda r: (g(r, "bin_after") or {}).get("exists")),
                ("셸 휴지통의 시험 항목 2개", lambda r: len((g(r, "bin_after") or {}).get("iso_items") or []) == 2),
                ("사용자 탐색기 휴지통에 보임", lambda r: bool((stg(r).get("explorer") or {}).get("iso_items"))),
                ("사용자가 셸 휴지통 폴더 목록 읽음", lambda r: isinstance(stg(r).get("host_list_account_bin"), dict)),
                ("SHEmptyRecycleBinW 성공", lambda r: (g(r, "rb_empty") or {}).get("hresult") == "0x00000000"),
                ("비운 뒤 셸 휴지통 항목 0", lambda r: (g(r, "bin_final") or {}).get("i_files") == 0),
                ("사용자 휴지통 항목 수 변화 없음", lambda r: r.get("user_bin_total_before") == (r.get("user_bin_after") or {}).get("total"))]
        for label, fn in rows:
            print(f"| {label} | " + " | ".join(cnt(fn(r) for r in d["trials"][c]) for c in cells) + " |")
        for c in cells:
            for r in d["trials"][c][:1]:
                ch = r.get("child") or {}
                st = (r.get("stages") or {}).get("host_check") or {}
                print(c, r["tag"], "| before", ch.get("bin_before"), "| sh", ch.get("rb_sh"),
                      "| vb", (ch.get("rb_vb") or {}).get("stdout", ch.get("rb_vb"))
                      if isinstance(ch.get("rb_vb"), dict) else ch.get("rb_vb"),
                      "| rm", (ch.get("rb_rm") or {}).get("stdout", "")[-120:].strip(), "| exists", ch.get("exists_after"),
                      "| after", ch.get("bin_after"), "| host", st, "| empty", ch.get("rb_empty"),
                      "| final", ch.get("bin_final"), "| user bin", r.get("user_bin_total_before"), "->",
                      (r.get("user_bin_after") or {}).get("total"), (r.get("user_bin_after") or {}).get("iso_items"))
    if (LOCAL / "net.json").exists() or (LOCAL / "net-partial.json").exists():
        d = load("net.json") if (LOCAL / "net.json").exists() else load("net-partial.json")
        cells = list(d["trials"])
        print("\n## net  port", d.get("port"), "refused", d.get("http_refused_other_clients"))
        print("| 항목 | " + " | ".join(cells) + " |\n| --- |" + " --- |" * len(cells))

        def okrun(k):
            return lambda r: (g(r, k) or {}).get("ok") if isinstance(g(r, k), dict) else False

        def okhttp(k):
            return lambda r: (g(r, k) or {}).get("body_ok")

        def oktcp(k):
            return lambda r: (g(r, k) or {}).get("result") == "ok"

        def okres(k, pred):
            return lambda r: isinstance(g(r, k), dict) and pred((g(r, k) or {}).get("result"))
        rows = [("셸 시작", lambda r: r.get("child") is not None), ("example.com HTTPS 직접(차단 확인)", okhttp("direct_https"))]
        for n in ("v4", "v6", "lan"):
            rows += [(f"curl {n}", okrun(f"curl_{n}")), (f"IWR {n}", okrun(f"iwr_{n}")), (f"Python {n}", okhttp(f"py_{n}"))]
        rows += [("호스트 → 셸 리스너 127.0.0.1", lambda r: ((r["stages"].get("host_connect") or {}).get("127.0.0.1") or {}).get("result") == "ok"),
                 ("호스트 → 셸 리스너 ::1", lambda r: ((r["stages"].get("host_connect") or {}).get("::1") or {}).get("result") == "ok"),
                 ("TCP 127.0.0.1:445", oktcp("smb_tcp_v4")), ("TCP LAN:445", oktcp("smb_tcp_lan")),
                 ("TCP 192.0.2.1:445", oktcp("smb_tcp_testnet")),
                 ("\\\\localhost 공유 읽기(Python)", okres("unc_share_py", lambda v: isinstance(v, dict) and v.get("match"))),
                 ("\\\\localhost 공유 dir", okrun("unc_share_cmd")),
                 ("\\\\LAN 공유 읽기", okres("unc_share_lan", lambda v: isinstance(v, dict) and v.get("match"))),
                 ("BITS Start-BitsTransfer", okrun("bits_ps")),
                 ("BITS bitsadmin 파일", lambda r: (g(r, "bits_files") or {}).get(f"{r['tag']}-bits-adm.html"))]
        for label, fn in rows:
            print(f"| {label} | " + " | ".join(cnt(fn(r) for r in d["trials"][c]) for c in cells) + " |")
        for c in cells:
            for r in d["trials"][c][:2]:
                ch = r.get("child") or {}
                print(c, r["tag"], "user", (g(r, "token", "user") or "")[-6:], "restricted", g(r, "token", "is_token_restricted"),
                      "secs", r.get("seconds"))
                for k in ("direct_https", "curl_v4", "iwr_v4", "py_v4", "curl_lan", "py_lan", "listen", "smb_tcp_v4",
                          "smb_tcp_lan", "smb_tcp_testnet", "unc_share_py", "unc_share_lan", "unc_admin_share",
                          "smb_conn", "unc_testnet", "webdav_netuse", "webdav", "webdav_netuse_delete", "bits_ps",
                          "bits_admin", "bits_files", "bits_left"):
                    v = ch.get(k)
                    if isinstance(v, dict) and "stdout" in v:
                        v = {"exit": v.get("exit"), "out": (v.get("stdout") or "")[-220:].strip(),
                             "err": (v.get("stderr") or "")[-160:].strip(), "s": v.get("seconds")}
                    print("   ", k, json.dumps(v, ensure_ascii=False)[:400])
                print("    stages", json.dumps(r.get("stages"))[:300])
                print("    tcp_seen", json.dumps(r.get("tcp_seen"))[:900])
                print("    http_log", json.dumps(r.get("http_log"))[:300], "services", r.get("services_after"))


if __name__ == "__main__":
    step = sys.argv[1]
    if step == "state":
        state(sys.argv[2])
    else:
        {"prep": prep, "acl": acl, "run": run, "cleanup": cleanup, "summary": summary}[step]()
