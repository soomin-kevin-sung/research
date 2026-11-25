"""Runs inside the sandbox; prints one ISOJSON line.

token     : SIDs of this process token (user, AppContainer, capabilities, restricted SIDs, integrity).
devserver : bind an HTTP server on 127.0.0.1, connect to it from the same process, then keep
            serving for a few seconds so the harness can try to connect from the host.
parbuild  : a synthetic parallel build (16 small modules, 4 worker processes) and a serial control.
"""
import os
import sys
import json
import time
import ctypes
import threading
from ctypes import wintypes
from pathlib import Path


def token_info():
    a = ctypes.WinDLL("advapi32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    h = wintypes.HANDLE()
    a.OpenProcessToken(wintypes.HANDLE(-1), 0x0008, ctypes.byref(h))

    def raw(cls):
        size = wintypes.DWORD()
        a.GetTokenInformation(h, cls, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value or 8)
        ok = a.GetTokenInformation(h, cls, buf, size, ctypes.byref(size))
        return buf if ok else None

    def sid_str(psid):
        if not psid:
            return None
        s = wintypes.LPWSTR()
        a.ConvertSidToStringSidW(ctypes.c_void_p(psid), ctypes.byref(s))
        v = s.value
        k.LocalFree(s)
        return v

    def groups(cls):
        buf = raw(cls)
        if buf is None:
            return None
        n = ctypes.c_uint32.from_buffer(buf).value
        out = []
        for i in range(n):
            psid = ctypes.c_void_p.from_buffer(buf, 8 + 16 * i).value
            out.append(sid_str(psid))
        return out

    def first_sid(cls):
        buf = raw(cls)
        return sid_str(ctypes.c_void_p.from_buffer(buf, 0).value) if buf is not None else None

    is_ac = raw(29)
    return {"user": first_sid(1), "is_appcontainer": bool(ctypes.c_uint32.from_buffer(is_ac).value) if is_ac else None,
            "appcontainer_sid": first_sid(31), "capabilities": groups(30), "restricted_sids": groups(11),
            "integrity": first_sid(25)}


def devserver(ws):
    import http.server
    import urllib.request
    seen = threading.Event()

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/host":
                seen.set()
            self.send_response(200)
            self.send_header("Content-Length", "6")
            self.end_headers()
            self.wfile.write(b"DEV_OK")

        def log_message(self, *a):
            pass

    out = {}
    try:
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    except OSError as e:
        return {"bind": f"error:{getattr(e, 'winerror', None) or e.errno}"}
    out["bind"] = "ok"
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        out["self_connect"] = opener.open(f"http://127.0.0.1:{port}/self", timeout=3).read().decode()
    except Exception as e:
        out["self_connect"] = f"error:{type(e).__name__}"
    (Path(ws) / "port.txt").write_text(str(port))
    out["host_request_seen"] = seen.wait(8)
    srv.shutdown()
    return out


def build_one(i, out_dir):
    import py_compile
    p = Path(out_dir) / f"m{i}.py"
    p.write_text("".join(f"VALUE_{i}_{j} = {j}\n" for j in range(300)))
    py_compile.compile(str(p), cfile=str(p) + "c", doraise=True)
    return os.getpid()


def parbuild(ws):
    from concurrent.futures import ProcessPoolExecutor
    out = {}
    serial = Path(ws) / "serial"
    serial.mkdir(exist_ok=True)
    try:
        [build_one(i, serial) for i in range(16)]
        out["serial_ok"] = len(list(serial.glob("*.pyc"))) == 16
    except Exception as e:
        out["serial_ok"] = f"error:{type(e).__name__}:{str(e)[:80]}"
    par = Path(ws) / "parallel"
    par.mkdir(exist_ok=True)
    t0 = time.monotonic()
    try:
        with ProcessPoolExecutor(max_workers=4) as ex:
            pids = list(ex.map(build_one, range(16), [str(par)] * 16))
        out["parallel_ok"] = len(list(par.glob("*.pyc"))) == 16
        out["worker_processes"] = len(set(pids))
    except Exception as e:
        import traceback
        out["parallel_ok"] = f"error:{type(e).__name__}:{getattr(e, 'winerror', '')}"
        out["failed_at"] = [f"{Path(f.filename).name}:{f.name}" for f in traceback.extract_tb(e.__traceback__)][-3:]
    out["parallel_s"] = round(time.monotonic() - t0, 2)
    return out


def access(*dirs):
    """Open each object with one access right at a time; nothing is read, written or deleted."""
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.restype = wintypes.HANDLE
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                              wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    share = 0x7  # read | write | delete

    def try_open(path, right, flags=0):
        h = k.CreateFileW(str(path), right, share, None, 3, flags, None)  # OPEN_EXISTING
        if h in (None, wintypes.HANDLE(-1).value):
            return f"denied:{ctypes.get_last_error()}"
        k.CloseHandle(h)
        return "granted"

    out = {}
    for d in dirs:
        d = Path(d)
        res = {"dir_list": try_open(d, 0x1, 0x02000000), "dir_add_file": try_open(d, 0x2, 0x02000000),
               "dir_delete_child": try_open(d, 0x40, 0x02000000)}
        try:
            res["os_listdir"] = len(os.listdir(d))
        except OSError as e:
            res["os_listdir"] = f"error:{e.winerror}"
        for f in ("existing.txt", "new.txt"):
            res[f] = {"read": try_open(d / f, 0x80000000), "write_data": try_open(d / f, 0x2),
                      "delete": try_open(d / f, 0x10000)}
        out[d.name] = res
    return out


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "token":
        res = token_info()
    elif mode == "devserver":
        res = devserver(sys.argv[2])
    elif mode == "access":
        res = access(*sys.argv[2:])
    elif mode == "pyops":  # synthetic files only: list, delete d.txt, create created.txt
        res = {}
        for d in map(Path, sys.argv[2:]):
            r = {}
            for name, op in (("list", lambda: len(os.listdir(d))), ("delete", lambda: os.remove(d / "d.txt")),
                             ("create", lambda: (d / "created.txt").write_text("c"))):
                try:
                    op()
                    r[name] = "ok"
                except OSError as e:
                    r[name] = f"error:{e.winerror}"
            res[d.name] = r
    else:
        res = parbuild(sys.argv[2])
    print("ISOJSON " + json.dumps(res))
