"""Child for the recycle bin, clipboard and in-PC network measurement (runs/2026-11-27-01.md). Stdlib + ctypes.

Usage: python ux_child.py <spec.json>     prints one ISOJSON line (and writes spec["out"] when it can)
Runs with the token the harness gives it: the measurement account's logon token, the Codex-style WRITE_RESTRICTED
token made from it (optionally inside a Job with clipboard UI limits), a real Codex sandbox account through
`codex sandbox`, or the current user (host reference). Imports child.py (probe-token-backends-child.py) from its own
folder for token_info and run_tool.

Tasks (each returns a small record; clipboard contents are compared here and never printed)
  token      token_info() of child.py, plus IsTokenRestricted
  winsta     names of the process window station and the thread desktop
  mark       writes a file (stage signal to the host);  wait  waits for a file (the host's answer)
  rb_list    the own recycle bin folder C:\\$Recycle.Bin\\<own SID>: exists, $I/$R counts, original names that
             start with iso-rb- (read from the $I files)
  rb_shfileop  SHFileOperationW FO_DELETE with FOF_ALLOWUNDO and no UI (silent, no confirmation, no error UI)
  rb_empty   SHEmptyRecycleBinW for C:\\ without UI; skipped when this process can list the user's own recycle bin
             folder (guard: the call must not be able to reach the user's items)
  exists     whether files still exist
  clip_read  OpenClipboard + GetClipboardData(CF_UNICODETEXT), compared with spec["expect"]
  clip_write OpenClipboard (message-only window) + EmptyClipboard + SetClipboardData(CF_UNICODETEXT)
  listen     TCP listeners on 127.0.0.1 and ::1 (ephemeral ports, loopback only), ports written to "ready";
             accepts until "go" exists or the timeout, answers iso-shell-ok
  tcp        TCP connection only;  http  urllib GET without proxies;  listdir / readfile  in a thread with a
             timeout (UNC paths can block for tens of seconds)
  run        an installed tool with child.py run_tool; "if_ok" skips it unless an earlier task's field is true
"""
import os
import sys
import json
import time
import socket
import ctypes
import threading
import importlib.util
import urllib.request
from ctypes import wintypes
from pathlib import Path

_c = importlib.util.spec_from_file_location("child", Path(__file__).with_name("child.py"))
C = importlib.util.module_from_spec(_c)
_c.loader.exec_module(C)

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
u32 = ctypes.WinDLL("user32", use_last_error=True)
sh32 = ctypes.WinDLL("shell32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
H, DW, BOOL, VP = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, ctypes.c_void_p
adv.IsTokenRestricted.argtypes = [H]
u32.GetProcessWindowStation.restype = H
u32.GetThreadDesktop.restype = H
u32.GetThreadDesktop.argtypes = [DW]
u32.GetUserObjectInformationW.argtypes = [H, ctypes.c_int, VP, DW, ctypes.POINTER(DW)]
u32.CreateWindowExW.restype = wintypes.HWND
u32.CreateWindowExW.argtypes = [DW, wintypes.LPCWSTR, wintypes.LPCWSTR, DW, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, wintypes.HWND, VP, VP, VP]
u32.DestroyWindow.argtypes = [wintypes.HWND]
u32.OpenClipboard.argtypes = [wintypes.HWND]
u32.GetClipboardData.restype = H
u32.GetClipboardData.argtypes = [wintypes.UINT]
u32.SetClipboardData.restype = H
u32.SetClipboardData.argtypes = [wintypes.UINT, H]
k32.GlobalAlloc.restype = H
k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
k32.GlobalLock.restype = VP
k32.GlobalLock.argtypes = [H]
k32.GlobalUnlock.argtypes = [H]
k32.GlobalFree.argtypes = [H]
k32.GetCurrentThreadId.restype = DW
sh32.SHEmptyRecycleBinW.restype = ctypes.c_long
sh32.SHEmptyRecycleBinW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, DW]
CF_UNICODETEXT = 13


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT), ("pFrom", VP), ("pTo", VP),
                ("fFlags", wintypes.WORD), ("fAnyOperationsAborted", BOOL), ("hNameMappings", VP),
                ("lpszProgressTitle", wintypes.LPCWSTR)]


sh32.SHFileOperationW.argtypes = [ctypes.POINTER(SHFILEOPSTRUCTW)]
FO_DELETE = 3
FOF_SILENT, FOF_NOCONFIRMATION, FOF_ALLOWUNDO, FOF_NOCONFIRMMKDIR, FOF_NOERRORUI = 0x4, 0x10, 0x40, 0x200, 0x400


def err():
    return f"error:{ctypes.get_last_error()}"


def own_sid():
    h = C.own_token()
    buf = C.tok_raw(h, 1)
    sid = C.sid_str(ctypes.c_void_p.from_buffer(buf, 0).value) if buf else None
    C.k32.CloseHandle(h)
    return sid


# ---------------------------------------------------------------- token, window station
def token_task():
    out = C.token_info()
    h = C.own_token()
    out["is_token_restricted"] = bool(adv.IsTokenRestricted(h))
    C.k32.CloseHandle(h)
    return out


def uo_name(h):
    if not h:
        return err()
    buf = ctypes.create_unicode_buffer(256)
    n = DW()
    if not u32.GetUserObjectInformationW(h, 2, buf, ctypes.sizeof(buf), ctypes.byref(n)):  # UOI_NAME
        return err()
    return buf.value


def winsta_task():
    return {"window_station": uo_name(u32.GetProcessWindowStation()),
            "desktop": uo_name(u32.GetThreadDesktop(k32.GetCurrentThreadId()))}


# ---------------------------------------------------------------- recycle bin
def bin_dir(sid=None):
    return Path("C:\\$Recycle.Bin") / (sid or own_sid())


def info_name(p):
    """Original file name from a $I file (version 2: 8-byte version, size, time, 4-byte length, UTF-16 path)."""
    b = p.read_bytes()
    if len(b) >= 28 and int.from_bytes(b[:8], "little") == 2:
        n = int.from_bytes(b[24:28], "little")
        return b[28:28 + 2 * n].decode("utf-16-le", "replace").rstrip("\0")
    if len(b) >= 24 and int.from_bytes(b[:8], "little") == 1:
        return b[24:24 + 520].decode("utf-16-le", "replace").split("\0")[0]
    return None


def rb_list(t):
    d = bin_dir()
    out = {"sid_dir": d.name, "exists": None}
    try:
        names = os.listdir(d)
    except OSError as e:
        out["exists"] = d.exists()
        out["list"] = f"error:{getattr(e, 'winerror', None) or e.errno}"
        return out
    out["exists"] = True
    out["i_files"] = sum(1 for n in names if n.startswith("$I"))
    out["r_files"] = sum(1 for n in names if n.startswith("$R"))
    ours, other = [], 0
    for n in names:
        if n.startswith("$I"):
            try:
                orig = info_name(d / n)
            except OSError as e:
                orig = f"error:{e.winerror}"
            base = Path(orig).name if isinstance(orig, str) and not orig.startswith("error") else orig
            if isinstance(base, str) and base.startswith("iso-rb-"):
                ours.append(base)
            else:
                other += 1
    out["iso_items"], out["other_items"] = sorted(ours), other
    return out


def rb_shfileop(t):
    path = t["path"]
    buf = ctypes.create_unicode_buffer(path + "\0")  # double NUL at the end
    op = SHFILEOPSTRUCTW(None, FO_DELETE, ctypes.addressof(buf), None,
                         FOF_ALLOWUNDO | FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI,
                         False, None, None)
    t0 = time.monotonic()
    r = sh32.SHFileOperationW(ctypes.byref(op))
    out = {"ret": f"0x{r & 0xffffffff:x}", "aborted": bool(op.fAnyOperationsAborted),
           "file_exists_after": Path(path).exists(), "seconds": round(time.monotonic() - t0, 2)}
    listed = rb_list({})
    out["in_own_bin"] = Path(path).name in (listed.get("iso_items") or [])
    return out


def rb_empty(t):
    guard = t.get("guard_sid")
    if guard:
        try:
            os.listdir(bin_dir(guard))
            return {"skipped": "user recycle bin folder is listable by this process"}
        except OSError as e:
            g = f"error:{getattr(e, 'winerror', None) or e.errno}"
    else:
        return {"skipped": "no guard SID"}
    hr = sh32.SHEmptyRecycleBinW(None, "C:\\", 0x1 | 0x2 | 0x4)  # NOCONFIRMATION | NOPROGRESSUI | NOSOUND
    return {"guard_list_user_bin": g, "hresult": f"0x{hr & 0xffffffff:08x}"}


# ---------------------------------------------------------------- clipboard
def msg_window():
    return u32.CreateWindowExW(0, "STATIC", "iso-clip", 0, 0, 0, 0, 0, wintypes.HWND(-3), None, None, None)  # HWND_MESSAGE


def clip_open(hwnd):
    last = None
    for _ in range(20):
        if u32.OpenClipboard(hwnd):
            return None
        last = err()
        time.sleep(0.05)
    return last


def compare(s, expect):
    if s is None:
        return "none"
    s = s.strip()
    return "match" if s == expect else ("empty" if not s else f"other:len={len(s)}")


def clip_read(t):
    hwnd = msg_window()
    out = {"window": "ok" if hwnd else err()}
    e = clip_open(hwnd)
    if e:
        out["open"] = e
    else:
        out["open"] = "ok"
        try:
            out["formats"] = u32.CountClipboardFormats()  # 0: the clipboard is empty
            h = u32.GetClipboardData(CF_UNICODETEXT)
            if not h:
                out["data"] = err()
            else:
                p = k32.GlobalLock(h)
                out["data"] = compare(ctypes.wstring_at(p) if p else None, t["expect"])
                k32.GlobalUnlock(h)
        finally:
            u32.CloseClipboard()
    if hwnd:
        u32.DestroyWindow(hwnd)
    return out


def clip_write(t):
    hwnd = msg_window()
    out = {"window": "ok" if hwnd else err()}
    e = clip_open(hwnd)
    if e:
        out["open"] = e
    else:
        out["open"] = "ok"
        try:
            out["empty"] = "ok" if u32.EmptyClipboard() else err()
            data = t["data"]
            size = (len(data) + 1) * 2
            h = k32.GlobalAlloc(0x2, size)  # GMEM_MOVEABLE
            p = k32.GlobalLock(h)
            ctypes.memmove(p, ctypes.create_unicode_buffer(data), size)
            k32.GlobalUnlock(h)
            if u32.SetClipboardData(CF_UNICODETEXT, h):
                out["set"] = "ok"
            else:
                out["set"] = err()
                k32.GlobalFree(h)
        finally:
            u32.CloseClipboard()
    if hwnd:
        u32.DestroyWindow(hwnd)
    return out


# ---------------------------------------------------------------- network
def oserr(e):
    return f"error:{getattr(e, 'winerror', None) or e.errno or type(e).__name__}"


def tcp(t):
    t0 = time.monotonic()
    try:
        s = socket.create_connection((t["host"], t["port"]), timeout=t.get("timeout", 8))
        s.close()
        r = "ok"
    except socket.timeout:
        r = "timeout"
    except OSError as e:
        r = oserr(e)
    return {"result": r, "seconds": round(time.monotonic() - t0, 2)}


def http(t):
    t0 = time.monotonic()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(t["url"], timeout=t.get("timeout", 8)) as r:
            body = r.read(200).decode("utf-8", "replace")
            res = {"status": r.status, "body_ok": t.get("expect", "") in body}
    except Exception as e:  # noqa: BLE001 (URLError, timeouts, resets)
        reason = getattr(e, "reason", e)
        res = {"error": f"{type(e).__name__}:{oserr(reason) if isinstance(reason, OSError) else reason}"}
    res["seconds"] = round(time.monotonic() - t0, 2)
    return res


def threaded(fn, timeout):
    box = {}

    def go():
        try:
            box["result"] = fn()
        except OSError as e:
            box["result"] = oserr(e)
        except Exception as e:  # noqa: BLE001
            box["result"] = f"exception:{type(e).__name__}:{e}"
    th = threading.Thread(target=go, daemon=True)
    t0 = time.monotonic()
    th.start()
    th.join(timeout)
    return {"result": box.get("result", "timeout"), "seconds": round(time.monotonic() - t0, 2)}


def listdir(t):
    return threaded(lambda: {"entries": len(os.listdir(t["path"]))}, t.get("timeout", 60))


def readfile(t):
    return threaded(lambda: {"match": Path(t["path"]).read_text(encoding="utf-8").strip() == t["expect"]},
                    t.get("timeout", 60))


def listen(t):
    res = {"bound": {}, "accepted": []}
    socks = []
    for fam, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.bind((addr, 0))
            s.listen(5)
            s.settimeout(0.2)
            socks.append(s)
            res["bound"][addr] = s.getsockname()[1]
        except OSError as e:
            res["bound"][addr] = oserr(e)
    Path(t["ready"]).write_text(json.dumps(res["bound"]), encoding="utf-8")
    end = time.monotonic() + t.get("timeout", 30)
    while time.monotonic() < end and not Path(t["go"]).exists():
        for s in socks:
            try:
                c, a = s.accept()
            except socket.timeout:
                continue
            except OSError as e:
                res["accepted"].append({"local": s.getsockname()[0], "error": oserr(e)})
                continue
            try:
                c.settimeout(3)
                data = c.recv(64).decode("utf-8", "replace")
                c.sendall(b"iso-shell-ok")
            except OSError as e:
                data = oserr(e)
            c.close()
            res["accepted"].append({"local": s.getsockname()[0], "peer": a[0], "data": data})
    for s in socks:
        s.close()
    res["ended"] = "go" if Path(t["go"]).exists() else "timeout"
    return res


# ---------------------------------------------------------------- dispatcher
def wait_for(path, timeout):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if Path(path).exists():
            return "ok"
        time.sleep(0.1)
    return "timeout"


def run_task(t, done):
    cond = t.get("if_ok")
    if cond:
        prev = done.get(cond[0])
        if not (isinstance(prev, dict) and prev.get(cond[1])):
            return f"skipped:{cond[0]}.{cond[1]} is not true"
    kind = t["kind"]
    if kind == "token":
        return token_task()
    if kind == "winsta":
        return winsta_task()
    if kind == "env":
        return {n: os.environ.get(n) for n in t["names"]}
    if kind == "hkcu_name":
        return C.hkcu_name()
    if kind == "mark":
        Path(t["path"]).write_text(t.get("data", "1"), encoding="utf-8")
        return "ok"
    if kind == "wait":
        return wait_for(t["path"], t.get("timeout", 60))
    if kind == "rb_list":
        return rb_list(t)
    if kind == "rb_shfileop":
        return rb_shfileop(t)
    if kind == "rb_empty":
        return rb_empty(t)
    if kind == "exists":
        return {Path(p).name: Path(p).exists() for p in t["paths"]}
    if kind == "clip_read":
        return clip_read(t)
    if kind == "clip_write":
        return clip_write(t)
    if kind == "listen":
        return listen(t)
    if kind == "tcp":
        return tcp(t)
    if kind == "http":
        return http(t)
    if kind == "listdir":
        return listdir(t)
    if kind == "readfile":
        return readfile(t)
    if kind == "run":
        r = C.run_tool(t["argv"], t.get("cwd"), t.get("timeout", 60), t.get("stdin", "pipe"), t.get("env"))
        if t.get("ok_if") and isinstance(r, dict):
            r["ok"] = r.get("exit") == 0 and t["ok_if"] in (r.get("stdout") or "")
        return r
    return f"unknown_kind:{kind}"


def main():
    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out = {}
    for t in spec["tasks"]:
        t0 = time.monotonic()
        try:
            out[t["id"]] = run_task(t, out)
        except Exception as e:  # noqa: BLE001
            out[t["id"]] = f"exception:{type(e).__name__}:{e}"
        if isinstance(out[t["id"]], dict) and "seconds" not in out[t["id"]]:
            out[t["id"]]["task_seconds"] = round(time.monotonic() - t0, 2)
    line = json.dumps(out)
    if spec.get("out"):
        try:
            Path(spec["out"]).write_text(line, encoding="utf-8")
        except OSError:
            pass
    print("ISOJSON " + line, flush=True)


if __name__ == "__main__":
    main()
