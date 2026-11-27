"""Child for the local proxy, profile read ACE and HKLM key measurement (runs/2026-11-27-02.md). Stdlib + ctypes.

Usage: python pa_child.py <spec.json>     prints one ISOJSON line (and writes spec["out"] when it can)
Runs with the token the harness gives it (see probe-proxy-ace.py, Cells). Imports ux_child.py
(probe-ux-net-child.py) from its own folder; tasks it does not know go to ux_child.run_task (token, tcp, http,
listdir, readfile, run, ...).

Tasks added here
  proxy_http     one absolute-form request through the proxy over a raw socket:
                 GET http://<host>/ HTTP/1.1, optional Proxy-Authorization; status line, Proxy-Authenticate present,
                 whether the body holds spec "expect"
  proxy_connect  CONNECT <host>:<port> through the proxy, optional Proxy-Authorization; status line; when 200 and
                 "tls" is set, a TLS handshake with the default context (server name checked) and GET / inside
  reg_read       HKLM key: RegOpenKeyEx with the given access, then RegQueryValueEx of one value, compared with
                 "expect" (the value is a dummy; only the comparison is kept)
  tcp_table      GetExtendedTcpTable (owner PID) for IPv4 listeners on 127.0.0.1: how many, and whether the given
                 port is listed with the given PID
"""
import sys
import json
import time
import ssl
import socket
import ctypes
import winreg
import importlib.util
from ctypes import wintypes
from pathlib import Path

_u = importlib.util.spec_from_file_location("ux_child", Path(__file__).with_name("ux_child.py"))
U = importlib.util.module_from_spec(_u)
_u.loader.exec_module(U)


def recv_head(s, limit=65536):
    """Reads until the end of the response head or the connection closes; returns (head, rest)."""
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < limit:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head.decode("latin-1", "replace"), rest


def head_fields(head):
    lines = head.split("\r\n")
    status = lines[0] if lines and lines[0] else "no_response"
    names = {ln.split(":", 1)[0].strip().lower() for ln in lines[1:] if ":" in ln}
    return {"status": status[:60], "proxy_authenticate": "proxy-authenticate" in names}


def proxy_http(t):
    t0 = time.monotonic()
    req = f"GET http://{t['host']}/ HTTP/1.1\r\nHost: {t['host']}\r\nConnection: close\r\n"
    if t.get("auth"):
        req += f"Proxy-Authorization: {t['auth']}\r\n"
    try:
        s = socket.create_connection(("127.0.0.1", t["port"]), timeout=t.get("timeout", 15))
        s.sendall((req + "\r\n").encode("latin-1"))
        head, rest = recv_head(s)
        res = head_fields(head)
        if res["status"].split(" ")[1:2] == ["200"]:
            body = rest
            while len(body) < 4000:
                chunk = s.recv(4096)
                if not chunk:
                    break
                body += chunk
            res["body_ok"] = t.get("expect", "").encode() in body
        s.close()
    except socket.timeout:
        res = {"status": "timeout"}
    except OSError as e:
        res = {"status": U.oserr(e)}
    res["seconds"] = round(time.monotonic() - t0, 2)
    return res


def proxy_connect(t):
    t0 = time.monotonic()
    req = f"CONNECT {t['host']}:{t.get('target_port', 443)} HTTP/1.1\r\nHost: {t['host']}:{t.get('target_port', 443)}\r\n"
    if t.get("auth"):
        req += f"Proxy-Authorization: {t['auth']}\r\n"
    try:
        s = socket.create_connection(("127.0.0.1", t["port"]), timeout=t.get("timeout", 15))
        s.sendall((req + "\r\n").encode("latin-1"))
        head, _ = recv_head(s)
        res = head_fields(head)
        if t.get("tls") and res["status"].split(" ")[1:2] == ["200"]:
            try:
                ctx = ssl.create_default_context()
                ts = ctx.wrap_socket(s, server_hostname=t["host"])
                ts.sendall(f"GET / HTTP/1.1\r\nHost: {t['host']}\r\nConnection: close\r\n\r\n".encode())
                h2, rest = recv_head(ts)
                body = rest
                while len(body) < 4000:
                    chunk = ts.recv(4096)
                    if not chunk:
                        break
                    body += chunk
                res["tls"] = {"status": head_fields(h2)["status"], "body_ok": t.get("expect", "").encode() in body,
                              "version": ts.version()}
                ts.close()
            except (OSError, ssl.SSLError) as e:
                res["tls"] = {"error": f"{type(e).__name__}:{e}"[:160]}
        else:
            s.close()
    except socket.timeout:
        res = {"status": "timeout"}
    except OSError as e:
        res = {"status": U.oserr(e)}
    res["seconds"] = round(time.monotonic() - t0, 2)
    return res


def reg_read(t):
    out = {}
    access = t.get("access", winreg.KEY_READ)
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, t["path"], 0, access)
        out["open"] = "ok"
        try:
            v, _ = winreg.QueryValueEx(k, t["value"])
            out["value_match"] = v == t["expect"]
        except OSError as e:
            out["query"] = U.oserr(e)
        winreg.CloseKey(k)
    except OSError as e:
        out["open"] = U.oserr(e)
    return out


class ROW(ctypes.Structure):
    _fields_ = [("state", wintypes.DWORD), ("laddr", wintypes.DWORD), ("lport", wintypes.DWORD),
                ("raddr", wintypes.DWORD), ("rport", wintypes.DWORD), ("pid", wintypes.DWORD)]


def tcp_table(t):
    iph = ctypes.WinDLL("iphlpapi")
    size = wintypes.DWORD(0)
    iph.GetExtendedTcpTable(None, ctypes.byref(size), False, socket.AF_INET, 3, 0)  # TCP_TABLE_OWNER_PID_LISTENER
    buf = ctypes.create_string_buffer(size.value + 4096)
    size = wintypes.DWORD(len(buf))
    r = iph.GetExtendedTcpTable(buf, ctypes.byref(size), False, socket.AF_INET, 3, 0)
    if r:
        return {"error": r}
    n = ctypes.c_uint32.from_buffer(buf).value
    rows = (ROW * n).from_buffer(buf, 4)
    loop = [(socket.ntohs(rw.lport & 0xFFFF), rw.pid) for rw in rows if rw.laddr == 0x0100007F]
    return {"loopback_listeners": len(loop), "port_listed": any(p == t["port"] for p, _ in loop),
            "port_pid_match": any(p == t["port"] and pid == t["pid"] for p, pid in loop)}


TASKS = {"proxy_http": proxy_http, "proxy_connect": proxy_connect, "reg_read": reg_read, "tcp_table": tcp_table}


def main():
    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out = {}
    for t in spec["tasks"]:
        t0 = time.monotonic()
        try:
            fn = TASKS.get(t["kind"])
            out[t["id"]] = fn(t) if fn else U.run_task(t, out)
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
