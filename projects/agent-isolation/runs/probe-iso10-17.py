"""ISO-10/11/12/17 defensive measurement on QwenPaw 2.3.0.post1 non-admin Windows backends.

Synthetic, host-controlled resources only:
  * loopback HTTP test server and named-pipe servers run in this harness process;
  * registry is READ-ONLY (only exit code / line count recorded, never values,
    except the non-personal OS build number);
  * no raw-socket demonstration under a block policy (the product's own
    unenforced-constraint warning is used as evidence instead);
  * no spoofed denial text: ISO-17 uses a benign, unrelated command failure.
Product state is redirected to a disposable profile before importing qwenpaw.
"""

import os
import sys
import json
import uuid
import time
import shutil
import asyncio
import logging
import threading
import subprocess
import http.server
from pathlib import Path

_SCRATCH = Path(os.environ["ISO_SCRATCH"])
BASE = _SCRATCH / f"iso10-17-{uuid.uuid4().hex[:8]}"
BASE.mkdir(parents=True, exist_ok=False)  # plain mkdir (no owner-only DACL)
PROFILE, WORK_ROOT = BASE / "profile", BASE / "work_root"
for p in (PROFILE, WORK_ROOT):
    p.mkdir(parents=True, exist_ok=True)
os.environ.update(USERPROFILE=str(PROFILE), HOME=str(PROFILE))

warnings = []


class _Grab(logging.Handler):
    def emit(self, r):
        if r.levelno >= logging.WARNING:
            warnings.append(r.getMessage())


logging.getLogger("qwenpaw").addHandler(_Grab())

import pywintypes  # noqa: E402
import win32file  # noqa: E402
import win32pipe  # noqa: E402
from qwenpaw.sandbox.config import SandboxConfig, SandboxMode, create_sandbox  # noqa: E402
from qwenpaw.sandbox import windows_unelevated_sandbox as wu  # noqa: E402

SHELL = r"C:\Windows\System32\cmd.exe"
SYS_CURL = r"C:\Windows\System32\curl.exe"
BASE_PY = sys._base_executable
REG_QUERIES = {
    "hkcu_keyboard_layout": r'"HKCU\Keyboard Layout\Preload"',
    "hkcu_console": r'"HKCU\Console"',
    "hkcu_environment": r'"HKCU\Environment"',
    "hklm_build": r'"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild',
}

# ---------------- host-controlled synthetic services ----------------


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ISO10_OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPD = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
PORT = HTTPD.server_address[1]
threading.Thread(target=HTTPD.serve_forever, daemon=True).start()


def pipe_server(name, mode, payload=b"", store=None):
    """Serve up to 3 concurrent instances (cmd may open a pipe path more than once).

    mode='recv': record what a client writes. mode='send': write payload to each client.
    Security descriptor None -> the default named-pipe DACL.
    """
    store["connections"] = 0
    store["stop"] = False
    # Pre-create every instance up front: cmd's `type` opens the path more than once,
    # and a serially re-created instance races with the second open (ERROR_PIPE_BUSY).
    handles = [
        win32pipe.CreateNamedPipe(
            name, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
            win32pipe.PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, None)
        for _ in range(3)
    ]

    def serve(h):
        if True:
            try:
                try:
                    win32pipe.ConnectNamedPipe(h, None)
                except pywintypes.error as e:
                    if e.winerror != 535:  # ERROR_PIPE_CONNECTED is fine
                        store["server_error"] = e.winerror
                        return
                if store["stop"]:
                    return
                store["connections"] += 1
                if mode == "recv":
                    _, data = win32file.ReadFile(h, 4096)
                    if data:
                        store["received"] = data.decode(errors="replace").strip()
                else:
                    win32file.WriteFile(h, payload)
                    win32file.FlushFileBuffers(h)
            except pywintypes.error as e:
                store.setdefault("io_errors", []).append(e.winerror)
            finally:
                try:
                    win32pipe.DisconnectNamedPipe(h)
                except pywintypes.error:
                    pass
                h.Close()

    threads = [threading.Thread(target=serve, args=(h,), daemon=True) for h in handles]
    for t in threads:
        t.start()
    return threads


def unblock(name, threads, store):
    """Stop the server: connect from the host until every instance exits (not counted)."""
    store["stop"] = True
    for _ in range(6):
        if not any(t.is_alive() for t in threads):
            break
        try:
            c = win32file.CreateFile(name, 0xC0000000, 0, None, 3, 0, None)
            c.Close()
        except pywintypes.error:
            pass
        for t in threads:
            t.join(0.3)


def host_cmd(cmd):
    # String form: passed verbatim, so cmd.exe sees the same quoting as the sandbox shell.
    r = subprocess.run(f"{SHELL} /d /c {cmd}", capture_output=True, text=True, timeout=15)
    return {"exit": r.returncode, "out": r.stdout.strip(), "err": r.stderr.strip()}


# ---------------- sandbox helpers ----------------


async def run(sb, cmd):
    r = await sb.execute(cmd)
    return {"exit": r.exit_code, "out": (r.stdout or "").strip()[:400],
            "err": (r.stderr or "").strip()[:400], "violation": r.sandbox_violation is not None,
            "timed_out": r.timed_out}


async def cleanup(sb, allow_read_all):
    await sb.stop()
    if allow_read_all:
        wu.shutdown_cleanup(log_progress=False)
    else:
        await sb.destroy()


DEVSERVER = (
    "import socket\n"
    "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1)\n"
    "c=socket.create_connection(s.getsockname(), timeout=3); a,_=s.accept()\n"
    "c.sendall(b'x'); print('DEVSERVER_OK', a.recv(1)==b'x')\n"
)


async def backend(name, allow_read_all):
    res = {}
    # ---- ISO-10 allow condition (network_allow=['*']) + ISO-11/12/17 ----
    ws = WORK_ROOT / f"{name}_allow"
    ws.mkdir()
    (ws / "devserver.py").write_text(DEVSERVER, encoding="ascii")
    warnings.clear()
    sb = create_sandbox(SandboxConfig(mode=SandboxMode.WINDOWS, workspace_dir=str(ws),
                                      allow_read_all=allow_read_all, shell_executable=SHELL,
                                      timeout_seconds=15, network_allow=["*"]))
    res["backend_class"] = type(sb).__name__
    res["positive_control"] = await run(sb, r"echo ok> pc.txt & type pc.txt")
    iso10 = {
        "curl_fullpath_version": await run(sb, f'"{SYS_CURL}" --version'),
        "curl_path_resolved_version": await run(sb, "curl --version"),
        "curl_fullpath_to_host_loopback": await run(sb, f'"{SYS_CURL}" -s -m 3 http://127.0.0.1:{PORT}/'),
        "devserver_bind_connect_loopback": await run(sb, f'"{BASE_PY}" -I -B devserver.py'),
    }
    # ---- ISO-11 IPC ----
    anon = await run(sb, "echo iso11-anon| findstr iso11-anon")
    pw_name = rf"\\.\pipe\iso11-w-{uuid.uuid4().hex[:8]}"
    store_w = {}
    tw = pipe_server(pw_name, "recv", store=store_w)
    sb_write = await run(sb, f"echo iso11-from-sandbox> {pw_name}")
    unblock(pw_name, tw, store_w)
    pr_name = rf"\\.\pipe\iso11-r-{uuid.uuid4().hex[:8]}"
    store_r = {}
    tr = pipe_server(pr_name, "send", payload=b"iso11-from-host\r\n", store=store_r)
    sb_read = await run(sb, f"type {pr_name}")
    unblock(pr_name, tr, store_r)
    iso11 = {
        "intra_sandbox_anonymous_pipe": anon,
        "write_to_host_named_pipe": {**sb_write, "server_connections": store_w["connections"],
                                     "host_received": store_w.get("received")},
        "read_from_host_named_pipe": {**sb_read, "server_connections": store_r["connections"],
                                      "payload_seen": "iso11-from-host" in sb_read["out"]},
    }
    # ---- ISO-12 registry (read-only; values never recorded) ----
    iso12 = {}
    for label, q in REG_QUERIES.items():
        r = await run(sb, f"reg query {q}")
        iso12[label] = {"exit": r["exit"], "lines": len(r["out"].splitlines()), "err": r["err"][:120]}
        if label == "hklm_build":
            iso12[label]["has_26200"] = "26200" in r["out"]
    # ---- ISO-17 classifier: benign unrelated failure vs real OS denial ----
    outside = BASE / f"outside_{name}.txt"
    iso17 = {
        "benign_missing_file": await run(sb, "type iso17_definitely_missing.txt"),
        "real_denial_write_outside_workspace": await run(sb, f'echo x> "{outside}"'),
        "outside_file_created": None,
    }
    iso17["outside_file_created"] = outside.exists()
    res["allow_warnings"] = list(warnings)
    await cleanup(sb, allow_read_all)

    # ---- ISO-10 block condition (network_allow=[]): proxy-respecting client only ----
    wsb = WORK_ROOT / f"{name}_block"
    wsb.mkdir()
    warnings.clear()
    sbb = create_sandbox(SandboxConfig(mode=SandboxMode.WINDOWS, workspace_dir=str(wsb),
                                       allow_read_all=allow_read_all, shell_executable=SHELL,
                                       timeout_seconds=15, network_allow=[]))
    iso10["block_curl_fullpath_to_host_loopback"] = await run(
        sbb, f'"{SYS_CURL}" -s -m 3 http://127.0.0.1:{PORT}/')
    res["block_warnings"] = list(warnings)
    await cleanup(sbb, allow_read_all)

    res.update(iso10=iso10, iso11=iso11, iso12=iso12, iso17=iso17)
    return res


async def main():
    out = {"port": PORT, "base_python": BASE_PY, "is_admin": bool(wu._is_admin())}
    # Host positive controls for the same synthetic resources
    hc = {"curl_fullpath_to_loopback": host_cmd(f'"{SYS_CURL}" -s -m 3 http://127.0.0.1:{PORT}/')}
    for label, q in REG_QUERIES.items():
        r = host_cmd(f"reg query {q}")
        hc[f"reg_{label}"] = {"exit": r["exit"], "lines": len(r["out"].splitlines())}
    pn = rf"\\.\pipe\iso11-hc-{uuid.uuid4().hex[:8]}"
    st = {}
    t = pipe_server(pn, "recv", store=st)
    hc["pipe_write"] = host_cmd(f"echo iso11-host> {pn}")
    unblock(pn, t, st)
    hc["pipe_write"]["host_received"] = st.get("received")
    pr = rf"\\.\pipe\iso11-hcr-{uuid.uuid4().hex[:8]}"
    st2 = {}
    t2 = pipe_server(pr, "send", payload=b"iso11-from-host\r\n", store=st2)
    r2 = host_cmd(f"type {pr}")
    unblock(pr, t2, st2)
    hc["pipe_read"] = {"exit": r2["exit"], "err": r2["err"][:120],
                       "payload_seen": "iso11-from-host" in r2["out"]}
    out["host_controls"] = hc
    for name, ara in (("restricted_token", True), ("appcontainer", False)):
        try:
            out[name] = await backend(name, ara)
        except Exception as e:
            import traceback
            out[name] = {"error": repr(e), "tb": traceback.format_exc()[-1500:]}
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        HTTPD.shutdown()
        shutil.rmtree(BASE, ignore_errors=True)
