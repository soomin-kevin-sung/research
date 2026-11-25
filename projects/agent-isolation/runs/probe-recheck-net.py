"""Re-measurement: AppContainer curl start discrepancy and loopback vs external network.

Synthetic and harness-owned only:
  * external target is Windows' own connectivity-check endpoint (no user data sent);
  * the PATH mechanism check copies System32 curl.exe into a harness folder and sets
    ACLs only on that harness folder;
  * no raw-socket demonstration under a block policy.
Product state is redirected to a disposable profile before importing qwenpaw.
"""

import os
import sys
import json
import uuid
import shutil
import asyncio
import threading
import subprocess
import http.server
from pathlib import Path

_SCRATCH = Path(os.environ["ISO_SCRATCH"])
BASE = _SCRATCH / f"recheck-net-{uuid.uuid4().hex[:8]}"
BASE.mkdir(parents=True, exist_ok=False)
PROFILE, WORK_ROOT = BASE / "profile", BASE / "work_root"
for p in (PROFILE, WORK_ROOT):
    p.mkdir(parents=True)
USER_TEMP_ROOT = Path(os.environ["LOCALAPPDATA"]) / "Temp" / f"iso-recheck-{uuid.uuid4().hex[:8]}"
os.environ.update(USERPROFILE=str(PROFILE), HOME=str(PROFILE))

import win32security  # noqa: E402
import ntsecuritycon as nsc  # noqa: E402
from qwenpaw.sandbox.config import SandboxConfig, SandboxMode, create_sandbox  # noqa: E402
from qwenpaw.sandbox import windows_unelevated_sandbox as wu  # noqa: E402

SHELL = r"C:\Windows\System32\cmd.exe"
SYS_CURL = r"C:\Windows\System32\curl.exe"
GIT_CURL = r"C:\Program Files\Git\mingw64\bin\curl.exe"
EXTERNAL = "http://www.msftconnecttest.com/connecttest.txt"
EXTERNAL_OK = "Microsoft Connect Test"
REPS = 5


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "8")
        self.end_headers()
        self.wfile.write(b"ISO10_OK")

    def log_message(self, *a):
        pass


HTTPD = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
PORT = HTTPD.server_address[1]
threading.Thread(target=HTTPD.serve_forever, daemon=True).start()


def host(cmd):
    r = subprocess.run(f"{SHELL} /d /c {cmd}", capture_output=True, timeout=30)
    dec = lambda b: (b or b"").decode("utf-8", errors="replace").strip()[:200]  # noqa: E731
    return {"exit": r.returncode, "out": dec(r.stdout), "err": dec(r.stderr)}


async def run(sb, cmd):
    r = await sb.execute(cmd)
    return {"exit": r.exit_code, "out": (r.stdout or "").strip()[:120],
            "err": (r.stderr or "").strip()[:160], "violation": r.sandbox_violation is not None}


async def with_sandbox(ws, allow_read_all, network_allow, fn, **cfg):
    ws.mkdir(parents=True, exist_ok=True)
    sb = create_sandbox(SandboxConfig(mode=SandboxMode.WINDOWS, workspace_dir=str(ws),
                                      allow_read_all=allow_read_all, shell_executable=SHELL,
                                      timeout_seconds=20, network_allow=network_allow, **cfg))
    try:
        pc = await run(sb, "echo ok> pc.txt & type pc.txt")
        return {"positive_control_exit": pc["exit"], **(await fn(sb))}
    finally:
        await sb.stop()
        if allow_read_all:
            wu.shutdown_cleanup(log_progress=False)
        else:
            await sb.destroy()


def grant_ac_list_only(folder):
    """Harness folder only: let ALL APPLICATION PACKAGES list/traverse it, not inherit."""
    sid = win32security.ConvertStringSidToSid("S-1-15-2-1")
    sd = win32security.GetNamedSecurityInfo(str(folder), win32security.SE_FILE_OBJECT,
                                            win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    mask = nsc.FILE_LIST_DIRECTORY | nsc.FILE_TRAVERSE | nsc.FILE_READ_ATTRIBUTES | nsc.SYNCHRONIZE
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, 0, mask, sid)
    win32security.SetNamedSecurityInfo(str(folder), win32security.SE_FILE_OBJECT,
                                       win32security.DACL_SECURITY_INFORMATION, None, None, dacl, None)


def has_ac_ace(path):
    sd = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                                            win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    return any(win32security.ConvertSidToStringSid(dacl.GetAce(i)[2]) == "S-1-15-2-1"
               for i in range(dacl.GetAceCount()))


async def main():
    out = {"port": PORT}
    out["host_controls"] = {
        "external": host(f'"{SYS_CURL}" -s -m 5 {EXTERNAL}'),
        "loopback": host(f'"{SYS_CURL}" -s -m 3 http://127.0.0.1:{PORT}/'),
        "where_curl": host("where curl"),
        "loopback_exempt_list": host("CheckNetIsolation.exe LoopbackExempt -s"),
    }

    # ---- 1. AppContainer curl start matrix ----
    curl_cmds = {
        "curl.exe --version": "curl.exe --version",
        "curl --version": "curl --version",
        "system32 full path": f'"{SYS_CURL}" --version',
        "git full path": f'"{GIT_CURL}" --version',
    }

    async def curl_matrix(sb):
        res = {}
        for label, cmd in curl_cmds.items():
            r = await run(sb, cmd)
            res[label] = {"exit": r["exit"], "first_line": r["out"].splitlines()[0][:40] if r["out"] else "",
                          "err": r["err"][:60]}
        return res

    matrix = {}
    USER_TEMP_ROOT.mkdir(parents=True)
    for where, root in (("scratch", WORK_ROOT), ("user_temp", USER_TEMP_ROOT)):
        for cfg_label, cfg in (("default", {}), ("run02_like_allowlist", {"env_mode": "allowlist", "env_vars": {}})):
            ws = root / f"curl_{where}_{cfg_label}"
            matrix[f"{where}/{cfg_label}"] = await with_sandbox(ws, False, ["*"], curl_matrix, **cfg)
    out["ac_curl_matrix"] = matrix

    # ---- 2. PATH mechanism: a curl copy that AppContainer can list but not execute ----
    fakebin_listable = BASE / "fakebin_listable"
    fakebin_hidden = BASE / "fakebin_hidden"
    for d in (fakebin_listable, fakebin_hidden):
        d.mkdir()
        shutil.copy2(SYS_CURL, d / "curl.exe")
    grant_ac_list_only(fakebin_listable)
    mech = {"listable_dir_has_ac_ace": has_ac_ace(fakebin_listable),
            "copied_file_has_ac_ace": has_ac_ace(fakebin_listable / "curl.exe"),
            "hidden_dir_has_ac_ace": has_ac_ace(fakebin_hidden)}
    base_path = os.environ.get("PATH", "")
    for label, d in (("first_PATH_dir_listable_not_executable", fakebin_listable),
                     ("first_PATH_dir_not_listable", fakebin_hidden)):
        async def probe(sb):
            return {"curl --version": await run(sb, "curl --version")}
        mech[label] = await with_sandbox(WORK_ROOT / f"mech_{label}", False, ["*"], probe,
                                         env_vars={"PATH": f"{d};{base_path}"})
    out["ac_path_mechanism"] = mech

    # ---- 3. Network: external vs loopback, allow vs block, REPS each ----
    def tally(results):
        return {"n": len(results), "exits": [r["exit"] for r in results],
                "ok": sum(1 for r in results if r["exit"] == 0 and (EXTERNAL_OK in r["out"] or "ISO10_OK" in r["out"]))}

    net = {}
    for name, ara in (("restricted_token", True), ("appcontainer", False)):
        for policy_label, policy in (("allow_all", ["*"]), ("block_all", [])):
            async def netprobe(sb):
                ext, loop = [], []
                for _ in range(REPS):
                    ext.append(await run(sb, f'"{SYS_CURL}" -s -m 5 {EXTERNAL}'))
                    loop.append(await run(sb, f'"{SYS_CURL}" -s -m 3 http://127.0.0.1:{PORT}/'))
                return {"external": tally(ext), "loopback": tally(loop)}
            net[f"{name}/{policy_label}"] = await with_sandbox(
                WORK_ROOT / f"net_{name}_{policy_label}", ara, policy, netprobe)
    out["network"] = net
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        HTTPD.shutdown()
        shutil.rmtree(BASE, ignore_errors=True)
        shutil.rmtree(USER_TEMP_ROOT, ignore_errors=True)
        print(f"[cleanup] base_exists={BASE.exists()} user_temp_exists={USER_TEMP_ROOT.exists()}",
              file=sys.stderr)
