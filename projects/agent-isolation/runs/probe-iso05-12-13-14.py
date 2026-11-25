"""ISO-05 (network posture), ISO-12 (registry write access), ISO-13 (clipboard open), ISO-14 (limits).

5 trials per backend; every trial uses fresh sandboxes. The in-sandbox checks are in
probe-child-checks.py and are read-only: registry keys are opened with write access but
nothing is written, and clipboard content is never read.

AppContainer cannot execute the user-installed Python, so the harness copies the Python
runtime into its own folder and gives ALL APPLICATION PACKAGES read/execute on that copy
only. Both backends run the same copy.
"""
import os
import sys
import json
import uuid
import shutil
import asyncio
import subprocess
from pathlib import Path

SCR = Path(os.environ["ISO_SCRATCH"])
BASE = SCR / f"probe0514-{uuid.uuid4().hex[:8]}"
PROFILE = BASE / "profile"
PROFILE.mkdir(parents=True)
os.environ.update(USERPROFILE=str(PROFILE), HOME=str(PROFILE))
TRIALS = int(os.environ.get("ISO_TRIALS", "5"))

from qwenpaw.sandbox.config import SandboxConfig, SandboxMode, create_sandbox  # noqa: E402
from qwenpaw.sandbox import windows_unelevated_sandbox as wu  # noqa: E402

SHELL = r"C:\Windows\System32\cmd.exe"
CURL = r"C:\Windows\System32\curl.exe"
ALLOWED = "http://www.msftconnecttest.com/connecttest.txt"   # "Microsoft Connect Test"
OTHER = "http://www.msftncsi.com/ncsi.txt"                    # "Microsoft NCSI"
SRC_PY = Path(sys.base_prefix)
PYRT = BASE / "pyrt"
CHILD = Path(__file__).with_name("probe-child-checks.py")


def build_runtime():
    PYRT.mkdir()
    subprocess.run(["icacls", str(PYRT), "/grant", "*S-1-15-2-1:(OI)(CI)(RX)"], check=True, capture_output=True)
    for f in ("python.exe", "python3.dll", "python312.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        shutil.copy2(SRC_PY / f, PYRT / f)
    shutil.copytree(SRC_PY / "DLLs", PYRT / "DLLs")
    skip = shutil.ignore_patterns("site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip",
                                  "lib2to3", "__pycache__", "pydoc_data")
    shutil.copytree(SRC_PY / "Lib", PYRT / "Lib", ignore=skip)
    shutil.copy2(CHILD, PYRT / "child.py")


def child_cmd(mode):
    return f'"{PYRT / "python.exe"}" -I -B "{PYRT / "child.py"}" {mode}'


def parse(stdout):
    for line in (stdout or "").splitlines():
        if line.startswith("ISOJSON "):
            return json.loads(line[8:])
    return None


def host(cmd):
    r = subprocess.run(f"{SHELL} /d /c {cmd}", capture_output=True, timeout=60)
    return r.returncode, (r.stdout or b"").decode("utf-8", errors="replace")


async def run(sb, cmd):
    r = await sb.execute(cmd)
    return {"exit": r.exit_code, "out": (r.stdout or "").strip(), "err": (r.stderr or "").strip()[:200]}


def curl_result(r, expect):
    return {"exit": r["exit"], "ok": r["exit"] == 0 and expect in r["out"]}


async def with_sandbox(tag, allow_read_all, fn, **cfg):
    ws = BASE / "ws" / tag
    ws.mkdir(parents=True)
    cfg.setdefault("network_allow", [])
    sb = create_sandbox(SandboxConfig(mode=SandboxMode.WINDOWS, workspace_dir=str(ws), allow_read_all=allow_read_all,
                                      shell_executable=SHELL, timeout_seconds=60, **cfg))
    try:
        pc = await run(sb, "echo ok> pc.txt & type pc.txt")
        return {"positive_control_ok": pc["exit"] == 0 and pc["out"] == "ok", **(await fn(sb))}
    finally:
        await sb.stop()
        if allow_read_all:
            wu.shutdown_cleanup(log_progress=False)
        else:
            await sb.destroy()


async def checks_default(sb):
    out = {}
    for mode in ("reg", "clip"):
        r = await run(sb, child_cmd(mode))
        out[mode] = parse(r["out"]) or {"raw_exit": r["exit"], "raw": r["out"][:200], "err": r["err"]}
    out["net_block_plain"] = curl_result(await run(sb, f'"{CURL}" -s -m 8 {ALLOWED}'), "Microsoft Connect Test")
    out["net_block_noproxy"] = curl_result(await run(sb, f'"{CURL}" -s -m 8 --noproxy "*" {ALLOWED}'),
                                           "Microsoft Connect Test")
    return out


async def checks_limits(sb):
    r = await run(sb, child_cmd("limits"))
    return {"limits": parse(r["out"]) or {"raw_exit": r["exit"], "raw": r["out"][:200], "err": r["err"]}}


async def checks_domain(sb):
    return {"listed_domain": curl_result(await run(sb, f'"{CURL}" -s -m 8 {ALLOWED}'), "Microsoft Connect Test"),
            "unlisted_domain": curl_result(await run(sb, f'"{CURL}" -s -m 8 {OTHER}'), "Microsoft NCSI")}


async def main():
    build_runtime()
    out = {"host_controls": {}}
    for mode in ("reg", "clip", "limits"):
        r = subprocess.run([str(PYRT / "python.exe"), "-I", "-B", str(PYRT / "child.py"), mode],
                           capture_output=True, timeout=60)
        so = (r.stdout or b"").decode("utf-8", errors="replace")
        out["host_controls"][mode] = parse(so) or {"raw_exit": r.returncode, "raw": so[:200]}
    out["host_controls"]["listed_domain"] = host(f'"{CURL}" -s -m 8 {ALLOWED}')
    out["host_controls"]["unlisted_domain"] = host(f'"{CURL}" -s -m 8 {OTHER}')
    for name, ara in (("restricted_token", True), ("appcontainer", False)):
        for i in range(TRIALS):
            for label, fn, cfg in (("default_block_net", checks_default, {}),
                                   ("limits_p1_m64", checks_limits, {"max_processes": 1, "max_memory_mb": 64}),
                                   ("domain_allowlist", checks_domain, {"network_allow": ["www.msftconnecttest.com"]})):
                key = f"{name}/{label}"
                try:
                    res = await with_sandbox(f"{name}_{label}_{i}", ara, fn, **cfg)
                except Exception as e:
                    res = {"error": repr(e)[:200]}
                out.setdefault(key, []).append(res)
    # The product prints progress lines to stdout, so the result goes to its own file.
    Path(os.environ["ISO_OUT"]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        shutil.rmtree(BASE, ignore_errors=True)
        print(f"[cleanup] base_exists={BASE.exists()}", file=sys.stderr)
