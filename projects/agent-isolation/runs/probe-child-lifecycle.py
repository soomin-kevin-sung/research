"""ISO-06/14 child-process lifecycle, 5 trials per backend and scenario.

Scenarios (synthetic `ping` to 127.0.0.1 only, identified by an unusual -n count):
  timeout    : the shell waits on a foreground child; command limit 3 s.
  background : the shell starts a detached child with `start /b` and exits normally.
A child is "the same" only if PID and creation time both match. Children are
checked right after the call returns, 5 s later, after stop(), and after the
product cleanup. If a call does not return, the child state is recorded at the
cap and then only that harness-owned child is terminated.
"""

import os
import sys
import json
import time
import uuid
import shutil
import asyncio
from pathlib import Path

import psutil

_SCRATCH = Path(os.environ["ISO_SCRATCH"])
BASE = _SCRATCH / f"child-life-{uuid.uuid4().hex[:8]}"
BASE.mkdir(parents=True, exist_ok=False)
PROFILE = BASE / "profile"
PROFILE.mkdir()
os.environ.update(USERPROFILE=str(PROFILE), HOME=str(PROFILE))

from qwenpaw.sandbox.config import SandboxConfig, SandboxMode, create_sandbox  # noqa: E402
from qwenpaw.sandbox import windows_unelevated_sandbox as wu  # noqa: E402

SHELL = r"C:\Windows\System32\cmd.exe"
TRIALS = 5
# `ping` cannot run inside the AppContainer backend ("Unable to contact IP driver"),
# so the child is a marked cmd.exe loop that runs in both backends until stopped.
LOOP = 'cmd /d /c "set {m}=1& for /l %i in (0,0,1) do @ver>nul"'
SCEN = {
    "timeout": {"count": "ISO41", "limit": 3, "cap": 9.0,
                "cmd": LOOP.format(m="ISO41") + " & echo after"},
    "background": {"count": "ISO43", "limit": 20, "cap": 10.0,
                   "cmd": 'start "" /b ' + LOOP.format(m="ISO43") + " >nul 2>&1 & echo SHELL_DONE"},
    # Same background child, but the command limit (4 s) falls inside the cap (12 s).
    "background_limit4": {"count": "ISO43", "limit": 4, "cap": 12.0,
                          "cmd": 'start "" /b ' + LOOP.format(m="ISO43") + " >nul 2>&1 & echo SHELL_DONE"},
}
if len(sys.argv) > 1:  # optional scenario filter, e.g. `background_limit4`
    SCEN = {k: v for k, v in SCEN.items() if k in sys.argv[1:]}


def find_child(marker):
    """The marked loop is started as `cmd /d /c ...`; the product's outer shell uses `/c`."""
    for p in psutil.process_iter(["name", "cmdline", "create_time"]):
        try:
            argv = p.info["cmdline"] or []
            if ((p.info["name"] or "").lower() == "cmd.exe" and len(argv) > 1
                    and argv[1].lower() == "/d" and marker in " ".join(argv)):
                return (p.pid, p.info["create_time"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None


def alive(ident):
    if not ident:
        return None
    try:
        return psutil.Process(ident[0]).create_time() == ident[1]
    except psutil.NoSuchProcess:
        return False


def kill_leftovers(count):
    killed = []
    while (c := find_child(count)) is not None:
        try:
            psutil.Process(c[0]).kill()
            killed.append(c[0])
        except psutil.NoSuchProcess:
            pass
        time.sleep(0.2)
    return killed


async def trial(backend, allow_read_all, scen_name, idx):
    s = SCEN[scen_name]
    ws = BASE / f"{backend}_{scen_name}_{idx}"
    ws.mkdir()
    sb = create_sandbox(SandboxConfig(mode=SandboxMode.WINDOWS, workspace_dir=str(ws),
                                      allow_read_all=allow_read_all, shell_executable=SHELL,
                                      timeout_seconds=s["limit"], network_allow=["*"]))
    rec = {}
    try:
        pc = await sb.execute("echo ok> pc.txt & type pc.txt")
        rec["positive_control_exit"] = pc.exit_code
        t0 = time.monotonic()
        task = asyncio.create_task(sb.execute(s["cmd"]))
        ident = None
        while ident is None and not task.done() and time.monotonic() - t0 < 4:
            ident = find_child(s["count"])
            await asyncio.sleep(0.2)
        if ident is None:  # background child may appear just as the shell exits
            ident = find_child(s["count"])
        rec["child_observed"] = ident is not None
        done, _ = await asyncio.wait({task}, timeout=max(0.0, s["cap"] - (time.monotonic() - t0)))
        rec["returned_within_cap"] = bool(done)
        if done:
            r = task.result()
            rec["call"] = {"ms": round((time.monotonic() - t0) * 1000), "exit": r.exit_code,
                           "timed_out": r.timed_out, "out": (r.stdout or "").strip()[:40]}
            rec["child_alive_at_return"] = alive(ident)
            await asyncio.sleep(5)
            rec["child_alive_plus5s"] = alive(ident)
        else:
            rec["child_alive_at_cap"] = alive(ident)
            if ident:
                psutil.Process(ident[0]).kill()
                rec["harness_killed_child"] = True
            try:
                r = await asyncio.wait_for(task, 15)
                rec["call_after_kill"] = {"ms": round((time.monotonic() - t0) * 1000),
                                          "exit": r.exit_code, "timed_out": r.timed_out}
            except asyncio.TimeoutError:
                rec["call_after_kill"] = "still not returned after 15 s"
        await sb.stop()
        rec["child_alive_after_stop"] = alive(ident)
    finally:
        if allow_read_all:
            wu.shutdown_cleanup(log_progress=False)
        else:
            await sb.destroy()
        rec["child_alive_after_cleanup"] = alive(ident)
        rec["harness_killed_leftovers"] = kill_leftovers(s["count"])
    return rec


async def main():
    out = {}
    for backend, ara in (("restricted_token", True), ("appcontainer", False)):
        for scen in SCEN:
            out[f"{backend}/{scen}"] = []
            for i in range(TRIALS):
                try:
                    out[f"{backend}/{scen}"].append(await trial(backend, ara, scen, i))
                except Exception as e:
                    out[f"{backend}/{scen}"].append({"error": repr(e)})
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        for c in SCEN.values():
            kill_leftovers(c["count"])
        shutil.rmtree(BASE, ignore_errors=True)
