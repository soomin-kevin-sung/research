"""ISO-06 abnormal-termination path for the Restricted Token backend only.

Orchestrator (this file without args) never imports qwenpaw, so nothing is
registered against the real profile. Workers run with USERPROFILE/HOME pointed
at a disposable profile:
  worker crash   -> create sandbox, start a long child, then os._exit(0)
                    (no stop(), no atexit cleanup)
  worker cleanup -> a NEW process calls shutdown_cleanup() on the same profile
All residue stays inside the scratchpad (workspace ACE, test-profile metadata).
"""

import os
import sys
import json
import time
import uuid
import shutil
import subprocess
from pathlib import Path

PING_COUNT = 37  # unusual count used to identify this test's child by command line


def worker(mode, ws):
    import asyncio
    from qwenpaw.sandbox.config import SandboxConfig, SandboxMode, create_sandbox
    from qwenpaw.sandbox import windows_unelevated_sandbox as wu

    if mode == "cleanup":
        wu.shutdown_cleanup(log_progress=False)
        print("CLEANUP_DONE", flush=True)
        return

    async def go():
        sb = create_sandbox(SandboxConfig(
            mode=SandboxMode.WINDOWS, workspace_dir=ws, allow_read_all=True,
            shell_executable=r"C:\Windows\System32\cmd.exe", timeout_seconds=60))
        task = asyncio.create_task(sb.execute(f"ping -n {PING_COUNT} 127.0.0.1 >nul & echo done"))
        await asyncio.sleep(8)  # orchestrator observes the child during this window
        print(f"CRASHING owner_pid={os.getpid()} class={type(sb).__name__}", flush=True)
        os._exit(0)  # abnormal end: skips stop(), destroy() and atexit handlers
        await task

    asyncio.run(go())


def explicit_aces(path):
    import win32security
    sd = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                                            win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    out = set()
    for i in range(dacl.GetAceCount()):
        (t, f), m, s = dacl.GetAce(i)[:3]
        if not f & 0x10:
            out.add(f"{win32security.ConvertSidToStringSid(s)} {m:#x}")
    return out


def ping_children():
    ps = ("Get-CimInstance Win32_Process -Filter \"Name='PING.EXE'\" | "
          f"Where-Object {{ $_.CommandLine -like '*-n {PING_COUNT} *' }} | "
          "ForEach-Object { \"$($_.ProcessId)|$($_.CreationDate)\" }")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True)
    return [x for x in r.stdout.split() if x]


def orchestrate():
    scratch = Path(os.environ["ISO_SCRATCH"])
    base = scratch / f"iso06crash-{uuid.uuid4().hex[:8]}"
    profile, ws = base / "profile", base / "work"
    profile.mkdir(parents=True)
    ws.mkdir()
    env = dict(os.environ, USERPROFILE=str(profile), HOME=str(profile))
    meta_dir = profile / ".qwenpaw" / "unelevated_sandboxes"
    res = {}
    try:
        t0 = explicit_aces(ws)
        p = subprocess.Popen([sys.executable, __file__, "worker", "crash", str(ws)], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        before = []
        for _ in range(12):  # poll up to ~6s while the worker is still alive
            time.sleep(0.5)
            before = ping_children()
            if before:
                break
        res["before_crash"] = {"worker_alive": p.poll() is None, "ping_child_alive": before,
                               "added_explicit_aces": sorted(explicit_aces(ws) - t0)}
        out, _ = p.communicate(timeout=60)
        res["crash_worker"] = {"exit": p.returncode,
                               "stdout": [l for l in out.splitlines() if "CRASHING" in l]}
        res["after_crash_immediate"] = {
            "added_explicit_aces": sorted(explicit_aces(ws) - t0),
            "metadata_json": sorted(x.name for x in meta_dir.glob("*.json")) if meta_dir.exists() else [],
            "ping_child_alive": ping_children(),
        }
        time.sleep(5)
        res["after_crash_plus5s"] = {"ping_child_alive": ping_children()}
        q = subprocess.run([sys.executable, __file__, "worker", "cleanup", str(ws)], env=env,
                           capture_output=True, text=True, timeout=120)
        res["cleanup_worker"] = {"exit": q.returncode, "done": "CLEANUP_DONE" in q.stdout}
        res["after_next_process_cleanup"] = {
            "added_explicit_aces": sorted(explicit_aces(ws) - t0),
            "metadata_json": sorted(x.name for x in meta_dir.glob("*.json")) if meta_dir.exists() else [],
            "failed_cleanup_dir": (profile / ".qwenpaw" / "failed_cleanup").exists(),
        }
    finally:
        leftover = ping_children()
        for entry in leftover:  # harness-owned synthetic child only (identified by -n 37)
            subprocess.run(["taskkill", "/PID", entry.split("|")[0], "/F"], capture_output=True)
        res["harness_killed_leftover_children"] = leftover
        shutil.rmtree(base, ignore_errors=True)
        res["harness_tree_removed"] = not base.exists()
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "worker":
        worker(sys.argv[2], sys.argv[3])
    else:
        orchestrate()
