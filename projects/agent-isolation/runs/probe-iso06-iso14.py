"""ISO-06 (dedicated temp + cleanup timeline) and ISO-14 (declared vs effective limits).

First pass. Its ISO-14 results stand. Its ISO-06 part is superseded by
probe-iso06-cleanup.py: here the AppContainer marker is checked under the host
TEMP instead of the child's TEMP, and the whole-DACL diff also lists ACEs that
the parent folders already carried.

Defensive measurement of QwenPaw 2.3.0.post1's two non-admin Windows backends.
All product state is redirected into a disposable test profile (USERPROFILE/HOME
set BEFORE importing qwenpaw), so the real ~/.qwenpaw is never read or written.
Synthetic workloads only; no known-bypass reproduction.
"""

import os
import sys
import json
import uuid
import shutil
import logging
import asyncio
from pathlib import Path

# Plain mkdir (NOT tempfile.mkdtemp): mkdtemp yields an owner-only DACL that made
# the Restricted Token backend falsely fail ISO-01 in run 2026-11-23-02.
_SCRATCH = Path(os.environ["ISO_SCRATCH"])
BASE = _SCRATCH / f"iso-temp-limits-{uuid.uuid4().hex[:8]}"
BASE.mkdir(parents=True, exist_ok=False)
PROFILE = BASE / "profile"
CTRL_TEMP = BASE / "ctrl_temp"
WORK_ROOT = BASE / "work_root"
for p in (PROFILE, CTRL_TEMP, WORK_ROOT):
    p.mkdir(parents=True, exist_ok=True)

REAL_USERPROFILE = os.environ.get("USERPROFILE", "")
os.environ["USERPROFILE"] = str(PROFILE)
os.environ["HOME"] = str(PROFILE)
os.environ["TEMP"] = str(CTRL_TEMP)
os.environ["TMP"] = str(CTRL_TEMP)

records = []


class _Grab(logging.Handler):
    def emit(self, r):
        try:
            records.append(f"{r.levelname}: {r.getMessage()}")
        except Exception:
            pass


_h = _Grab()
_h.setLevel(logging.DEBUG)
_ql = logging.getLogger("qwenpaw")
_ql.addHandler(_h)
_ql.setLevel(logging.DEBUG)

import win32security  # noqa: E402
from qwenpaw.sandbox.config import SandboxConfig, SandboxMode  # noqa: E402
from qwenpaw.sandbox.config import create_sandbox, probe_sandbox_support  # noqa: E402
from qwenpaw.sandbox import windows_unelevated_sandbox as wu  # noqa: E402
from qwenpaw.sandbox import windows_appcontainer_sandbox as wa  # noqa: E402

SHELL = r"C:\Windows\System32\cmd.exe"
QP = PROFILE / ".qwenpaw"


def dacl_aces(path):
    """Return a sorted list of (type, sid, mask_hex) for explicit+inherited ACEs."""
    sd = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION
    )
    dacl = sd.GetSecurityDescriptorDacl()
    out = []
    if dacl is None:
        return out
    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        (ace_type, flags), mask, sid = ace[0], ace[1], ace[2]
        out.append((int(ace_type), win32security.ConvertSidToStringSid(sid), hex(mask), int(flags)))
    return sorted(out)


def added(base, now):
    b = set(base)
    return [a for a in now if a not in b]


def state_files():
    if not QP.exists():
        return []
    return sorted(str(p.relative_to(QP)).replace("\\", "/") for p in QP.rglob("*") if p.is_file())


async def run_cmd(sb, cmd):
    r = await sb.execute(cmd)
    return {
        "exit": r.exit_code,
        "out": (r.stdout or "").strip(),
        "err": (r.stderr or "").strip(),
        "timed_out": r.timed_out,
        "violation": r.sandbox_violation,
    }


async def iso06(name, allow_read_all):
    ws = WORK_ROOT / f"iso06_{name}"
    ws.mkdir(parents=True, exist_ok=True)
    marker = CTRL_TEMP / f"iso06_{name}_marker.txt"
    t0 = dacl_aces(ws)
    cfg = SandboxConfig(
        mode=SandboxMode.WINDOWS, workspace_dir=str(ws), allow_read_all=allow_read_all,
        shell_executable=SHELL, timeout_seconds=15,
    )
    sb = create_sandbox(cfg)
    backend_class = type(sb).__name__

    ws_control = await run_cmd(sb, r"echo ws-ok> ws_control.txt & type ws_control.txt")
    temp_probe = await run_cmd(sb, r"echo TEMP=%TEMP%& echo TMP=%TMP%& echo USERPROFILE=%USERPROFILE%")
    write_probe = await run_cmd(
        sb, r'echo iso06-child> "%TEMP%\iso06_{0}_marker.txt" & type "%TEMP%\iso06_{0}_marker.txt"'.format(name)
    )
    t1_aces, t1_state = added(t0, dacl_aces(ws)), state_files()

    await sb.stop()
    t2_aces, t2_state = added(t0, dacl_aces(ws)), state_files()
    marker_after_stop = marker.exists()

    cleanup_call = None
    try:
        if allow_read_all:
            cleanup_call = "windows_unelevated_sandbox.shutdown_cleanup()"
            wu.shutdown_cleanup(log_progress=False)
        else:
            cleanup_call = "WindowsAppContainerSandbox.destroy()"
            await sb.destroy()
    except Exception as e:
        cleanup_call = f"{cleanup_call} raised {e!r}"
    t3_aces, t3_state = added(t0, dacl_aces(ws)), state_files()
    marker_after_cleanup = marker.exists()
    ws_file_after_cleanup = (ws / "ws_control.txt").exists()

    if marker.exists():
        marker.unlink()  # harness removes the child's temp artifact itself

    return {
        "backend_class": backend_class,
        "ctrl_temp": str(CTRL_TEMP),
        "workspace_positive_control": ws_control,
        "child_env_probe": temp_probe,
        "child_write_to_inherited_temp": write_probe,
        "T1_after_execute": {"added_aces": t1_aces, "state_files": t1_state},
        "T2_after_stop": {"added_aces": t2_aces, "state_files": t2_state,
                          "child_temp_marker_exists": marker_after_stop},
        "T3_after_cleanup": {"cleanup_call": cleanup_call, "added_aces": t3_aces,
                             "state_files": t3_state,
                             "child_temp_marker_exists": marker_after_cleanup,
                             "workspace_result_file_exists": ws_file_after_cleanup},
    }


async def iso14(name, allow_read_all):
    ws = WORK_ROOT / f"iso14_{name}"
    ws.mkdir(parents=True, exist_ok=True)
    records.clear()
    cfg = SandboxConfig(
        mode=SandboxMode.WINDOWS, workspace_dir=str(ws), allow_read_all=allow_read_all,
        shell_executable=SHELL, timeout_seconds=15, max_processes=1, max_memory_mb=64,
    )
    sb = create_sandbox(cfg)
    report = [m for m in records if "does not enforce" in m]
    spawn = await run_cmd(sb, r"for /l %c in (1,1,3) do @cmd /c echo child-%c")
    await sb.stop()
    try:
        if allow_read_all:
            wu.shutdown_cleanup(log_progress=False)
        else:
            await sb.destroy()
    except Exception:
        pass
    return {
        "declared": {"max_processes": 1, "max_memory_mb": 64},
        "product_unenforced_report": report,
        "child_spawn_x3_under_max_processes_1": spawn,
    }


async def main():
    cap = probe_sandbox_support()
    result = {
        "python": sys.version.split()[0],
        "capability": {"supported": cap.supported, "mode": str(cap.mode), "reason": cap.reason},
        "is_admin": bool(wu._is_admin()),
        "state_dir_redirected_to_profile": str(wu._qwenpaw_state_dir).startswith(str(PROFILE))
        and str(wa._state_dir).startswith(str(PROFILE)),
        "real_userprofile_untouched": REAL_USERPROFILE != str(PROFILE),
        "backends": {},
    }
    for name, ara in (("restricted_token", True), ("appcontainer", False)):
        entry = {}
        for label, fn in (("iso06", iso06), ("iso14", iso14)):
            try:
                entry[label] = await fn(name, ara)
            except Exception as e:
                import traceback
                entry[label] = {"error": repr(e), "tb": traceback.format_exc()[-1500:]}
        result["backends"][name] = entry
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        shutil.rmtree(BASE, ignore_errors=True)
        print(f"[cleanup] removed {BASE.name}: exists_after={BASE.exists()}", file=sys.stderr)
