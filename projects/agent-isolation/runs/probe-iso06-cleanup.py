"""ISO-06 re-measurement: dedicated temp location + cleanup timeline (explicit ACEs only).

Defensive, synthetic-only. Product state is redirected into a disposable test
profile (USERPROFILE/HOME set BEFORE importing qwenpaw). The AppContainer
profile is created by Windows under the real %LOCALAPPDATA%\\Packages, so this
script verifies it and its HKCU mapping are removed by the product's destroy().
"""

import os
import re
import sys
import json
import uuid
import shutil
import asyncio
import winreg
from pathlib import Path

_SCRATCH = Path(os.environ["ISO_SCRATCH"])
BASE = _SCRATCH / f"iso06v2-{uuid.uuid4().hex[:8]}"
BASE.mkdir(parents=True, exist_ok=False)  # plain mkdir: avoid mkdtemp owner-only DACL
PROFILE, CTRL_TEMP, WORK_ROOT = BASE / "profile", BASE / "ctrl_temp", BASE / "work_root"
for p in (PROFILE, CTRL_TEMP, WORK_ROOT):
    p.mkdir(parents=True, exist_ok=True)

REAL_LOCALAPPDATA = os.environ["LOCALAPPDATA"]
os.environ.update(USERPROFILE=str(PROFILE), HOME=str(PROFILE), TEMP=str(CTRL_TEMP), TMP=str(CTRL_TEMP))

import win32security  # noqa: E402
from qwenpaw.sandbox.config import SandboxConfig, SandboxMode, create_sandbox  # noqa: E402
from qwenpaw.sandbox import windows_unelevated_sandbox as wu  # noqa: E402

SHELL = r"C:\Windows\System32\cmd.exe"
QP = PROFILE / ".qwenpaw"
MAPPINGS = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings"


def explicit_aces(path):
    sd = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                                            win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    out = []
    for i in range(dacl.GetAceCount() if dacl else 0):
        (t, flags), mask, sid = dacl.GetAce(i)[:3]
        if not flags & 0x10:  # skip INHERITED_ACE
            out.append(f"{win32security.ConvertSidToStringSid(sid)} mask={mask:#x} flags={flags:#x}")
    return sorted(out)


def state_files():
    return sorted(str(p.relative_to(QP)).replace("\\", "/") for p in QP.rglob("*")
                  if p.is_file() and "dependency-environments" not in str(p)) if QP.exists() else []


def qwenpaw_mappings():
    found = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, MAPPINGS) as k:
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(k, sid) as sk:
                        moniker = winreg.QueryValueEx(sk, "Moniker")[0]
                    if str(moniker).startswith("qwenpaw"):
                        found.append(f"{moniker} {sid}")
                except OSError:
                    pass
    except OSError:
        pass
    return sorted(found)


async def run(sb, cmd):
    r = await sb.execute(cmd)
    return {"exit": r.exit_code, "out": (r.stdout or "").strip(), "err": (r.stderr or "").strip()}


def snap(ws, marker, pkg):
    return {
        "explicit_aces": explicit_aces(ws),
        "state_files": state_files(),
        "child_temp_marker_exists": marker.exists() if marker else None,
        "appcontainer_profile_dir_exists": pkg.exists() if pkg else None,
        "hkcu_qwenpaw_mappings": qwenpaw_mappings(),
    }


async def case(label, allow_read_all, temp_in_workspace=False):
    ws = WORK_ROOT / label
    ws.mkdir(parents=True, exist_ok=True)
    env_vars = {}
    if temp_in_workspace:
        (ws / "tmp").mkdir(exist_ok=True)
        env_vars = {"TEMP": str(ws / "tmp"), "TMP": str(ws / "tmp")}
    res = {"T0_before_sandbox": {"explicit_aces": explicit_aces(ws)}}
    cfg = SandboxConfig(mode=SandboxMode.WINDOWS, workspace_dir=str(ws), allow_read_all=allow_read_all,
                        shell_executable=SHELL, timeout_seconds=15, env_vars=env_vars)
    sb = create_sandbox(cfg)
    res["backend_class"] = type(sb).__name__
    res["positive_control"] = await run(sb, r"echo ws-ok> ws_control.txt & type ws_control.txt")
    envp = await run(sb, r"echo TEMP=%TEMP%& echo TMP=%TMP%& echo LOCALAPPDATA=%LOCALAPPDATA%& echo APPDATA=%APPDATA%")
    res["child_env"] = envp
    m = re.search(r"TEMP=(.+)", envp["out"])
    child_temp = Path(m.group(1).strip()) if m else None
    res["child_temp_write"] = await run(sb, r'echo iso06v2> "%TEMP%\iso06v2_marker.txt" & type "%TEMP%\iso06v2_marker.txt"')
    marker = child_temp / "iso06v2_marker.txt" if child_temp else None
    pkg = None
    if child_temp and "\\Packages\\" in str(child_temp):
        pkg = Path(REAL_LOCALAPPDATA) / "Packages" / child_temp.parts[child_temp.parts.index("Packages") + 1]
    res["T1_after_execute"] = snap(ws, marker, pkg)
    await sb.stop()
    res["T2_after_stop"] = snap(ws, marker, pkg)
    if allow_read_all:
        res["cleanup_call"] = "windows_unelevated_sandbox.shutdown_cleanup()"
        wu.shutdown_cleanup(log_progress=False)
    else:
        res["cleanup_call"] = "WindowsAppContainerSandbox.destroy()"
        await sb.destroy()
    res["T3_after_cleanup"] = snap(ws, marker, pkg)
    res["workspace_files_after_cleanup"] = sorted(p.name for p in ws.rglob("*") if p.is_file())
    return res


async def main():
    out = {"is_admin": bool(wu._is_admin())}
    for label, ara, tiw in (("rt_default", True, False), ("rt_temp_in_workspace", True, True),
                            ("appcontainer", False, False)):
        try:
            out[label] = await case(label, ara, tiw)
        except Exception as e:
            import traceback
            out[label] = {"error": repr(e), "tb": traceback.format_exc()[-1500:]}
    print(json.dumps(out, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        shutil.rmtree(BASE, ignore_errors=True)
