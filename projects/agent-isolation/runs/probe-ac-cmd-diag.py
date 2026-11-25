"""Why do cmd `dir` and `del` fail in AppContainer while the same rights open fine? 1 sandbox per backend."""
import os, sys, json, uuid, shutil, asyncio
from pathlib import Path

SCR = Path(os.environ["ISO_SCRATCH"])
BASE = SCR / f"cmddiag-{uuid.uuid4().hex[:8]}"
(BASE / "profile").mkdir(parents=True)
os.environ.update(USERPROFILE=str(BASE / "profile"), HOME=str(BASE / "profile"))
from qwenpaw.sandbox.config import SandboxConfig, SandboxMode, create_sandbox  # noqa: E402
from qwenpaw.sandbox import windows_unelevated_sandbox as wu  # noqa: E402


async def main():
    out = {}
    for name, ara in (("restricted_token", True), ("appcontainer", False)):
        ws = BASE / name
        (ws / "sub").mkdir(parents=True)
        for f in ("a.txt", "d1.txt", "d2.txt", "d3.txt"):
            (ws / "sub" / f).write_text("x\n")
        sb = create_sandbox(SandboxConfig(mode=SandboxMode.WINDOWS, workspace_dir=str(ws), allow_read_all=ara,
                                          shell_executable=r"C:\Windows\System32\cmd.exe", timeout_seconds=30,
                                          network_allow=[]))
        res = {}
        try:
            cmds = {"dir_rel": "dir /b sub", "dir_abs": f'dir /b "{ws / "sub"}"', "dir_cd": "cd sub && dir /b",
                    "dir_ws": "dir /b", "dir_wildcard_rel": "dir /b sub\\*.txt",
                    "del_rel": "del sub\\d1.txt", "del_abs": f'del "{ws / "sub" / "d2.txt"}"',
                    "erase_cd": "cd sub && del d3.txt", "cd_value": "cd"}
            for k, c in cmds.items():
                r = await sb.execute(c)
                res[k] = {"exit": r.exit_code, "out": (r.stdout or "").strip().replace("\r\n", "|")[:120],
                          "err": (r.stderr or "").strip()[:120]}
            res["remaining"] = sorted(p.name for p in (ws / "sub").iterdir())
        finally:
            await sb.stop()
            if ara:
                wu.shutdown_cleanup(log_progress=False)
            else:
                await sb.destroy()
        out[name] = res
    Path(os.environ["ISO_OUT"]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")


try:
    asyncio.run(main())
finally:
    shutil.rmtree(BASE, ignore_errors=True)
