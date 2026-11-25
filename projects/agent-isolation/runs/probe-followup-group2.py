"""Follow-up checks, 5 trials each (fresh sandboxes every trial).

ISO-03     : which ACE let Restricted Token overwrite a file outside the workspace. Harness folders
             get one extra ACE each (none / Everyone Modify / INTERACTIVE Modify); RT's restricting
             SIDs are [capability SID, logon SID, Everyone].
ISO-07~09  : AppContainer read-only mount and deny_paths. In-sandbox list/read/overwrite/rename/delete
             on synthetic files, the AC-related ACEs of every object, and the child token SIDs.
ISO-10     : a dev server inside AppContainer (bind, self-connect, host -> sandbox connect).
ISO-11     : synthetic parallel build with 4 worker processes, both backends.
ISO-06 add : AppContainer also grants RX on the QwenPaw Python folder (dirname of sys.executable,
             here the test venv). Its ACE is checked before, during and after destroy().

Only harness folders get ACEs from the harness. The Python copy used inside AppContainer is the
same as probe-iso05-12-13-14.py.
"""
import os
import sys
import json
import uuid
import shutil
import asyncio
import subprocess
import urllib.request
from pathlib import Path

SCR = Path(os.environ["ISO_SCRATCH"])
BASE = SCR / f"probe-g2-{uuid.uuid4().hex[:8]}"
PROFILE = BASE / "profile"
PROFILE.mkdir(parents=True)
os.environ.update(USERPROFILE=str(PROFILE), HOME=str(PROFILE))
TRIALS = int(os.environ.get("ISO_TRIALS", "5"))

import win32security  # noqa: E402
from qwenpaw.sandbox.config import SandboxConfig, SandboxMode, MountSpec, create_sandbox  # noqa: E402
from qwenpaw.sandbox import windows_unelevated_sandbox as wu  # noqa: E402

SHELL = r"C:\Windows\System32\cmd.exe"
SRC_PY = Path(sys.base_prefix)
PYRT = BASE / "pyrt"
VENV = Path(sys.executable).parent.parent  # product grants AC RX on this folder
CHILD = Path(__file__).with_name("probe-child2-checks.py")


def build_runtime():
    PYRT.mkdir()
    subprocess.run(["icacls", str(PYRT), "/grant", "*S-1-15-2-1:(OI)(CI)(RX)"], check=True, capture_output=True)
    for f in ("python.exe", "python3.dll", "python312.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        shutil.copy2(SRC_PY / f, PYRT / f)
    shutil.copytree(SRC_PY / "DLLs", PYRT / "DLLs")
    skip = shutil.ignore_patterns("site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip",
                                  "lib2to3", "__pycache__", "pydoc_data")
    shutil.copytree(SRC_PY / "Lib", PYRT / "Lib", ignore=skip)
    shutil.copy2(CHILD, PYRT / "child2.py")


def child(mode, *args):
    extra = " ".join(f'"{a}"' for a in args)
    return f'"{PYRT / "python.exe"}" -I -B "{PYRT / "child2.py"}" {mode} {extra}'


def parse(stdout):
    for line in (stdout or "").splitlines():
        if line.startswith("ISOJSON "):
            return json.loads(line[8:])
    return None


def sddl(path):
    info = win32security.DACL_SECURITY_INFORMATION | win32security.LABEL_SECURITY_INFORMATION
    sd = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, info)
    return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, info)


def ac_aces(path):
    """ACE strings of the DACL/SACL that name an AppContainer or capability SID, plus the label."""
    s = sddl(path)
    aces = [a for a in s.replace(")(", ")|(").split("|") if "S-1-15-" in a]
    label = s[s.find("S:"):] if "S:" in s else ""
    return {"aces": [a.strip("D:PAI") for a in aces], "label": label}


def explicit_ac_sids(path):
    sd = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                                            win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    out = []
    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        sid = win32security.ConvertSidToStringSid(ace[-1])
        if sid.startswith("S-1-15-2-") and not (ace[0][1] & 0x10):  # skip INHERITED_ACE
            out.append(sid)
    return out


async def run(sb, cmd):
    r = await sb.execute(cmd)
    return {"exit": r.exit_code, "out": (r.stdout or "").strip(), "err": (r.stderr or "").strip()[:160]}


async def with_sandbox(ws, allow_read_all, fn, **cfg):
    ws.mkdir(parents=True, exist_ok=True)
    cfg.setdefault("network_allow", [])
    venv_before = explicit_ac_sids(VENV)
    sb = create_sandbox(SandboxConfig(mode=SandboxMode.WINDOWS, workspace_dir=str(ws), allow_read_all=allow_read_all,
                                      shell_executable=SHELL, timeout_seconds=90, **cfg))
    rec, sid = {}, None
    try:
        pc = await run(sb, "echo ok> pc.txt & type pc.txt")
        rec["positive_control_ok"] = pc["exit"] == 0 and pc["out"] == "ok"
        if not allow_read_all:
            sid = getattr(sb, "_container_sid", None)
            rec["venv_ace_during"] = sid is not None and sid in explicit_ac_sids(VENV)
        rec.update(await fn(sb, ws))
    finally:
        await sb.stop()
        if allow_read_all:
            wu.shutdown_cleanup(log_progress=False)
        else:
            await sb.destroy()
            rec["venv_ace_after_destroy"] = sid in explicit_ac_sids(VENV)
            rec["venv_other_ac_aces_unchanged"] = sorted(explicit_ac_sids(VENV)) == sorted(venv_before)
    return rec


# ---------------- ISO-03 cause ----------------
async def iso03(i):
    root = BASE / f"iso03_{i}"
    folders = {"default": None, "everyone_modify": "*S-1-1-0:(OI)(CI)(M)", "interactive_modify": "*S-1-5-4:(OI)(CI)(M)"}
    for name, grant in folders.items():
        (root / name).mkdir(parents=True)
        if grant:
            subprocess.run(["icacls", str(root / name), "/grant", grant], check=True, capture_output=True)
        (root / name / "target.txt").write_text("orig\n")

    async def fn(sb, ws):
        res = {}
        for name in folders:
            t = root / name / "target.txt"
            r = await run(sb, f'echo replaced> "{t}"')
            res[name] = {"exit": r["exit"], "overwritten": t.read_text().strip() == "replaced"}
        return res
    return await with_sandbox(BASE / "ws" / f"iso03_{i}", True, fn)


# ---------------- ISO-07~09 AppContainer ----------------
async def iso0709(i):
    ws = BASE / "ws" / f"iso0709_{i}"
    for sub in ("ro", "deny"):
        d = ws / sub
        d.mkdir(parents=True)
        for f in ("existing", "w", "r", "d"):
            (d / f"{f}.txt").write_text(f"{sub}-{f}\n")

    async def fn(sb, ws):
        for sub in ("ro", "deny"):
            (ws / sub / "new.txt").write_text(f"{sub}-new\n")  # created by the host after start
        res = {"token": parse((await run(sb, child("token")))["out"])}
        res["access_rights"] = parse((await run(sb, child("access", ws / "ro", ws / "deny")))["out"])
        hc = subprocess.run([str(PYRT / "python.exe"), "-I", "-B", str(PYRT / "child2.py"), "access",
                             str(ws / "ro"), str(ws / "deny")], capture_output=True, timeout=60)
        res["access_rights_host"] = parse(hc.stdout.decode("utf-8", "replace"))
        res["acl"] = {name: ac_aces(p) for name, p in (("workspace", ws), ("ro", ws / "ro"), ("ro/existing", ws / "ro" / "existing.txt"),
                                                      ("ro/new", ws / "ro" / "new.txt"), ("deny", ws / "deny"),
                                                      ("deny/existing", ws / "deny" / "existing.txt"),
                                                      ("deny/new", ws / "deny" / "new.txt"))}
        for sub in ("ro", "deny"):
            d = ws / sub
            ops = {}
            r = await run(sb, f"dir /b {sub}")
            ops["list"] = r["exit"] == 0 and "existing.txt" in r["out"]
            ops["read_existing"] = (await run(sb, f"type {sub}\\existing.txt"))["out"] == f"{sub}-existing"
            ops["read_new"] = (await run(sb, f"type {sub}\\new.txt"))["out"] == f"{sub}-new"
            await run(sb, f"echo changed> {sub}\\w.txt")
            ops["overwrite"] = (d / "w.txt").read_text().strip() == "changed"
            await run(sb, f"ren {sub}\\r.txt r2.txt")
            ops["rename"] = (d / "r2.txt").exists()
            await run(sb, f"del {sub}\\d.txt")
            ops["delete"] = not (d / "d.txt").exists()
            res[sub] = ops
        # cmd's dir/del fail everywhere inside AppContainer, so repeat list/delete/create from Python.
        res["python_ops"] = parse((await run(sb, child("pyops", ws / "ro", ws / "deny")))["out"])
        res["python_ops_host_check"] = {sub: {"d_deleted": not (ws / sub / "d.txt").exists(),
                                              "created": (ws / sub / "created.txt").exists()} for sub in ("ro", "deny")}
        res["cmd_dir_workspace_root"] = (await run(sb, "dir /b"))["exit"]
        return res
    return await with_sandbox(ws, False, fn, mounts=[MountSpec(path=str(ws / "ro"), writable=False)],
                              deny_paths=[str(ws / "deny")])


# ---------------- ISO-10 dev server ----------------
async def devserver(backend, net, i):
    ara = backend == "restricted_token"

    async def fn(sb, ws):
        task = asyncio.create_task(run(sb, child("devserver", ws)))
        port_file, host = ws / "port.txt", None
        for _ in range(60):
            if port_file.exists() and port_file.read_text().strip():
                break
            if task.done():
                break
            await asyncio.sleep(0.1)
        if port_file.exists() and port_file.read_text().strip():
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                host = await asyncio.to_thread(lambda: opener.open(
                    f"http://127.0.0.1:{port_file.read_text().strip()}/host", timeout=3).read().decode())
            except Exception as e:
                host = f"error:{type(e).__name__}"
        r = await task
        return {"child": parse(r["out"]) or {"exit": r["exit"], "err": r["err"]}, "host_connect": host}
    return await with_sandbox(BASE / "ws" / f"dev_{backend}_{net}_{i}", ara, fn,
                              network_allow=["*"] if net == "allow" else [])


# ---------------- ISO-11 parallel build ----------------
async def parbuild(backend, i):
    async def fn(sb, ws):
        r = await run(sb, child("parbuild", ws))
        return {"build": parse(r["out"]) or {"exit": r["exit"], "err": r["err"], "out": r["out"][-200:]}}
    return await with_sandbox(BASE / "ws" / f"par_{backend}_{i}", backend == "restricted_token", fn)


async def main():
    build_runtime()
    out = {"venv_explicit_ac_aces_at_start": explicit_ac_sids(VENV)}
    hp = subprocess.run([str(PYRT / "python.exe"), "-I", "-B", str(PYRT / "child2.py"), "parbuild", str(BASE)],
                        capture_output=True, timeout=120)
    out["host_control_parbuild"] = parse(hp.stdout.decode("utf-8", "replace"))
    plan = [("ISO-03 cause (RT)", iso03), ("ISO-07~09 AppContainer", iso0709)]
    plan += [(f"ISO-10 dev server {b}/{n}", (lambda b, n: lambda i: devserver(b, n, i))(b, n))
             for b, n in (("restricted_token", "block"), ("appcontainer", "block"), ("appcontainer", "allow"))]
    plan += [(f"ISO-11 parallel build {b}", (lambda b: lambda i: parbuild(b, i))(b))
             for b in ("restricted_token", "appcontainer")]
    for label, fn in plan:
        out[label] = []
        for i in range(TRIALS):
            try:
                out[label].append(await asyncio.wait_for(fn(i), 240))
            except Exception as e:
                out[label].append({"error": repr(e)[:200]})
    out["venv_explicit_ac_aces_at_end"] = explicit_ac_sids(VENV)
    Path(os.environ["ISO_OUT"]).write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        shutil.rmtree(BASE, ignore_errors=True)
