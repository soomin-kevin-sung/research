"""Named object, pipe and tool measurements (plan-token-backends.md N0-N4, Q1-Q3, T1-T6), 2026-11-26.

Usage:
  python probe-named-objects-campaign.py <config> <group> [<group> ...]
     config: qwenpaw-unelevated | qwenpaw-admin | codex-unelevated | codex-elevated
     group : nq                     N0 (sandbox side), N1-N4, Q1-Q3 and G4, five trials
             dirs                   N0 host side
             uac-before uac-after   qwenpaw-admin in the UAC-approved session: admin-only state
             qpcleanup              qwenpaw-admin: the product's cleanup, then what stays on the PC
             tools                  T1-T6: Node, Git Bash and Git inside the sandbox, five trials
             toolshost              T1-T6 run directly on the host (control; normal session only)

The configurations, QwenPaw worker and Codex command lines are those of probe-token-backends-campaign.py
(imported, unchanged). Every host-side action goes through probe-named-objects-hostagent.py, which must be
running in the normal (non-elevated) session. Codex elevated groups stop if the sandbox accounts change
(plan 2.3). Each group writes local/<ISO_DATE>/<config>-<group>.json. ISO_DATE defaults to 2026-11-26
(N, Q); the tool run uses ISO_DATE=2026-11-26-tools. The host agent is needed only for nq and dirs.
"""
import os
import sys
import json
import time
import uuid
import hashlib
import subprocess
import importlib.util
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (LOCAL, REAL_CODEX_HOME, ROOT, PY, CHILD, ws, load, save, wait_file,  # noqa: E402
                                   parse_isojson, dacl_aces, lookup_sid, write_spec)

_spec = importlib.util.spec_from_file_location("campaign", Path(__file__).with_name("probe-token-backends-campaign.py"))
K = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(K)

BOX = LOCAL / "hostagent"
TYPES = ("event", "mutex", "semaphore", "section")


def host(action, timeout=90, **kw):
    rid = uuid.uuid4().hex[:12]
    tmp = BOX / f"w-{rid}.tmp"
    tmp.write_text(json.dumps({"id": rid, "action": action, **kw}), encoding="utf-8")
    tmp.replace(BOX / f"req-{rid}.json")
    resp = BOX / f"resp-{rid}.json"
    t0 = time.time()
    while time.time() - t0 < timeout:
        if resp.exists():
            try:
                r = json.loads(resp.read_text(encoding="utf-8"))
            except ValueError:
                time.sleep(0.1)
                continue
            resp.unlink(missing_ok=True)
            return r
        time.sleep(0.1)
    return {"ok": False, "error": "host agent did not answer"}


def codex_accounts():
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-LocalUser CodexSandboxOffline,CodexSandboxOnline | ForEach-Object { $_.Name + '=' + $_.PasswordLastSet.ToString('o') }"],
                       capture_output=True)
    users = REAL_CODEX_HOME / ".sandbox-secrets" / "sandbox_users.json"
    return {"passwords": r.stdout.decode().split(),
            "users_file": hashlib.sha256(users.read_bytes()).hexdigest() if users.exists() else "missing"}


def held_result(proc, timeout=180):
    try:
        so, se = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        so, se = proc.communicate()
    text = so.decode("utf-8", "replace")
    w = K.parse_worker(text)
    if w and w.get("steps"):
        st = w["steps"][0]
        return {"exit": st.get("exit"), "result": st.get("result"), "instances": w.get("instances"),
                "stderr": (st.get("stderr") or "")[-300:]}
    return {"exit": proc.returncode, "result": parse_isojson(text), "stderr": se.decode("utf-8", "replace")[-300:]}


def g_nq(ad, ctx):
    qp = isinstance(ad, K.QwenPaw)
    variant = "plain" if qp else "iso"
    a_ws = ws(ad.name, "ws-A")
    out = []
    for t in range(1, K.TRIALS + 1):
        tag = uuid.uuid4().hex[:8]
        rec = {"trial": t, "tag": tag}
        # ---- N1/N2: host objects, then Q1 and G4 in the same sandbox command
        hobjs = [{"type": ty, "name": f"{ns}\\iso-nq-h-{tag}-{ty}"} for ns in ("Local", "Global") for ty in TYPES]
        rec["host_create"] = host("create", key=tag, objects=hobjs, marker=f"H-{tag}")
        smark = f"S-{tag}"
        rec["run1"] = ad.run("ws-A", [{"id": "N0", "kind": "nsdir"},
                                      {"id": "N1N2", "kind": "nobj_open", "objects": hobjs, "effects": True,
                                       "marker": smark},
                                      {"id": "Q1", "kind": "pipe_steps"},
                                      {"id": "G4", "kind": "parbuild", "ws": str(a_ws)}], f"nq1-{t}", variant=variant)
        rec["host_check"] = host("check", key=tag, marker=smark)
        # ---- N3/Q2: objects and a pipe server made by the ws-A sandbox, kept while others try them
        aobjs = []
        for ns in ("Local", "Global"):
            aobjs += [{"type": "event", "name": f"{ns}\\iso-nq-a-{tag}-event", "signaled": True},
                      {"type": "section", "name": f"{ns}\\iso-nq-a-{tag}-section", "marker": f"A-{tag}"}]
        plain = [{"type": o["type"], "name": o["name"]} for o in aobjs]
        pipe = f"iso-nq-a-{tag}"
        cp, hb, stop, plog = (a_ws / f"nq-cp-{t}.json", a_ws / f"nq-hold-{t}.hb", a_ws / f"nq-stop-{t}",
                              a_ws / f"nq-pipe-{t}.log")
        for p in (cp, hb, stop, plog):
            p.unlink(missing_ok=True)
        proc = ad.start("ws-A", [{"id": "N3", "kind": "nobj_create", "objects": aobjs},
                                 {"id": "Q2", "kind": "pipe_serve", "name": pipe, "instances": 4, "log": str(plog)},
                                 {"id": "cp", "kind": "checkpoint", "path": str(cp)},
                                 {"id": "hold", "kind": "hold", "seconds": 300, "heartbeat": str(hb), "stop": str(stop)}],
                        f"nq2-{t}", variant=variant)
        if not wait_file(cp, 300):
            stop.write_text("stop")
            rec["error"] = "ws-A sandbox did not reach the checkpoint"
            rec["hold"] = held_result(proc, 60)
            out.append(rec)
            continue
        time.sleep(0.5)
        rec["sandbox_created"] = json.loads(cp.read_text(encoding="utf-8"))
        rec["host_precreate"] = host("precreate", objects=plain, pipe=pipe)        # N4, Q3
        rec["host_open"] = host("open_sandbox", objects=plain, pipe=pipe, marker=f"HH-{tag}")  # N3, Q2
        rec["run_b"] = ad.run("ws-B", [{"id": "N3b", "kind": "nobj_open", "objects": plain, "effects": True,
                                        "marker": f"B-{tag}"},
                                       {"id": "Q2b", "kind": "pipe_client", "name": pipe, "data": f"B-{tag}"}],
                              f"nq3-{t}", variant=variant)
        time.sleep(1)
        stop.write_text("stop")
        rec["hold"] = held_result(proc)
        rec["pipe_log"] = ([json.loads(x) for x in plog.read_text(encoding="utf-8").splitlines() if x.strip()]
                           if plog.exists() else None)
        out.append(rec)
        save(f"{ad.name}-nq-partial.json", out)
        print(f"[{ad.name}] nq trial {t} done", flush=True)
    return out


NODE = r"C:\Program Files\nodejs\node.exe"
BASH = r"C:\Program Files\Git\usr\bin\bash.exe"
BASH_LAUNCHER = r"C:\Program Files\Git\bin\bash.exe"
GIT = r"C:\Program Files\Git\cmd\git.exe"
NODE_CASES = ("basic", "spawn_pipe", "spawn_inherit", "spawn_async", "exec_shell", "fork_ipc", "worker", "pipe_server")


def tool_tasks(a_ws, tag):
    js, cwd = str(a_ws / "nodetest.js"), str(a_ws)
    tasks = [{"id": f"node_{c}", "kind": "run", "argv": [NODE, js, c, tag], "cwd": cwd, "timeout": 40} for c in NODE_CASES]
    b = [BASH, "--noprofile", "--norc", "-c"]
    # /usr/bin first: without a login profile, bash only has the caller's PATH, which differs between the
    # Git Bash session (normal session runs) and cmd (UAC batch). First tool run 2026-11-26 lacked this.
    for name, cmd in (("bash_echo", "echo bash-ok"), ("bash_pipe", "echo pipe-ok | cat"),
                      ("bash_subst", 'x=$(echo subst-ok); echo "$x"'), ("bash_bg", "sleep 1 & wait $!; echo bg-ok:$?")):
        tasks.append({"id": name, "kind": "run", "argv": b + ["PATH=/usr/bin:$PATH; " + cmd], "cwd": cwd})
    tasks += [{"id": "bash_launcher", "kind": "run", "argv": [BASH_LAUNCHER, "--noprofile", "--norc", "-c", "echo launcher-ok"],
               "cwd": cwd},
              {"id": "git_version", "kind": "run", "argv": [GIT, "--version"], "cwd": cwd},
              {"id": "git_status", "kind": "run",
               "argv": [GIT, "-C", str(a_ws / "repo"), "--no-optional-locks", "status", "--porcelain"], "cwd": cwd}]
    return tasks


def g_tools(ad, ctx):
    variant = "plain" if isinstance(ad, K.QwenPaw) else "iso"
    a_ws = ws(ad.name, "ws-A")
    out = []
    for t in range(1, K.TRIALS + 1):
        tag = uuid.uuid4().hex[:8]
        r = ad.run("ws-A", [{"id": "token", "kind": "token"}, *tool_tasks(a_ws, tag)], f"tools-{t}", variant=variant,
                   timeout=900)
        out.append({"trial": t, "tag": tag, **r})
        print(f"[{ad.name}] tools trial {t} done", flush=True)
    return out


def g_toolshost(ad, ctx):
    """Control: the same commands run directly on the host by the non-elevated in-sandbox program."""
    if K.is_elevated():
        raise SystemExit("toolshost is the non-elevated host control")
    a_ws = ws(ad.name, "ws-A")
    out = []
    for t in range(1, K.TRIALS + 1):
        tag = uuid.uuid4().hex[:8]
        spec = write_spec(a_ws, f"toolshost-{t}", tool_tasks(a_ws, tag))
        p = subprocess.run([str(PY), "-I", "-B", str(CHILD), str(spec)], capture_output=True, timeout=900)
        out.append({"trial": t, "tag": tag, "exit": p.returncode,
                    "result": parse_isojson(p.stdout.decode("utf-8", "replace"))})
    return out


def g_dirs(ad, ctx):
    return host("dirs")


def g_qpcleanup(ad, ctx):
    """QwenPaw admin: run the product's cleanup and record what stays (same checks as cleanuprec, no H6)."""
    import winreg
    known = K.known_qwenpaw_accounts(ad)
    out = {"final_cleanup": ad.cleanup()}
    time.sleep(3)
    sids = set(known)
    caps = {v.get("cap_sid") for v in known.values() if v.get("cap_sid")}
    lo = {"accounts_created_total": len(sids), "accounts_remaining": len(K.local_users("qwenpaw_")),
          "metadata_remaining": K.qwenpaw_admin_meta()}
    pl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, pl) as k:
        lo["profilelist_keys"] = sum(1 for sid in sids if K._subkey_exists(k, sid))
    lo["profile_dirs"] = len([p for p in Path(r"C:\Users").iterdir() if p.name.lower().startswith("qwenpaw_")])
    try:
        lo["batch_logon_right_sids"] = len(set(K.batch_logon_sids()) & sids)
    except Exception as e:
        lo["batch_logon_right_sids"] = f"error:{e}"
    paths = [ROOT, ROOT / ad.name, *(ws(ad.name, n) for n in ("ws-A", "ws-B"))]
    lo["test_path_aces"] = {str(p): sum(1 for a in dacl_aces(p) if a["sid"] in sids | caps) for p in paths if p.exists()}
    try:
        lo["window_object_aces"] = {k: sum(1 for x in v if x in sids) for k, v in K.window_object_sids().items()}
    except Exception as e:
        lo["window_object_aces"] = f"error:{e}"
    try:
        lo["nul_device_cap_aces"] = sum(1 for x in K.nul_device_sids() if x in caps)
    except Exception as e:
        lo["nul_device_cap_aces"] = f"error:{e}"
    venv = Path(os.environ["LOCALAPPDATA"]) / "agent-isolation-qwenpaw-2.3.0.post1"
    grp = lookup_sid("QwenpawUsers")
    lo["qwenpaw_group"] = bool(grp)
    lo["venv_group_ace"] = any(a["sid"] == grp for a in dacl_aces(venv)) if grp else None
    lo["venv_marker"] = (venv / ".qwenpaw_acl_granted").exists()
    out["leftovers"] = lo
    return out


GROUPS = {"nq": g_nq, "dirs": g_dirs, "qpcleanup": g_qpcleanup, "uac-before": K.g_uacstate, "uac-after": K.g_uacstate,
          "tools": g_tools, "toolshost": g_toolshost}


def main():
    K.SETUP = load("setup.json")
    config, groups = sys.argv[1], sys.argv[2:]
    ad = K.adapter(config)
    if ad.name == "qwenpaw-admin" and not K.is_elevated():
        raise SystemExit("qwenpaw-admin needs the UAC-approved session (IsUserAnAdmin is false)")
    ctx = {}
    if {"nq", "dirs"} & set(groups):
        ping = host("ping", timeout=15)
        if not ping.get("ok") or ping["result"].get("elevated"):
            raise SystemExit(f"host agent missing or elevated: {ping}")
        ctx["host_agent"] = ping["result"]
    base = codex_accounts() if ad.name == "codex-elevated" else None
    for g in groups:
        print(f"[{config}] {g} ...", flush=True)
        t0 = time.monotonic()
        res = GROUPS[g](ad, ctx)
        rec = {"config": config, "group": g, "trials": K.TRIALS, "seconds": round(time.monotonic() - t0, 1),
               "context": ctx, "result": res}
        if base is not None:
            now = codex_accounts()
            rec["codex_accounts_unchanged"] = now == base
        save(f"{config}-{g}.json", rec)
        if ad.name == "qwenpaw-admin":
            K.known_qwenpaw_accounts(ad)
        print(f"[{config}] {g} done in {round(time.monotonic() - t0, 1)}s", flush=True)
        if base is not None and not rec["codex_accounts_unchanged"]:
            print("STOP: Codex sandbox account state changed", flush=True)
            break


if __name__ == "__main__":
    main()
