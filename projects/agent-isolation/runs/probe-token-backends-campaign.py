"""Measurement campaign for plan-token-backends.md.

Usage:
  python probe-token-backends-campaign.py <config> <group> [<group> ...]
     config: qwenpaw-unelevated | qwenpaw-admin | codex-unelevated | codex-elevated
     group : core b6first b5 b8b c5 f1 g4 g p6 h r2x p7          (all configs)
             prep uac-before uac-after r2hold cleanuprec          (qwenpaw-admin, UAC-approved session)
             r2qa b10                                             (non-elevated configs)
             r3                                                   (codex-elevated: state shared between workspaces)
  python probe-token-backends-campaign.py qwenpaw-worker <job.json>   (internal)

qwenpaw-admin runs in a UAC-approved session. Its P1/P2/G5 targets come from the non-elevated
probe-token-backends-hostholder.py, and the non-elevated side of R2 (r2qa) runs in a separate
non-elevated process that waits for the r2hold signal files. Each group writes
local/2026-11-25/<config>-<group>.json. Other processes, tokens and registry keys are only opened and
closed by the in-sandbox program; see probe-token-backends-child.py.
"""
import os
import sys
import json
import time
import uuid
import shutil
import asyncio
import threading
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, TARGETS, QP_PROFILE, CODEX, REAL_CODEX_HOME, PY, CHILD, LOCAL,  # noqa: E402
                                   save, load, parse_isojson, write_spec, child_argv, child_cmdline,
                                   heartbeat_alive, wait_file, find_window, process_categories, hku_category,
                                   start_test_process, ws, lookup_sid, dacl_aces)

SHELL = r"C:\Windows\System32\cmd.exe"
TRIALS = int(os.environ.get("ISO_TRIALS", "5"))
PROFILE = Path(os.environ["USERPROFILE"])
SETUP = None


# =============================================================== QwenPaw worker (separate process)
ADMIN_TIMED = ("_create_new_sandbox", "_restore_from_metadata", "_provision_sandbox_user", "_grant_batch_logon_right",
               "_logon_user", "_create_user_profile", "_grant_winsta_desktop_access", "_apply_all_acls",
               "_ensure_python_dir_group_acl", "_allow_null_device", "_create_restricted_token", "_dpapi_encrypt",
               "_dpapi_decrypt", "_create_process_with_token", "_remove_acls_from_metadata", "_remove_firewall_rules_sync",
               "_delete_local_user_sync", "_remove_profile_dir_sync")
LOG_KEYS = ("CreateProcess", "AssignProcessToJobObject", "CreateProfile", "Traverse ACE", "Granting RX", "ACE", "ACL")


def qwenpaw_worker(job_path):
    import atexit
    import logging
    job = json.loads(Path(job_path).read_text(encoding="utf-8"))
    os.environ.update(USERPROFILE=str(QP_PROFILE), HOME=str(QP_PROFILE))
    os.environ.update(job.get("env", {}))
    from qwenpaw.sandbox.config import SandboxConfig, SandboxMode, MountSpec, create_sandbox
    from qwenpaw.sandbox import windows_unelevated_sandbox as wu
    boxes, out = {}, {"steps": [], "backend": {}, "instances": {}, "logs": [], "timing": {}}

    class Capture(logging.Handler):
        def emit(self, rec):
            msg = rec.getMessage()
            if rec.levelno >= logging.WARNING or any(k in msg for k in LOG_KEYS):
                out["logs"].append(f"{rec.levelname}:{msg[:240]}")
    qlog = logging.getLogger("qwenpaw")
    qlog.setLevel(logging.DEBUG)
    qlog.addHandler(Capture())
    cleaner = wu
    if job.get("admin"):
        from qwenpaw.sandbox import windows_elevated_sandbox as we
        cleaner = we
        atexit.unregister(wu.shutdown_cleanup)  # never touch the non-admin config's state from this process
        if not job.get("cleanup", True):
            atexit.unregister(we.shutdown_cleanup)  # account kept for the next worker (long-running app model)

        def timed(name, fn):
            def wrapper(*a, **k):
                t0 = time.monotonic()
                try:
                    return fn(*a, **k)
                finally:
                    e = out["timing"].setdefault(name, [0, 0.0])
                    e[0] += 1
                    e[1] = round(e[1] + time.monotonic() - t0, 3)
            return wrapper
        for n in ADMIN_TIMED:
            if hasattr(we, n):
                setattr(we, n, timed(n, getattr(we, n)))

    def make(key):
        c = job["configs"][key]
        cfg = SandboxConfig(mode=SandboxMode.WINDOWS, workspace_dir=c["ws"], allow_read_all=True,
                            shell_executable=SHELL, timeout_seconds=c.get("timeout", 120), network_allow=["*"],
                            mounts=[MountSpec(path=m["path"], writable=m["writable"]) for m in c.get("mounts", [])],
                            deny_paths=c.get("deny_paths", []))
        sb = create_sandbox(cfg)
        out["backend"][key] = type(sb).__name__
        return sb

    async def main():
        for st in job["steps"]:
            key = st["box"]
            t0 = time.monotonic()
            if key not in boxes:
                boxes[key] = make(key)
            r = await boxes[key].execute(child_cmdline(st["spec"]))
            out["steps"].append({"box": key, "exit": r.exit_code, "seconds": round(time.monotonic() - t0, 3),
                                 "timed_out": getattr(r, "timed_out", None), "result": parse_isojson(r.stdout),
                                 "stderr": (r.stderr or "")[-300:]})
            inst = getattr(boxes[key], "_instance", None)
            if inst is not None and key not in out["instances"]:
                out["instances"][key] = {a: getattr(inst, b, None) for a, b in (
                    ("username", "username"), ("user_sid", "user_sid_string"), ("cap_sid", "cap_sid"),
                    ("profile_dir", "profile_dir"))}
        for sb in boxes.values():
            await sb.stop()
        if job.get("cleanup", True):
            t0 = time.monotonic()
            cleaner.shutdown_cleanup(log_progress=False)
            out["cleanup_seconds"] = round(time.monotonic() - t0, 3)

    asyncio.run(main())
    print("WORKERJSON " + json.dumps(out), flush=True)


# =============================================================== adapters
class QwenPaw:
    name = "qwenpaw-unelevated"
    admin = False
    default_cleanup = True

    def __init__(self):
        self.root = ROOT / self.name
        self.temp = self.root / "temp"
        self.temp.mkdir(exist_ok=True)
        self.created = {}

    def config(self, wsname, variant="plain"):
        c = {"ws": str(ws(self.name, wsname)), "timeout": 120}
        if wsname == "ws-A" and variant != "plain":
            c["mounts"] = [{"path": str(ws(self.name, "ws-A") / "ro"), "writable": False},
                           {"path": str(TARGETS / "admin-owned"), "writable": True}]
            c["deny_paths"] = [str(TARGETS / "deny-read")]
        return c

    def job(self, steps, configs, cleanup=None, timeout=None):
        if timeout:
            for c in configs.values():
                c["timeout"] = timeout
        p = LOCAL / "jobs" / f"job-{uuid.uuid4().hex[:8]}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        env = {"TEMP": str(self.temp), "TMP": str(self.temp), "ISO_TB_PLAIN": "plain-marker-1",
               "ISO_TB_API_KEY": "apikey-marker-2"}
        p.write_text(json.dumps({"steps": steps, "configs": configs, "env": env, "admin": self.admin,
                                 "cleanup": self.default_cleanup if cleanup is None else cleanup}), encoding="utf-8")
        return [sys.executable, str(Path(__file__)), "qwenpaw-worker", str(p)]

    def note(self, w):
        """Remember every sandbox account a worker reported (QwenPaw admin leftovers are checked against this)."""
        for v in ((w or {}).get("instances") or {}).values():
            if v.get("user_sid"):
                self.created[v["user_sid"]] = v
        return w

    def default_variant(self, wsname):
        return "full" if wsname == "ws-A" else "plain"

    def run(self, wsname, tasks, tag, variant=None, timeout=None, cleanup=None):
        variant = variant or self.default_variant(wsname)
        spec = write_spec(ws(self.name, wsname), tag, tasks)
        argv = self.job([{"box": "X", "spec": str(spec)}], {"X": self.config(wsname, variant)}, cleanup=cleanup,
                        timeout=timeout)
        t0 = time.monotonic()
        p = subprocess.run(argv, capture_output=True, timeout=900)
        w = self.note(parse_worker(p.stdout.decode("utf-8", "replace")))
        st = (w or {}).get("steps", [{}])[0] if w else {}
        r = {"exit": st.get("exit"), "seconds": st.get("seconds"), "wall": round(time.monotonic() - t0, 3),
             "result": st.get("result"), "backend": (w or {}).get("backend"),
             "cleanup_seconds": (w or {}).get("cleanup_seconds"), "stderr": st.get("stderr") or p.stderr.decode("utf-8", "replace")[-300:]}
        if w and (w.get("logs") or w.get("timing")):
            r["worker_logs"] = (w.get("logs") or [])[-20:]
            r["timing"] = w.get("timing")
        if w and w.get("instances"):
            r["instances"] = w["instances"]
        return r

    def start(self, wsname, tasks, tag, variant=None, timeout=None, cleanup=None):
        variant = variant or self.default_variant(wsname)
        spec = write_spec(ws(self.name, wsname), tag, tasks)
        argv = self.job([{"box": "X", "spec": str(spec)}], {"X": self.config(wsname, variant)}, cleanup=cleanup,
                        timeout=timeout)
        return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def multi(self, steps_specs, configs, cleanup=True):
        argv = self.job(steps_specs, configs, cleanup=cleanup)
        p = subprocess.run(argv, capture_output=True, timeout=1800)
        return self.note(parse_worker(p.stdout.decode("utf-8", "replace")))

    def product_pids(self, proc):
        return {"product": [proc.pid]}

    def r5_root(self):
        return "HKCU", r"Software\agent-isolation-test"


class QwenPawAdmin(QwenPaw):
    """WindowsElevatedSandbox. Accounts are kept between worker processes, as in one long-running QwenPaw
    process that reuses the account per configuration fingerprint; cleanup() runs the product's cleanup."""
    name = "qwenpaw-admin"
    admin = True
    default_cleanup = False

    def cleanup(self):
        w = self.multi([], {}, cleanup=True)
        return {"cleanup_seconds": (w or {}).get("cleanup_seconds"), "timing": (w or {}).get("timing"),
                "logs": ((w or {}).get("logs") or [])[-30:]}

    def r5_root(self):
        return "HKU", rf"{SETUP['user_sid']}\Software\agent-isolation-test"


class Codex:
    def __init__(self, level):
        self.level = level
        self.name = f"codex-{level}"
        self.home = ROOT / self.name / "home" if level == "unelevated" else REAL_CODEX_HOME
        self.temp = ROOT / self.name / "temp"
        q = '":root"="read", ":tmpdir"="write", ":workspace_roots"={"."="write", "ro"="read"}'
        self.profiles = {"iso": "{" + q + "}",
                         "isodeny": "{" + q + f", '{TARGETS / 'deny-read'}'=\"deny\"" + "}",
                         "isob10": "{" + q + f", '{TARGETS / 'admin-owned'}'=\"write\"" + "}"}

    def argv(self, wsname, spec, profile):
        return [str(CODEX), "sandbox", "-c", f'windows.sandbox="{self.level}"',
                "-c", f"permissions.{profile}.filesystem={self.profiles[profile]}",
                "-c", f"permissions.{profile}.network.enabled=false",
                "-P", profile, "-C", str(ws(self.name, wsname)), "--", *child_argv(spec)]

    def env(self):
        env = os.environ.copy()
        env.pop("CODEX_WINDOWS_REGISTERED_CORE", None)
        env.update(CODEX_HOME=str(self.home), TEMP=str(self.temp), TMP=str(self.temp),
                   ISO_TB_PLAIN="plain-marker-1", ISO_TB_API_KEY="apikey-marker-2")
        return env

    def run(self, wsname, tasks, tag, variant="iso", timeout=None):
        spec = write_spec(ws(self.name, wsname), tag, tasks)
        t0 = time.monotonic()
        p = subprocess.run(self.argv(wsname, spec, variant or "iso"), cwd=ws(self.name, wsname), env=self.env(),
                           capture_output=True, timeout=timeout or 300)
        return {"exit": p.returncode, "seconds": round(time.monotonic() - t0, 3),
                "result": parse_isojson(p.stdout.decode("utf-8", "replace")),
                "stderr": p.stderr.decode("utf-8", "replace")[-400:]}

    def start(self, wsname, tasks, tag, variant="iso", timeout=None):
        spec = write_spec(ws(self.name, wsname), tag, tasks)
        return subprocess.Popen(self.argv(wsname, spec, variant or "iso"), cwd=ws(self.name, wsname), env=self.env(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def r5_root(self):
        if self.level == "unelevated":
            return "HKCU", r"Software\agent-isolation-test"
        return "HKU", rf"{SETUP['user_sid']}\Software\agent-isolation-test"


def parse_worker(text):
    for line in (text or "").splitlines():
        if line.startswith("WORKERJSON "):
            return json.loads(line[11:])
    return None


def adapter(config):
    if config == "qwenpaw-unelevated":
        return QwenPaw()
    if config == "qwenpaw-admin":
        return QwenPawAdmin()
    return Codex(config.split("-", 1)[1])


def is_elevated():
    import ctypes
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


ADMIN_KEY = r"SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg"  # chosen by admin_only_key() in the non-UAC run
QP_SB = QP_PROFILE / ".qwenpaw" / "sandboxes"


def qwenpaw_admin_meta():
    """{user_sid: {username, path, cap_sid}} from QwenPaw admin metadata files (live and failed_cleanup)."""
    out = {}
    for p in [*QP_SB.glob("*.json"), *(QP_PROFILE / ".qwenpaw" / "failed_cleanup").glob("*.json")]:
        try:
            m = json.loads(p.read_text(encoding="utf-8"))
            out[m["user_sid"]] = {"username": m.get("username"), "cap_sid": m.get("cap_sid"), "path": str(p),
                                  "failed_cleanup": p.parent.name == "failed_cleanup"}
        except (OSError, ValueError, KeyError):
            pass
    return out


def sandbox_sid_set():
    s = set(x for x in SETUP["codex_accounts"].values() if x)
    return s | set(qwenpaw_admin_meta())


def hku_names_host():
    import winreg
    out, i = [], 0
    while True:
        try:
            out.append(winreg.EnumKey(winreg.HKEY_USERS, i))
        except OSError:
            return out
        i += 1


# =============================================================== helpers
def host_targets():
    """Real files opened (read access only) by C3/C4; names only are chosen here."""
    def first_file(d):
        d = Path(d)
        if not d.exists():
            return None
        files = sorted(f for f in d.iterdir() if f.is_file())
        return str(files[0]) if files else None
    t = {"ssh": first_file(PROFILE / ".ssh"), "codex_config": str(PROFILE / ".codex" / "config.toml"),
         "codex_auth": str(PROFILE / ".codex" / "auth.json"), "qwenpaw": first_file(PROFILE / ".qwenpaw"),
         "appdata_roaming": str(Path(os.environ["APPDATA"]) / "npm" / "codex.cmd"),
         "gitconfig": str(PROFILE / ".gitconfig"),
         "codex_secrets": str(PROFILE / ".codex" / ".sandbox-secrets" / "sandbox_users.json")}
    group = SETUP["codex_group_sid"]
    pre = {}
    for k, v in t.items():
        try:
            pre[k] = any(a["sid"] == group for a in dacl_aces(v)) if v else None
        except Exception as e:
            pre[k] = f"error:{e}"
    return t, pre


def admin_only_key():
    import winreg
    for k in (r"SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg",
              r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices",
              r"SYSTEM\CurrentControlSet\Control\Lsa\Data"):
        try:
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, k, 0, winreg.KEY_READ))
        except OSError as e:
            if e.winerror == 5:
                return k
    return None


def pipe_server(name, instances=4):
    import win32pipe
    hs = [win32pipe.CreateNamedPipe(rf"\\.\pipe\{name}", win32pipe.PIPE_ACCESS_DUPLEX,
                                    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT, 255, 4096, 4096, 0, None)
          for _ in range(instances)]
    return hs


def restore_ws_a(cfg, t):
    a = ws(cfg, "ws-A")
    for sub in (".git", ".codex", ".agents", "ro"):
        d = a / sub
        ren = a / f"{sub}-ren-{t}"
        if ren.exists() and not d.exists():
            ren.rename(d)
        for extra in d.glob(f"*-{t}.txt"):
            try:
                extra.unlink()
            except OSError:
                pass
        (d / "f.txt").write_text(f"{sub}-original\n")
        if not (d / "del.txt").exists():
            (d / "del.txt").write_text(f"{sub}-delete-target\n")


# =============================================================== groups
def core_tasks(ad, t, test_pid, marker, pipe, ctx):
    cfg = ad.name
    a = ws(cfg, "ws-A")
    ops = [{"id": "B1_create", "op": "write", "path": str(a / f"b1-{t}.txt")},
           {"id": "B1_read", "op": "read", "path": str(a / f"b1-{t}.txt")},
           {"id": "B1_rename", "op": "rename", "path": str(a / f"b1-{t}.txt"), "to": str(a / f"b1r-{t}.txt")},
           {"id": "B1_delete", "op": "delete", "path": str(a / f"b1r-{t}.txt")},
           {"id": "B2_user_only", "op": "write", "path": str(TARGETS / "user-only" / "f.txt")},
           {"id": "B2b_default_inherit", "op": "write", "path": str(TARGETS / "default-inherit" / "f.txt")},
           {"id": "B3_everyone_write", "op": "write", "path": str(TARGETS / "everyone-write" / "f.txt")},
           {"id": "B4_logon_write", "op": "write", "path": str(TARGETS / "logon-write" / "f.txt")},
           {"id": "B8_temp", "op": "write", "path": f"%TEMP%\\b8-{t}.txt"},
           {"id": "C1_user_only", "op": "read", "path": str(TARGETS / "user-only" / "f.txt")},
           {"id": "C1b_default_inherit", "op": "read", "path": str(TARGETS / "default-inherit" / "f.txt")},
           {"id": "C2_profile_child", "op": "read", "path": str(Path(SETUP["c2"]) / "f.txt")}]
    if (TARGETS / "admin-owned").exists():
        ops.append({"id": "B10_admin_owned", "op": "write", "path": str(TARGETS / "admin-owned" / f"b10-{cfg}-{t}.txt")})
    for sub in (".git", ".codex", ".agents", "ro"):
        d = a / sub
        ops += [{"id": f"B6{sub}_overwrite", "op": "write", "path": str(d / "f.txt")},
                {"id": f"B6{sub}_create", "op": "write", "path": str(d / f"new-{t}.txt")},
                {"id": f"B6{sub}_rename_file", "op": "rename", "path": str(d / "f.txt"), "to": str(d / f"f-{t}.txt")},
                {"id": f"B6{sub}_delete_file", "op": "delete", "path": str(d / "del.txt")},
                {"id": f"B6{sub}_rename_dir", "op": "rename", "path": str(d), "to": str(a / f"{sub}-ren-{t}")}]
    for k, v in ctx["c3"].items():
        if v:
            ops.append({"id": f"C3_{k}", "op": "open", "path": v, "access": 0x80000000})
    r5root, r5base = ad.r5_root()
    keys = [{"id": "B9_hkcu_write", "root": "HKCU", "path": "Software", "access": 0x6},
            {"id": "R1_user_software", "root": "HKU", "path": rf"{SETUP['user_sid']}\Software", "access": 0x20019},
            {"id": "R1_user_environment", "root": "HKU", "path": rf"{SETUP['user_sid']}\Environment", "access": 0x20019},
            {"id": "R4_hklm_users_readable", "root": "HKLM", "path": r"SOFTWARE\Microsoft\Windows\CurrentVersion", "access": 0x20019},
            {"id": "R4_hklm_software_write", "root": "HKLM", "path": "SOFTWARE", "access": 0x6}]
    if ctx["admin_key"]:
        keys.append({"id": "R4_admin_only_read", "root": "HKLM", "path": ctx["admin_key"], "access": 0x20019})
    for n in ("everyone-write", "logon-write", "users-write"):
        keys.append({"id": f"R5_{n}", "root": r5root, "path": rf"{r5base}\{n}", "access": 0x2})
    tasks = [{"id": "token", "kind": "token"},
             {"id": "env", "kind": "env", "names": ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
                                                    "ISO_TB_PLAIN", "ISO_TB_API_KEY", "HTTP_PROXY", "NO_PROXY"]},
             {"id": "fs", "kind": "fs", "ops": ops},
             {"id": "reg", "kind": "reg", "keys": keys},
             {"id": "R2_hku", "kind": "hku"},
             {"id": "C7_dpapi", "kind": "dpapi", "expected": SETUP["dpapi_expected"],
              "paths": [str(TARGETS / "dpapi" / "user.bin"), str(TARGETS / "dpapi" / "machine.bin")]},
             {"id": "P1_test_process", "kind": "proc_open", "pids": [test_pid]},
             {"id": "P2_cmdline", "kind": "cmdline", "pid": test_pid, "marker": marker},
             {"id": "G5_pipe", "kind": "pipe", "name": pipe}]
    if ad.name.startswith("codex"):
        tasks.append({"id": "P5_product", "kind": "proc_open_ancestors", "names": ["codex-command-runner", "codex.exe"]})
    else:  # the QwenPaw worker is the first python.exe above cmd.exe
        tasks.append({"id": "P5_product", "kind": "proc_open_ancestors", "names": ["python.exe"]})
    if t == 1:
        tasks.append({"id": "P4_proc_list", "kind": "proc_list", "categories": ctx["categories"]})
    return tasks


def hku_cat(n, own=None, qwen=()):
    suffix = "_Classes" if n.endswith("_Classes") else ""
    base = n[:-8] if suffix else n
    if own and base == own:
        return "own" + suffix
    if base in qwen:
        return "qwenpaw_admin_account" + suffix
    return hku_category(n, SETUP["user_sid"], set(x for x in SETUP["codex_accounts"].values() if x))


def g_core(ad, ctx):
    out = []
    holder = None
    if ad.admin:
        # P1/P2/G5 targets must be non-elevated: they come from probe-token-backends-hostholder.py
        holder = load("uac-host-targets.json")["trials"]
        warm = ad.run("ws-A", [{"id": "fs", "kind": "fs", "ops": [
            {"id": "w", "op": "write", "path": str(ws(ad.name, "ws-A") / "warm.txt")}]}], "core-warm")
        inst = (warm.get("instances") or {}).get("X") or {}
        meta = qwenpaw_admin_meta().get(inst.get("user_sid"), {})
        ctx["c3"]["qwenpaw_admin_meta"] = meta.get("path")
        ctx["categories"] = process_categories(SETUP["user_sid"], sandbox_sid_set())
        out_warm = {"exit": warm.get("exit"), "seconds": warm.get("seconds"), "timing": warm.get("timing"),
                    "worker_logs": warm.get("worker_logs")}
    for t in range(1, TRIALS + 1):
        tp, hs = None, []
        if holder:
            h = holder[t - 1]
            test_pid, marker, pipe = h["pid"], h["marker"], h["pipe"]
            alive = heartbeat_alive(h["hb"], 2)
        else:
            marker = f"ISO-TB-MARKER-{uuid.uuid4().hex[:10]}"
            hb = LOCAL / f"testproc-{t}.hb"
            tp = start_test_process(120, marker, hb)
            wait_file(hb, 10)
            test_pid = tp.pid
            pipe = f"iso-tb-{uuid.uuid4().hex[:8]}"
            hs = pipe_server(pipe)
        try:
            r = ad.run("ws-A", core_tasks(ad, t, test_pid, marker, pipe, ctx), f"core-{t}")
            if holder:
                r["holder_target_alive"] = alive
            if t == 1:
                r["P3_host_view"] = {"test_process": process_sd(test_pid), "shell_explorer": process_sd(explorer_pid())}
                if holder:
                    r["warm_up"] = out_warm
        finally:
            for x in hs:
                x.Close()
            if tp:
                tp.kill()
            restore_ws_a(ad.name, t)
            for n in ("user-only", "default-inherit", "everyone-write", "logon-write"):
                (TARGETS / n / "f.txt").write_text(f"{n}-original\n")
        res = r.get("result") or {}
        hku = res.get("R2_hku") if isinstance(res, dict) else None
        if isinstance(hku, dict):
            tok = res.get("token") if isinstance(res.get("token"), dict) else {}
            own = tok.get("user") if tok.get("user") != SETUP["user_sid"] else None
            qwen = set(qwenpaw_admin_meta())
            hku["by_category"] = {}
            for n, v in hku.get("opened", {}).items():
                hku["by_category"].setdefault(hku_cat(n, own, qwen), []).append(v)
            hku.pop("names", None)
            hku.pop("opened", None)
        out.append(r)
        print(f"  core trial {t}: exit={r.get('exit')} s={r.get('seconds')}", flush=True)
    return out


def g_b6first(ad, ctx):
    """First run in ws-B: .git/.agents/.codex do not exist yet (Codex protects missing .codex only)."""
    b = ws(ad.name, "ws-B")
    ops = [{"id": "mk_git", "op": "mkdir", "path": str(b / ".git")},
           {"id": "git_head", "op": "write", "path": str(b / ".git" / "HEAD")},
           {"id": "mk_agents", "op": "mkdir", "path": str(b / ".agents")},
           {"id": "agents_file", "op": "write", "path": str(b / ".agents" / "a.txt")},
           {"id": "mk_codex", "op": "mkdir", "path": str(b / ".codex")},
           {"id": "codex_file", "op": "write", "path": str(b / ".codex" / "c.txt")}]
    pre = {n: (b / n).exists() for n in (".git", ".agents", ".codex")}
    r = ad.run("ws-B", [{"id": "fs", "kind": "fs", "ops": ops}], "b6first", variant="plain" if ad.name.startswith("qwen") else "iso")
    return {"pre_existing": pre, "run": r, "post": {n: (b / n).exists() for n in (".git", ".agents", ".codex")}}


def g_b5(ad, ctx):
    out = []
    target = ws(ad.name, "ws-B") / "existing.txt"
    for t in range(1, TRIALS + 1):
        target.write_text("ws-B-original\n")
        if isinstance(ad, QwenPaw):
            spec_b = write_spec(ws(ad.name, "ws-B"), f"b5b-{t}", [{"id": "touch", "kind": "fs", "ops": [
                {"id": "b_write", "op": "write", "path": str(ws(ad.name, "ws-B") / f"b5-own-{t}.txt")}]}])
            spec_a = write_spec(ws(ad.name, "ws-A"), f"b5a-{t}", [{"id": "fs", "kind": "fs", "ops": [
                {"id": "write_ws_b", "op": "write", "path": str(target)}]}])
            w = ad.multi([{"box": "B", "spec": str(spec_b)}, {"box": "A", "spec": str(spec_a)}],
                         {"A": ad.config("ws-A", "full"), "B": ad.config("ws-B", "plain")})
            same = (w or {}).get("steps", [{}, {}])[1].get("result") if w else None
            after = ad.run("ws-A", [{"id": "fs", "kind": "fs", "ops": [{"id": "write_ws_b", "op": "write", "path": str(target)}]}],
                           f"b5after-{t}")
            out.append({"same_process_ace_present": same, "after_cleanup": after.get("result")})
        else:
            ad.run("ws-B", [{"id": "fs", "kind": "fs", "ops": [{"id": "b_write", "op": "write",
                                                                 "path": str(ws(ad.name, "ws-B") / f"b5-own-{t}.txt")}]}], f"b5b-{t}")
            r = ad.run("ws-A", [{"id": "fs", "kind": "fs", "ops": [{"id": "write_ws_b", "op": "write", "path": str(target)}]}],
                       f"b5a-{t}")
            out.append({"ace_persists": r.get("result"), "ws_b_explicit_aces": len([a for a in dacl_aces(ws(ad.name, "ws-B")) if not a["flags"] & 0x10])})
    return out


def g_b8b(ad, ctx):
    out = []
    for t in range(1, TRIALS + 1):
        name = f"%TEMP%\\b8b-{t}.txt"
        a = ad.run("ws-A", [{"id": "fs", "kind": "fs", "ops": [{"id": "a_write", "op": "write", "path": name}]}], f"b8ba-{t}")
        b = ad.run("ws-B", [{"id": "fs", "kind": "fs", "ops": [{"id": "b_overwrite", "op": "write", "path": name}]}], f"b8bb-{t}",
                   variant="plain" if isinstance(ad, QwenPaw) else "iso")
        out.append({"ws_a": a.get("result"), "ws_b": b.get("result")})
    return out


def g_c5(ad, ctx):
    out = []
    deny = TARGETS / "deny-read"
    for t in range(1, TRIALS + 1):
        new, moved_src, moved_dst = deny / f"new-{t}.txt", TARGETS / "moved-src" / f"m-{t}.txt", deny / f"m-{t}.txt"
        sig = ws(ad.name, "ws-A") / f"c6-signal-{t}"
        for p in (new, moved_dst, sig):
            if p.exists():
                p.unlink()
        moved_src.write_text("moved-original\n")
        tasks = [{"id": "fs", "kind": "fs", "ops": [
            {"id": "C5_read", "op": "read", "path": str(deny / "f.txt")},
            {"id": "C6_signal", "op": "signal", "path": str(sig)},
            {"id": "C6_new_file", "op": "wait_read", "path": str(new), "wait": 20},
            {"id": "C6_moved_file", "op": "wait_read", "path": str(moved_dst), "wait": 20},
            {"id": "C6_hardlink", "op": "read", "path": str(TARGETS / "hardlink-dir" / "h-link.txt")},
            {"id": "C6_direct_link_target", "op": "read", "path": str(deny / "h.txt")}]}]
        # positive control without the deny setting
        pc_variant = "plain" if isinstance(ad, QwenPaw) else "iso"
        pc_ws = "ws-B" if isinstance(ad, QwenPaw) else "ws-A"
        pc = ad.run(pc_ws, [{"id": "fs", "kind": "fs", "ops": [{"id": "C5_read", "op": "read", "path": str(deny / "f.txt")},
                                                              {"id": "C6_hardlink", "op": "read", "path": str(TARGETS / "hardlink-dir" / "h-link.txt")}]}],
                    f"c5pc-{t}", variant=pc_variant)
        proc = ad.start("ws-A", tasks, f"c5-{t}", variant="full" if isinstance(ad, QwenPaw) else "isodeny")
        t_wait = time.time()
        while not sig.exists() and proc.poll() is None and time.time() - t_wait < 90:
            time.sleep(0.2)
        signalled = sig.exists()
        if signalled:
            new.write_text("new-after-start\n")
            shutil.move(str(moved_src), str(moved_dst))
        try:
            so, se = proc.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            proc.kill()
            so, se = proc.communicate()
        text = so.decode("utf-8", "replace")
        res = parse_worker(text) if isinstance(ad, QwenPaw) else parse_isojson(text)
        if isinstance(ad, QwenPaw) and res:
            res = res["steps"][0]
        out.append({"positive_control": pc.get("result"), "signalled": signalled, "exit": proc.returncode,
                    "result": res, "stderr": se.decode("utf-8", "replace")[-300:],
                    "deny_dir_aces": [a for a in dacl_aces(deny) if a["type"] == 1],
                    "moved_file_aces_deny": [a for a in dacl_aces(moved_dst) if a["type"] == 1] if moved_dst.exists() else None})
        for p in (new, moved_dst):
            try:
                p.unlink()
            except OSError:
                pass
    return out


def g_f1(ad, ctx):
    out = []
    for t in range(1, TRIALS + 1):
        title = f"ISO-TB-WINDOW-{uuid.uuid4().hex[:8]}"
        proc = ad.start("ws-A", [{"id": "win", "kind": "window", "seconds": 8, "title": title}], f"f1-{t}")
        seen = find_window(title, timeout=10)
        try:
            proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
        out.append(seen)
    return out


def g_g4(ad, ctx):
    return [ad.run("ws-A", [{"id": "par", "kind": "parbuild", "ws": str(ws(ad.name, "ws-A"))}], f"g4-{t}").get("result")
            for t in range(1, TRIALS + 1)]


def g_g(ad, ctx):
    """G1 kill product process, G6 breakaway, G2 background child after the command's process exits."""
    a = ws(ad.name, "ws-A")
    out = {"G1": [], "G6": [], "G2": [], "G1b": []}
    for t in range(1, TRIALS + 1):
        for kind, breakaway in (("G1", False), ("G6", True)):
            hb_main, hb_child = a / f"{kind}-main-{t}.hb", a / f"{kind}-child-{t}.hb"
            hb_main.unlink(missing_ok=True)
            hb_child.unlink(missing_ok=True)
            tasks = [{"id": "spawn", "kind": "spawn", "seconds": 90, "heartbeat": str(hb_child), "breakaway": breakaway,
                      "stdout": "nul"},
                     {"id": "sleep", "kind": "sleep", "seconds": 90, "heartbeat": str(hb_main)}]
            proc = ad.start("ws-A", tasks, f"{kind}-{t}")
            started = wait_file(hb_main, 90)
            child_started = wait_file(hb_child, 5)
            runner_before = runner_running()
            proc.kill()
            proc.wait(30)
            time.sleep(2)
            out[kind].append({"started": started, "child_started": child_started,
                              "main_alive_after_kill": heartbeat_alive(hb_main, 3),
                              "child_alive_after_kill": heartbeat_alive(hb_child, 3),
                              "runner_before": runner_before, "runner_after": runner_running()})
        for mode in ("inherit", "nul"):
            hb = a / f"G2-{mode}-{t}.hb"
            hb.unlink(missing_ok=True)
            tasks = [{"id": "spawn", "kind": "spawn", "seconds": 25, "heartbeat": str(hb), "stdout": mode}]
            t0 = time.monotonic()
            proc = ad.start("ws-A", tasks, f"g2-{mode}-{t}")
            try:
                proc.communicate(timeout=60)
                returned = round(time.monotonic() - t0, 2)
            except subprocess.TimeoutExpired:
                proc.kill()
                returned = "not_within_60s"
            out["G2"].append({"stdout": mode, "call_returned_after_s": returned,
                              "child_alive_at_return": heartbeat_alive(hb, 2)})
        if isinstance(ad, QwenPaw):
            hb_main, hb_child = a / f"G1b-main-{t}.hb", a / f"G1b-child-{t}.hb"
            tasks = [{"id": "spawn", "kind": "spawn", "seconds": 60, "heartbeat": str(hb_child), "stdout": "nul"},
                     {"id": "sleep", "kind": "sleep", "seconds": 60, "heartbeat": str(hb_main)}]
            r = ad.run("ws-A", tasks, f"g1b-{t}", timeout=8)
            time.sleep(2)
            out["G1b"].append({"exit": r.get("exit"), "seconds": r.get("seconds"),
                               "main_alive": heartbeat_alive(hb_main, 3), "child_alive": heartbeat_alive(hb_child, 3)})
    return out


def process_sd(pid):
    """Host-side, read-only: owner, integrity label and DACL of a process (READ_CONTROL only)."""
    import win32api
    import win32security
    if not pid:
        return None
    try:
        h = win32api.OpenProcess(0x20000, False, pid)
    except Exception as e:
        return f"open_error:{e}"
    info = (win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
            | win32security.LABEL_SECURITY_INFORMATION)
    try:
        sd = win32security.GetSecurityInfo(h, win32security.SE_KERNEL_OBJECT, info)
        return win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, win32security.SDDL_REVISION_1, info)
    except Exception as e:
        return f"sd_error:{e}"
    finally:
        h.Close()


def explorer_pid():
    r = subprocess.run(["tasklist", "/fi", "imagename eq explorer.exe", "/fo", "csv", "/nh"], capture_output=True)
    for ln in r.stdout.decode("cp949", "replace").splitlines():
        parts = ln.strip('"').split('","')
        if len(parts) > 1 and parts[1].isdigit():
            return int(parts[1])
    return None


def runner_running():
    r = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True)
    return sum(1 for ln in r.stdout.decode("cp949", "replace").splitlines() if "codex-command-runner" in ln.lower())


def g_p6(ad, ctx):
    out = []
    for t in range(1, TRIALS + 1):
        hb = ws(ad.name, "ws-A") / f"p6-{t}.hb"
        hb.unlink(missing_ok=True)
        proc = ad.start("ws-A", [{"id": "sleep", "kind": "sleep", "seconds": 40, "heartbeat": str(hb)}], f"p6a-{t}")
        if not wait_file(hb, 90):
            proc.kill()
            out.append({"error": "sandbox A did not start"})
            continue
        time.sleep(1)
        pid = int(hb.read_text().split()[0])
        r = ad.run("ws-B", [{"id": "P6", "kind": "proc_open", "pids": [pid]}], f"p6b-{t}",
                   variant="plain" if isinstance(ad, QwenPaw) else "iso")
        proc.kill()
        out.append({"target_pid_seen": True, "result": r.get("result")})
    return out


def g_h(ad, ctx):
    out = {}
    if isinstance(ad, QwenPaw):
        spec = lambda w, tag: str(write_spec(ws(ad.name, w), tag, [{"id": "fs", "kind": "fs", "ops": [
            {"id": "w", "op": "write", "path": str(ws(ad.name, w) / f"{tag}.txt")}]}]))
        if ad.admin:  # H1 must start without an account for the configuration
            out["pre_cleanup"] = ad.cleanup()
        out["H1_first_command"] = []
        for t in range(1, TRIALS + 1):
            w = ad.multi([{"box": "A", "spec": spec("ws-A", f"h1-{t}")}], {"A": ad.config("ws-A", "full")})
            out["H1_first_command"].append({"seconds": w["steps"][0]["seconds"], "cleanup_seconds": w.get("cleanup_seconds"),
                                            "timing": w.get("timing") or None})
        w = ad.multi([{"box": "A", "spec": spec("ws-A", f"h2-{i}")} for i in range(21)], {"A": ad.config("ws-A", "full")})
        out["H2_repeat_seconds"] = [s["seconds"] for s in w["steps"][1:]]
        out["H3_cleanup_seconds"] = w.get("cleanup_seconds")
        out["H2_H3_timing"] = w.get("timing") or None
        w = ad.multi([{"box": "L", "spec": spec("ws-large", "h4-1")}], {"L": ad.config("ws-large", "plain")})
        out["H4_large"] = {"first_seconds": w["steps"][0]["seconds"], "cleanup_seconds": w.get("cleanup_seconds"),
                           "timing": w.get("timing") or None}
    else:
        task = lambda w, tag: [{"id": "fs", "kind": "fs", "ops": [{"id": "w", "op": "write", "path": str(ws(ad.name, w) / f"{tag}.txt")}]}]
        out["H2_repeat_seconds"] = [ad.run("ws-A", task("ws-A", f"h2-{i}"), f"h2-{i}")["seconds"] for i in range(20)]
        base = []
        for _ in range(20):
            t0 = time.monotonic()
            subprocess.run([str(CODEX), "--version"], env=ad.env(), capture_output=True)
            base.append(round(time.monotonic() - t0, 3))
        out["H2_baseline_codex_version_seconds"] = base
        first = ad.run("ws-large", task("ws-large", "h4-1"), "h4-1")
        second = ad.run("ws-large", task("ws-large", "h4-2"), "h4-2")
        out["H4_large"] = {"first_seconds": first["seconds"], "second_seconds": second["seconds"],
                           "first_ok": (first.get("result") or {}).get("fs")}
    host = []
    for _ in range(20):
        t0 = time.monotonic()
        subprocess.run(child_argv(write_spec(ws(ad.name, "ws-A"), "hostbase", [{"id": "fs", "kind": "fs", "ops": [
            {"id": "w", "op": "write", "path": str(ws(ad.name, "ws-A") / "hostbase.txt")}]}])), capture_output=True)
        host.append(round(time.monotonic() - t0, 3))
    out["host_baseline_seconds"] = host
    return out


def g_r2x(ad, ctx):
    """Run R2 from this (non-admin) config while Codex elevated keeps a sandbox process alive."""
    cx = Codex("elevated")
    out = []
    sandbox_sids = set(x for x in SETUP["codex_accounts"].values() if x)
    for t in range(1, TRIALS + 1):
        hb = ws(cx.name, "ws-A") / f"r2x-{t}.hb"
        hb.unlink(missing_ok=True)
        proc = cx.start("ws-A", [{"id": "sleep", "kind": "sleep", "seconds": 45, "heartbeat": str(hb)}], f"r2x-hold-{t}")
        started = wait_file(hb, 90)
        import winreg
        loaded = []
        i = 0
        while True:
            try:
                loaded.append(winreg.EnumKey(winreg.HKEY_USERS, i))
            except OSError:
                break
            i += 1
        loaded_cats = sorted({hku_category(n, SETUP["user_sid"], sandbox_sids) for n in loaded})
        r = ad.run("ws-A", [{"id": "R2_hku", "kind": "hku"}], f"r2x-{t}")
        res = ((r.get("result") or {}).get("R2_hku") or {})
        cats = {}
        for n, v in res.get("opened", {}).items():
            cats.setdefault(hku_category(n, SETUP["user_sid"], sandbox_sids), []).append(v)
        proc.kill()
        out.append({"holder_started": started, "host_loaded_categories": loaded_cats, "sandbox_view": cats})
    return out


def g_p7(ad, ctx):
    """P7: every process of the signed-in user, opened per right from the sandbox (open/close only).

    The P1 test process has no logon SID ACE; processes created with the logon session's default DACL
    (explorer and most desktop apps) do. Host side reads each DACL (READ_CONTROL) to split the counts.
    Only counts and the explorer row are kept; process names are not stored.
    """
    out = []
    sandbox_sids = set(x for x in SETUP["codex_accounts"].values() if x)
    for t in range(1, TRIALS + 1):
        cats = process_categories(SETUP["user_sid"], sandbox_sids)
        pids = sorted(int(p) for p, c in cats.items() if c == "user")
        ex = explorer_pid()
        has_logon, label = {}, {}
        for p in pids:
            sd = process_sd(p)
            has_logon[p] = ("unknown" if not isinstance(sd, str) or not sd.startswith("O:")
                            else "logon_sid_ace" if ";S-1-5-5-" in sd else "no_logon_sid_ace")
            label[p] = ("unknown" if not isinstance(sd, str) else "high" if ";;;HI)" in sd
                        else "medium" if ";;;ME)" in sd else "low" if ";;;LW)" in sd else "none")
        r = ad.run("ws-A", [{"id": "P7", "kind": "proc_open", "pids": pids}], f"p7-{t}")
        res = ((r.get("result") or {}).get("P7")) or {}
        agg = {}
        for p in pids:
            v = res.get(str(p))
            if not v:
                continue
            for grp in ("all", has_logon[p], f"label_{label[p]}"):
                g = agg.setdefault(grp, {"processes": 0, "rights": {}})
                g["processes"] += 1
                rights = dict(v["process"])
                if isinstance(v["token"], dict):
                    rights.update(v["token"])
                for name, val in rights.items():
                    c = g["rights"].setdefault(name, {})
                    key = "granted" if val == "granted" else "gone" if val == "error:87" else "denied" if val == "error:5" else val
                    c[key] = c.get(key, 0) + 1
        out.append({"user_processes": len(pids), "exit": r.get("exit"), "by_dacl": agg,
                    "explorer": res.get(str(ex)) if ex else None, "explorer_has_logon_sid_ace": has_logon.get(ex)})
    return out


# =============================================================== UAC session (qwenpaw-admin) and B10
def local_users(prefix):
    import win32net
    out, resume = [], 0
    while True:
        users, _, resume = win32net.NetUserEnum(None, 0, 0, resume)
        out += [u["name"] for u in users if u["name"].lower().startswith(prefix)]
        if not resume:
            return out


def batch_logon_sids():
    import win32security
    h = win32security.LsaOpenPolicy(None, win32security.POLICY_LOOKUP_NAMES | win32security.POLICY_VIEW_LOCAL_INFORMATION)
    try:
        return [win32security.ConvertSidToStringSid(x)
                for x in win32security.LsaEnumerateAccountsWithUserRight(h, "SeBatchLogonRight")]
    finally:
        win32security.LsaClose(h)


def window_object_sids():
    import win32api
    import win32service
    import win32security
    out = {}
    for name, h in (("winsta", win32service.GetProcessWindowStation()),
                    ("desktop", win32service.GetThreadDesktop(win32api.GetCurrentThreadId()))):
        sd = win32security.GetSecurityInfo(h, win32security.SE_WINDOW_OBJECT, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        out[name] = [win32security.ConvertSidToStringSid(dacl.GetAce(i)[2]) for i in range(dacl.GetAceCount())]
    return out


def nul_device_sids():
    import win32file
    import win32security
    h = win32file.CreateFile("\\\\.\\NUL", 0x20000, 3, None, 3, 0, None)
    try:
        sd = win32security.GetSecurityInfo(h.handle, 6, win32security.DACL_SECURITY_INFORMATION)
    finally:
        h.Close()
    dacl = sd.GetSecurityDescriptorDacl()
    return [win32security.ConvertSidToStringSid(dacl.GetAce(i)[2]) for i in range(dacl.GetAceCount())]


def known_qwenpaw_accounts(ad=None):
    try:
        known = load("qwenpaw-admin-accounts.json")
    except OSError:
        known = {}
    if ad is not None:
        known.update(ad.created)
    known.update(qwenpaw_admin_meta())
    save("qwenpaw-admin-accounts.json", known)
    return known


def g_prep(ad, ctx):
    """UAC session: targets/admin-owned, owner Administrators; the user may modify inside but has no WRITE_DAC."""
    import win32security
    from token_backends_common import icacls, sddl, SID_SYSTEM, SID_ADMINS, SID_USERS
    if not is_elevated():
        raise SystemExit("prep needs the UAC-approved session")
    d = TARGETS / "admin-owned"
    created = not d.exists()
    if created:
        d.mkdir()
        win32security.SetNamedSecurityInfo(str(d), win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION,
                                           win32security.ConvertStringSidToSid(SID_ADMINS), None, None, None)
        icacls(d, "/inheritance:r", "/grant:r", f"*{SID_SYSTEM}:(OI)(CI)F", f"*{SID_ADMINS}:(OI)(CI)F",
               f"*{SETUP['user_sid']}:(OI)(CI)M", f"*{SID_USERS}:(OI)(CI)RX")
        (d / "f.txt").write_text("admin-owned-original\n")
    return {"created": created, "dir_sddl": sddl(d), "file_sddl": sddl(d / "f.txt")}


def g_uacstate(ad, ctx):
    """Admin-only state (plan section 3): batch-logon right list, WFP filters, R4 positive control."""
    import winreg
    import xml.etree.ElementTree as ET
    import win32security
    from collections import Counter
    st = {"elevated": is_elevated()}
    codex_prefix = (SETUP["codex_accounts"].get("CodexSandboxOffline") or "").rsplit("-", 1)[0]
    try:
        sids = batch_logon_sids()
        cats, unresolved = Counter(), []
        for ss in sids:
            try:
                name = win32security.LookupAccountSid(None, win32security.ConvertStringSidToSid(ss))[0].lower()
                cat = ("codex_sandbox_account" if name.startswith("codexsandbox")
                       else "qwenpaw_account" if name.startswith("qwenpaw_")
                       else ss if ss.startswith("S-1-5-32-") or ss.count("-") <= 3 else "other_resolved")
            except win32security.error:
                cat = "unresolved_local" if codex_prefix and ss.startswith(codex_prefix + "-") else "unresolved_other"
                unresolved.append(ss)
            cats[cat] += 1
        st["batch_logon_right"] = {"total": len(sids), "by_category": dict(cats), "unresolved_sids": unresolved}
    except Exception as e:
        st["batch_logon_right"] = f"error:{type(e).__name__}:{e}"
    tmp = LOCAL / "wfp-filters-tmp.xml"
    try:
        r = subprocess.run(["netsh", "wfp", "show", "filters", f"file={tmp}"], capture_output=True, timeout=180)
        root = ET.parse(tmp).getroot()
        filters = [it for it in root.iter("item") if it.find("filterKey") is not None]
        named, providers = Counter(), Counter()
        for f in filters:
            dd = f.find("displayData")
            name = (dd.findtext("name") if dd is not None else "") or ""
            desc = (dd.findtext("description") if dd is not None else "") or ""
            if "codex" in (name + " " + desc).lower() or "qwenpaw" in (name + " " + desc).lower():
                named[name[:80]] += 1
                providers[f.findtext("providerKey") or "none"] += 1
        prov = {k for k in providers if k != "none"}
        st["wfp"] = {"netsh_exit": r.returncode, "total_filters": len(filters), "product_filters_by_name": dict(named),
                     "product_filter_providers": dict(providers),
                     "filters_of_those_providers": sum(1 for f in filters if (f.findtext("providerKey") or "none") in prov)}
    except Exception as e:
        st["wfp"] = f"error:{type(e).__name__}:{e}"
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass

    def reg_try(path, access):
        try:
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, access))
            return "granted"
        except OSError as e:
            return f"error:{e.winerror}"
    st["R4_admin_control"] = {"key": ADMIN_KEY, "admin_only_read": reg_try(ADMIN_KEY, winreg.KEY_READ),
                              "hklm_software_write_open": reg_try("SOFTWARE", 0x6)}
    st["qwenpaw_accounts"] = local_users("qwenpaw_")
    st["qwenpaw_group"] = lookup_sid("QwenpawUsers")
    return st


def g_r2hold(ad, ctx):
    """QwenPaw admin keeps a sandbox process (profile hive loaded) while the non-elevated r2qa process runs R2."""
    sync = LOCAL / "r2sync"
    sync.mkdir(exist_ok=True)
    out = []
    for t in range(1, TRIALS + 1):
        hb = ws(ad.name, "ws-A") / f"r2hold-{t}.hb"
        hb.unlink(missing_ok=True)
        proc = ad.start("ws-A", [{"id": "sleep", "kind": "sleep", "seconds": 150, "heartbeat": str(hb)}], f"r2hold-{t}")
        started = wait_file(hb, 240)
        qwen = qwenpaw_admin_meta()
        cats = sorted({hku_cat(n, None, set(qwen)) for n in hku_names_host()})
        (sync / f"ready-{t}.json").write_text(json.dumps({"qwenpaw_sids": sorted(qwen), "host_loaded_categories": cats}))
        done = wait_file(sync / f"done-{t}.json", 300)
        proc.kill()
        proc.wait(30)
        out.append({"holder_started": started, "host_loaded_categories": cats, "peer_done": done})
        print(f"  r2hold trial {t}: started={started} peer_done={done}", flush=True)
    return out


def g_r2qa(ad, ctx):
    """Non-elevated side of R2 (paired with r2hold in the UAC session): both non-admin configs list HKU and open
    every hive with read access while a QwenPaw admin sandbox process is running."""
    sync = LOCAL / "r2sync"
    sync.mkdir(exist_ok=True)
    out = []
    for t in range(1, TRIALS + 1):
        ready = sync / f"ready-{t}.json"
        if not wait_file(ready, 5400 if t == 1 else 600):
            out.append({"error": f"no ready signal for trial {t}"})
            break
        time.sleep(0.5)
        info = json.loads(ready.read_text())
        qwen = set(info["qwenpaw_sids"])
        row = {"host_loaded_categories": info["host_loaded_categories"]}
        for a in (QwenPaw(), Codex("unelevated")):
            r = a.run("ws-A", [{"id": "R2_hku", "kind": "hku"}], f"r2qa-{t}")
            res = ((r.get("result") or {}).get("R2_hku") or {})
            cats = {}
            for n, v in res.get("opened", {}).items():
                cats.setdefault(hku_cat(n, None, qwen), []).append(v)
            row[a.name] = {"exit": r.get("exit"), "by_category": cats}
        (sync / f"done-{t}.json").write_text("{}")
        out.append(row)
        print(f"  r2qa trial {t} done", flush=True)
    return out


def g_b10(ad, ctx):
    """B10: targets/admin-owned as writable mount (QwenPaw) or extra writable root (Codex isob10 profile)."""
    d = TARGETS / "admin-owned"

    def explicit():
        return [a for a in dacl_aces(d) if not a["flags"] & 0x10]
    out = {"explicit_aces_before": explicit(), "trials": []}
    for t in range(1, (1 if ad.name == "codex-unelevated" else TRIALS) + 1):
        tasks = [{"id": "fs", "kind": "fs", "ops": [
            {"id": "B10_write", "op": "write", "path": str(d / f"b10-{ad.name}-{t}.txt")},
            {"id": "B10_read", "op": "read", "path": str(d / "f.txt")}]}]
        r = ad.run("ws-A", tasks, f"b10-{t}", variant="full" if isinstance(ad, QwenPaw) else "isob10")
        r["explicit_aces_after"] = explicit()
        out["trials"].append(r)
        print(f"  b10 trial {t}: exit={r.get('exit')}", flush=True)
    return out


def g_r3(ad, ctx):
    """R3 (Codex elevated): state shared between workspaces through the fixed sandbox account.
    ws-A writes a synthetic file in the sandbox account's profile folder, ws-B checks it, reads it and
    deletes it, then ws-A checks that it is gone. HKCU is opened with write and read access only."""
    import winreg
    if ad.name != "codex-elevated":
        raise SystemExit("r3 is defined for codex-elevated")
    sid = SETUP["codex_accounts"]["CodexSandboxOffline"]
    pl = rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, pl) as k:
        prof = Path(winreg.QueryValueEx(k, "ProfileImagePath")[0])
    keys = [{"id": "hkcu_software_write", "root": "HKCU", "path": "Software", "access": 0x6},
            {"id": "hkcu_software_read", "root": "HKCU", "path": "Software", "access": 0x20019}]
    common = [{"id": "token", "kind": "token"}, {"id": "reg", "kind": "reg", "keys": keys},
              {"id": "env", "kind": "env", "names": ["USERPROFILE", "TEMP"]}]

    def tok(r):
        t = ((r.get("result") or {}).get("token") or {})
        return t if isinstance(t, dict) else {}
    out = {"trials": []}
    for t in range(1, TRIALS + 1):
        f = prof / f"agent-isolation-r3-{t}.txt"
        a = ad.run("ws-A", common + [{"id": "fs", "kind": "fs", "ops": [
            {"id": "write", "op": "write", "path": str(f), "data": f"r3-from-ws-A-{t}\n"},
            {"id": "exists", "op": "exists", "path": str(f)}]}], f"r3a-{t}")
        try:
            host_sees = "exists" if f.exists() else "missing"
        except PermissionError:
            host_sees = "denied"  # the sandbox account profile DACL does not include the user
        b = ad.run("ws-B", common + [{"id": "fs", "kind": "fs", "ops": [
            {"id": "exists", "op": "exists", "path": str(f)},
            {"id": "read", "op": "read", "path": str(f)},
            {"id": "delete", "op": "delete", "path": str(f)}]}], f"r3b-{t}")
        c = ad.run("ws-A", [{"id": "fs", "kind": "fs", "ops": [{"id": "exists", "op": "exists", "path": str(f)}]}],
                   f"r3c-{t}")
        ta, tb = tok(a), tok(b)
        row = {"exits": [a.get("exit"), b.get("exit"), c.get("exit")],
               "ws_a": {k: (a.get("result") or {}).get(k) for k in ("fs", "reg", "env")},
               "ws_b": {k: (b.get("result") or {}).get(k) for k in ("fs", "reg", "env")},
               "ws_a_after": (c.get("result") or {}).get("fs"),
               "host_sees_file": host_sees,
               "same_user_sid": ta.get("user") == tb.get("user") and bool(ta.get("user")),
               "user_is_sandbox_account": ta.get("user") == sid,
               "restricted_sids_differ": ta.get("restricted_sids") != tb.get("restricted_sids"),
               "hkcu": [ta.get("hkcu"), tb.get("hkcu")], "profile_dir_matches": ta.get("profile_dir") == str(prof),
               "stderr": [a.get("stderr"), b.get("stderr"), c.get("stderr")]}
        out["trials"].append(row)
        print(f"  r3 trial {t}: exits={row['exits']} b={row['ws_b']['fs']} after={row['ws_a_after']}", flush=True)
    # sweep: the sandbox deletes anything a failed trial left behind (the host cannot open this profile)
    sweep = ad.run("ws-A", [{"id": "fs", "kind": "fs", "ops": [
        {"id": f"t{t}", "op": "exists", "path": str(prof / f"agent-isolation-r3-{t}.txt")} for t in range(1, TRIALS + 1)]}],
        "r3-sweep")
    out["sweep_exists"] = (sweep.get("result") or {}).get("fs")
    left = [t for t in range(1, TRIALS + 1) if (out["sweep_exists"] or {}).get(f"t{t}") == "exists"]
    if left:
        d = ad.run("ws-A", [{"id": "fs", "kind": "fs", "ops": [
            {"id": f"t{t}", "op": "delete", "path": str(prof / f"agent-isolation-r3-{t}.txt")} for t in left]}], "r3-sweep-del")
        out["sweep_deleted"] = (d.get("result") or {}).get("fs")
    return out


def _subkey_exists(k, name):
    import winreg
    try:
        winreg.CloseKey(winreg.OpenKey(k, name))
        return True
    except OSError:
        return False


def g_cleanuprec(ad, ctx):
    """QwenPaw admin: H6 (worker with the product's exit cleanup killed during a command), the next run's
    cleanup of the orphan, then what stays on the PC."""
    import winreg
    out = {}
    hb = ws(ad.name, "ws-B") / "h6.hb"
    hb.unlink(missing_ok=True)
    proc = ad.start("ws-B", [{"id": "sleep", "kind": "sleep", "seconds": 60, "heartbeat": str(hb)}], "h6", cleanup=True)
    started = wait_file(hb, 240)
    proc.kill()
    proc.wait(30)
    time.sleep(2)
    out["H6"] = {"started": started, "sandbox_alive_after_kill": heartbeat_alive(hb, 3),
                 "metadata_after_kill": len(qwenpaw_admin_meta()), "accounts_after_kill": len(local_users("qwenpaw_"))}
    known = known_qwenpaw_accounts(ad)
    out["final_cleanup"] = ad.cleanup()
    time.sleep(3)
    sids = set(known)
    caps = {v.get("cap_sid") for v in known.values() if v.get("cap_sid")}
    lo = {"accounts_created_total": len(sids), "accounts_remaining": len(local_users("qwenpaw_")),
          "metadata_remaining": qwenpaw_admin_meta()}
    pl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, pl) as k:
        lo["profilelist_keys"] = sum(1 for sid in sids if _subkey_exists(k, sid))
    lo["profile_dirs"] = len([p for p in Path(r"C:\Users").iterdir() if p.name.lower().startswith("qwenpaw_")])
    try:
        lo["batch_logon_right_sids"] = len(set(batch_logon_sids()) & sids)
    except Exception as e:
        lo["batch_logon_right_sids"] = f"error:{e}"
    paths = [ROOT, ROOT / ad.name, *(ws(ad.name, n) for n in ("ws-A", "ws-B", "ws-large")), ws(ad.name, "ws-A") / "ro",
             TARGETS / "admin-owned", TARGETS / "deny-read"]
    lo["test_path_aces"] = {str(p): sum(1 for a in dacl_aces(p) if a["sid"] in sids | caps) for p in paths if p.exists()}
    try:
        wo = window_object_sids()
        lo["window_object_aces"] = {k: sum(1 for x in v if x in sids) for k, v in wo.items()}
    except Exception as e:
        lo["window_object_aces"] = f"error:{e}"
    try:
        lo["nul_device_cap_aces"] = sum(1 for x in nul_device_sids() if x in caps)
    except Exception as e:
        lo["nul_device_cap_aces"] = f"error:{e}"
    venv = Path(os.environ["LOCALAPPDATA"]) / "agent-isolation-qwenpaw-2.3.0.post1"
    grp = lookup_sid("QwenpawUsers")
    lo["qwenpaw_group"] = bool(grp)
    lo["venv_group_ace"] = any(a["sid"] == grp for a in dacl_aces(venv)) if grp else None
    lo["venv_marker"] = (venv / ".qwenpaw_acl_granted").exists()
    out["leftovers"] = lo
    return out


GROUPS = {"core": g_core, "b6first": g_b6first, "b5": g_b5, "b8b": g_b8b, "c5": g_c5, "f1": g_f1, "g4": g_g4,
          "g": g_g, "p6": g_p6, "h": g_h, "r2x": g_r2x, "p7": g_p7, "prep": g_prep, "uac-before": g_uacstate,
          "uac-after": g_uacstate, "r2hold": g_r2hold, "r2qa": g_r2qa, "b10": g_b10, "cleanuprec": g_cleanuprec, "r3": g_r3}


def main():
    global SETUP
    if sys.argv[1] == "qwenpaw-worker":
        qwenpaw_worker(sys.argv[2])
        return
    SETUP = load("setup.json")
    config, groups = sys.argv[1], sys.argv[2:]
    ad = adapter(config)
    if ad.name == "qwenpaw-admin" and not is_elevated():
        raise SystemExit("qwenpaw-admin needs the UAC-approved session (IsUserAnAdmin is false)")
    c3, c3_pre = host_targets()
    sandbox_sids = set(x for x in SETUP["codex_accounts"].values() if x)
    ctx = {"c3": c3, "c3_pre_codex_group_ace": c3_pre, "admin_key": admin_only_key() or (ADMIN_KEY if is_elevated() else None),
           "categories": process_categories(SETUP["user_sid"], sandbox_sids)}
    for g in groups:
        print(f"[{config}] {g} ...", flush=True)
        t0 = time.monotonic()
        res = GROUPS[g](ad, ctx)
        save(f"{config}-{g}.json", {"config": config, "group": g, "trials": TRIALS, "seconds": round(time.monotonic() - t0, 1),
                                    "context": {k: v for k, v in ctx.items() if k != "categories"}, "result": res})
        if ad.name == "qwenpaw-admin":
            known_qwenpaw_accounts(ad)
        print(f"[{config}] {g} done in {round(time.monotonic() - t0, 1)}s", flush=True)


if __name__ == "__main__":
    main()
