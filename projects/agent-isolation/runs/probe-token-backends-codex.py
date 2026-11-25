"""Codex `unelevated` / `elevated` measurements for plan-token-backends.md.

Every invocation names CODEX_HOME, the Windows backend and an explicit permission profile defined on
the command line (`-c permissions.<name>...`, `-P <name>`); the real config.toml is never edited.
The command always follows `--`. Usage:
  python probe-token-backends-codex.py precheck <unelevated|elevated>
  python probe-token-backends-codex.py run <unelevated|elevated> [group ...]
Results go to local/2026-11-25/codex-<level>-<group>.json.
"""
import os
import sys
import json
import time
import uuid
import shutil
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, CODEX, REAL_CODEX_HOME, TARGETS, PY, CHILD, save, load,  # noqa: E402
                                   parse_isojson, write_spec, child_argv, heartbeat_alive, wait_file,
                                   find_window, process_categories, hku_category, start_test_process, ws)

TRIALS = int(os.environ.get("ISO_TRIALS", "5"))
FS_BASE = '":root"="read", ":tmpdir"="write", ":workspace_roots"={"."="write", "ro"="read"}'
PROFILES = {
    "iso": "{" + FS_BASE + "}",
    "isodeny": "{" + FS_BASE + f", '{TARGETS / 'deny-read'}'=\"deny\"" + "}",
}


def level_paths(level):
    cfg = f"codex-{level}"
    home = ROOT / cfg / "home" if level == "unelevated" else REAL_CODEX_HOME
    return cfg, home, ROOT / cfg / "temp"


def codex_argv(level, wsdir, spec, profile="iso"):
    return [str(CODEX), "sandbox", "-c", f'windows.sandbox="{level}"',
            "-c", f"permissions.{profile}.filesystem={PROFILES[profile]}",
            "-c", f"permissions.{profile}.network.enabled=false",
            "-P", profile, "-C", str(wsdir), "--", *child_argv(spec)]


def codex_env(level, extra=None):
    _, home, temp = level_paths(level)
    env = os.environ.copy()
    env.pop("CODEX_WINDOWS_REGISTERED_CORE", None)
    env.update(CODEX_HOME=str(home), TEMP=str(temp), TMP=str(temp),
               ISO_TB_PLAIN="plain-marker-1", ISO_TB_API_KEY="apikey-marker-2")
    env.update(extra or {})
    return env


def run(level, wsdir, tasks, tag, profile="iso", timeout=180, extra_env=None):
    spec = write_spec(wsdir, tag, tasks)
    t0 = time.monotonic()
    p = subprocess.run(codex_argv(level, wsdir, spec, profile), cwd=wsdir, env=codex_env(level, extra_env),
                       capture_output=True, timeout=timeout)
    out = p.stdout.decode("utf-8", "replace")
    return {"exit": p.returncode, "seconds": round(time.monotonic() - t0, 3), "result": parse_isojson(out),
            "stderr": p.stderr.decode("utf-8", "replace")[-600:]}


def start(level, wsdir, tasks, tag, profile="iso"):
    spec = write_spec(wsdir, tag, tasks)
    return subprocess.Popen(codex_argv(level, wsdir, spec, profile), cwd=wsdir, env=codex_env(level),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def account_state():
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-LocalUser CodexSandboxOffline,CodexSandboxOnline | ForEach-Object { $_.Name + '=' + $_.PasswordLastSet.ToString('o') }"],
                       capture_output=True)
    users = REAL_CODEX_HOME / ".sandbox-secrets" / "sandbox_users.json"
    import hashlib
    return {"passwords": r.stdout.decode().split(), "users_file": hashlib.sha256(users.read_bytes()).hexdigest()
            if users.exists() else "missing"}


def precheck(level):
    cfg, home, temp = level_paths(level)
    wsdir = ws(cfg, "ws-A")
    rec = {"level": level, "codex_version": subprocess.run([str(CODEX), "--version"], capture_output=True,
                                                            env=codex_env(level)).stdout.decode().strip()}
    if level == "elevated":
        rec["accounts_before"] = account_state()
    tasks = [{"id": "token", "kind": "token"},
             {"id": "env", "kind": "env", "names": ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP",
                                                    "ISO_TB_PLAIN", "ISO_TB_API_KEY", "CODEX_SANDBOX",
                                                    "CODEX_SANDBOX_NETWORK_DISABLED", "HTTP_PROXY", "NO_PROXY"]},
             {"id": "fs", "kind": "fs", "ops": [{"id": "ws_write", "op": "write", "path": str(wsdir / "precheck.txt")},
                                                {"id": "ws_read", "op": "read", "path": str(wsdir / "precheck.txt")}]}]
    rec["run"] = run(level, wsdir, tasks, f"precheck-{uuid.uuid4().hex[:6]}")
    if level == "elevated":
        rec["accounts_after"] = account_state()
        rec["accounts_unchanged"] = rec["accounts_before"] == rec["accounts_after"]
    log = sorted((home / ".sandbox").glob("sandbox*.log"), key=lambda p: p.stat().st_mtime)
    if log:
        tail = log[-1].read_text(encoding="utf-8", errors="replace").splitlines()[-40:]
        rec["log_selection"] = [ln for ln in tail if "selection" in ln or "MXC" in ln or "error" in ln.lower()][-6:]
    print(save(f"codex-{level}-precheck.json", rec))
    return rec


if __name__ == "__main__":
    mode, level = sys.argv[1], sys.argv[2]
    if mode == "precheck":
        r = precheck(level)
        print(json.dumps({k: r[k] for k in r if k != "run"}, ensure_ascii=False)[:1500])
        res = r["run"]["result"] or {}
        print("exit", r["run"]["exit"], "stderr", r["run"]["stderr"][-400:])
        tok = res.get("token", {})
        print(json.dumps({k: tok.get(k) for k in ("user", "logon_sids", "restricted_sids", "integrity", "desktop",
                                                   "winsta", "hkcu", "profile_dir", "in_job", "limit_flags",
                                                   "ui_restrictions", "ppid_chain")}, ensure_ascii=False)[:2500])
        print(json.dumps(res.get("env"), ensure_ascii=False), json.dumps(res.get("fs")))
