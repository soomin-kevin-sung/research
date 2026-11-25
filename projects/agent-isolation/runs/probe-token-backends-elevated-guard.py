"""Runs the Codex elevated groups one at a time and stops if the sandbox accounts were re-provisioned.

Re-provisioning is detected by the two accounts' PasswordLastSet and the hash of
~/.codex/.sandbox-secrets/sandbox_users.json (plan-token-backends.md 2.3). Usage:
  python probe-token-backends-elevated-guard.py <group> [<group> ...]
"""
import sys
import json
import hashlib
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import REAL_CODEX_HOME, save  # noqa: E402


def account_state():
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-LocalUser CodexSandboxOffline,CodexSandboxOnline | ForEach-Object { $_.Name + '=' + $_.PasswordLastSet.ToString('o') }"],
                       capture_output=True)
    users = REAL_CODEX_HOME / ".sandbox-secrets" / "sandbox_users.json"
    return {"passwords": r.stdout.decode().split(),
            "users_file": hashlib.sha256(users.read_bytes()).hexdigest() if users.exists() else "missing"}


GUARD_FILE = "codex-elevated-guard.json" if sys.argv[1:] == ["p7"] else f"codex-elevated-guard-{'-'.join(sys.argv[1:])}.json"
base = account_state()
log = {"baseline": base, "groups": []}
for g in sys.argv[1:]:
    p = subprocess.run([sys.executable, str(Path(__file__).with_name("probe-token-backends-campaign.py")),
                        "codex-elevated", g], capture_output=True)
    now = account_state()
    entry = {"group": g, "exit": p.returncode, "tail": p.stdout.decode("utf-8", "replace")[-300:],
             "stderr": p.stderr.decode("utf-8", "replace")[-500:], "accounts_unchanged": now == base}
    log["groups"].append(entry)
    print(json.dumps({k: entry[k] for k in ("group", "exit", "accounts_unchanged")}), flush=True)
    save(GUARD_FILE, log)
    if now != base:
        log["stopped"] = {"after": g, "state": now}
        save(GUARD_FILE, log)
        print("STOP: sandbox account state changed", flush=True)
        break
