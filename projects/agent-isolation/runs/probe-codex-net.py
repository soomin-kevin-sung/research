"""Is the network blocked for Codex elevated's offline account, and open for the online one? (runs/2026-11-26-04.md)

Requested by another session that splits shell network access into an offline and an online account. The
user asked only whether the network is blocked or not (no per-domain checks, no SMB, no BITS, no loopback).
Runs the installed Codex CLI (`codex sandbox`, windows.sandbox="elevated") with network.enabled=false
(CodexSandboxOffline) and =true (CodexSandboxOnline), five trials each, plus the same commands on the host.
Each run starts the in-sandbox program, which runs:
  a TCP connection to example.com:443 (Python), HTTP GET http://example.com/ (curl.exe)
  HTTPS GET https://example.com/ with curl.exe, PowerShell Invoke-WebRequest and Python urllib
  name lookups of example.com with Resolve-DnsName (DNS client service), nslookup (own UDP query) and Python
  socket.getaddrinfo
No data other than the request itself is sent. Codex's own per-command refresh runs as it does in normal use
(it may add CodexSandboxUsers read ACEs to profile children); the PC state before and after is compared.

Usage (normal session, ISO_DATE=2026-11-26-rt2, ISO_ROOT=%USERPROFILE%\\agent-isolation-rt2):
  python probe-codex-net.py run
"""
import os
import sys
import json
import time
import uuid
import hashlib
import subprocess
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26-rt2")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, PY, CHILD, CODEX, REAL_CODEX_HOME, save, parse_isojson, write_spec,  # noqa: E402
                                   lookup_sid)

TRIALS = int(os.environ.get("ISO_TRIALS", "5"))
BASE = ROOT / "codex-net"
WS, TEMP = BASE / "ws", BASE / "temp"
URL, HOST = "https://example.com/", "example.com"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CURL = r"C:\Windows\System32\curl.exe"
NSLOOKUP = r"C:\Windows\System32\nslookup.exe"


def ps(cmd):
    return [PS, "-NoProfile", "-NonInteractive", "-Command", f"try {{ {cmd} }} catch {{ 'err:' + $_.Exception.Message }}"]


def tasks():
    def run(tid, argv, timeout=40):
        return {"id": tid, "kind": "run", "argv": argv, "cwd": str(WS), "timeout": timeout, "stdin": "pipe"}
    return [{"id": "token", "kind": "token"},
            {"id": "env", "kind": "env", "names": ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy",
                                                  "https_proxy", "CODEX_SANDBOX_NETWORK_DISABLED"]},
            # connection only and plain HTTP: separate "blocked" from TLS failures (first trial: the online
            # account connected but schannel and Python could not complete TLS)
            run("tcp_443", [str(PY), "-c", f"import socket; socket.create_connection(('{HOST}', 443), timeout=10).close(); print('tcp-ok')"]),
            run("http_curl", [CURL, "-sS", "-o", "NUL", "-w", "%{http_code}", "--max-time", "15", f"http://{HOST}/"]),
            run("https_curl", [CURL, "-sS", "-o", "NUL", "-w", "%{http_code}", "--max-time", "15", URL]),
            run("https_iwr", ps(f"(Invoke-WebRequest -UseBasicParsing -Uri {URL} -TimeoutSec 15).StatusCode")),
            run("https_urllib", [str(PY), "-c", f"import urllib.request as u; print(u.urlopen('{URL}', timeout=15).status)"]),
            run("dns_resolve_dnsname", ps(f"(Resolve-DnsName {HOST} -Type A -ErrorAction Stop | Select-Object -First 1).IPAddress")),
            run("dns_nslookup", [NSLOOKUP, "-timeout=5", HOST]),
            run("dns_getaddrinfo", [str(PY), "-c", f"import socket; print(socket.getaddrinfo('{HOST}', 443)[0][4][0])"])]


def codex_argv(spec, network):
    prof = '{":root"="read", ":tmpdir"="write", ":workspace_roots"={"."="write"}}'
    return [str(CODEX), "sandbox", "-c", 'windows.sandbox="elevated"', "-c", f"permissions.iso.filesystem={prof}",
            "-c", f"permissions.iso.network.enabled={'true' if network else 'false'}", "-P", "iso", "-C", str(WS), "--",
            str(PY), "-I", "-B", str(CHILD), str(spec)]


def codex_env():
    env = os.environ.copy()
    env.pop("CODEX_WINDOWS_REGISTERED_CORE", None)
    env.update(CODEX_HOME=str(REAL_CODEX_HOME), TEMP=str(TEMP), TMP=str(TEMP))
    return env


def codex_accounts():
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        "Get-LocalUser CodexSandboxOffline,CodexSandboxOnline | ForEach-Object { $_.Name + '=' + $_.PasswordLastSet.ToString('o') }"],
                       capture_output=True)
    users = REAL_CODEX_HOME / ".sandbox-secrets" / "sandbox_users.json"
    return {"passwords": r.stdout.decode().split(),
            "users_file": hashlib.sha256(users.read_bytes()).hexdigest() if users.exists() else "missing"}


def summarize(res):
    def ok(v, pred):
        return isinstance(v, dict) and v.get("exit") == 0 and pred((v.get("stdout") or "").strip())
    if not isinstance(res, dict):
        return {"result": "none"}
    return {"tcp_443": ok(res.get("tcp_443"), lambda s: s == "tcp-ok"),
            "http_curl": ok(res.get("http_curl"), lambda s: s.startswith(("2", "3"))),
            "https_curl": ok(res.get("https_curl"), lambda s: s.startswith(("2", "3"))),
            "https_iwr": ok(res.get("https_iwr"), lambda s: s[:1] in "23"),
            "https_urllib": ok(res.get("https_urllib"), lambda s: s[:1] in "23"),
            "dns_resolve_dnsname": ok(res.get("dns_resolve_dnsname"), lambda s: s.count(".") == 3 and not s.startswith("err")),
            "dns_nslookup": ok(res.get("dns_nslookup"), lambda s: "Addresses" in s or s.count("Address") >= 2),
            "dns_getaddrinfo": ok(res.get("dns_getaddrinfo"), lambda s: s.count(".") == 3)}


def main():
    if sys.argv[1:] != ["run"]:
        raise SystemExit(__doc__)
    for d in (WS, TEMP):
        d.mkdir(parents=True, exist_ok=True)
    acc = {n: lookup_sid(n) for n in ("CodexSandboxOffline", "CodexSandboxOnline")}
    base = codex_accounts()
    out = {"accounts": {k: bool(v) for k, v in acc.items()}, "offline": [], "online": [], "host": []}
    for t in range(1, TRIALS + 1):
        for label, network in (("offline", False), ("online", True)):
            tag = f"net-{label}-{t}-{uuid.uuid4().hex[:6]}"
            spec = write_spec(WS, tag, tasks())
            t0 = time.monotonic()
            p = subprocess.run(codex_argv(spec, network), cwd=WS, env=codex_env(), capture_output=True, timeout=600)
            res = parse_isojson(p.stdout.decode("utf-8", "replace"))
            user = ((res or {}).get("token") or {}).get("user") if isinstance(res, dict) else None
            rec = {"trial": t, "exit": p.returncode, "seconds": round(time.monotonic() - t0, 1),
                   "account": next((k for k, v in acc.items() if v == user), "other" if user else None),
                   "summary": summarize(res), "env": (res or {}).get("env") if isinstance(res, dict) else None,
                   "detail": {k: v for k, v in (res or {}).items() if k not in ("token", "env")} if isinstance(res, dict) else None,
                   "stderr": p.stderr.decode("utf-8", "replace")[-400:]}
            out[label].append(rec)
            print(f"{label} trial {t}: {rec['account']} {rec['summary']}", flush=True)
        spec = write_spec(WS, f"net-host-{t}", tasks()[2:])
        p = subprocess.run([str(PY), "-I", "-B", str(CHILD), str(spec)], cwd=WS, capture_output=True, timeout=600,
                           env={**os.environ, "TEMP": str(TEMP), "TMP": str(TEMP)})
        res = parse_isojson(p.stdout.decode("utf-8", "replace"))
        out["host"].append({"trial": t, "summary": summarize(res), "detail": res})
        print(f"host trial {t}: {out['host'][-1]['summary']}", flush=True)
        save("codex-net-partial.json", out)
    out["codex_accounts_unchanged"] = codex_accounts() == base
    print(save("codex-net.json", out))


if __name__ == "__main__":
    main()
