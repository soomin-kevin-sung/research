"""Counts for runs/2026-11-26-04.md from local/2026-11-26-rt2 (tools, gitbash, pwsh, codex-net) and
local/2026-11-26-survey (registry, pipes). Prints Markdown tables; SIDs are already replaced by kind."""
import json
import sys
from pathlib import Path

L = Path(__file__).resolve().parents[1] / "local"
RT2, SURVEY = L / "2026-11-26-rt2", L / "2026-11-26-survey"


def load(p):
    return json.loads(p.read_text(encoding="utf-8"))


def ok(v, needle=None):
    return isinstance(v, dict) and v.get("exit") == 0 and (needle is None or needle in (v.get("stdout") or "") + (v.get("stderr") or ""))


def count(trials, fn):
    vals = [fn(t) for t in trials]
    return f"{sum(1 for v in vals if v)}/{len(vals)}"


def child_res(phase):
    L1 = (phase or {}).get("launcher")
    if not isinstance(L1, dict):
        return {}
    for lid, r in L1["launches"].items():
        if lid.startswith("child") and isinstance(r, dict) and isinstance(r.get("result"), dict):
            return r["result"]
    return {}


def tools():
    d = load(RT2 / "tools.json")["result"]
    rows = [("사용자 프로필 아래 Python 3.12(python.org 사용자 설치) 실행, `ssl`·`sqlite3` import", "userpy_version", "userpy-ok"),
            ("같은 Python으로 `python -m unittest`(자식 프로세스 파이프, 임시 폴더 포함 시험 3개)", "userpy_unittest", "OK"),
            ("시험용 Python으로 `python -m unittest`", "pyrt_unittest", "OK"),
            ("`WindowsApps\\python.exe` 앱 실행 별칭(`--version`)", "alias_python", "Python"),
            ("`npm --version`", "npm_version", None),
            ("`npm run`(자식 프로세스를 stdio 파이프로 시작하는 스크립트)", "npm_run", "child-ok"),
            ("같은 `npm run`, npm 캐시를 쓸 수 있는 폴더로 지정", "npm_run_cache", "child-ok")]
    print("| 명령 | 샌드박스(Codex `elevated` 구조) | 호스트 |")
    print("| --- | --- | --- |")
    for label, k, needle in rows:
        s = count(d, lambda t: ok(child_res(t["sandbox"]).get(k), needle))
        h = count(d, lambda t: ok(t["host"].get(k), needle))
        print(f"| {label} | {s} | {h} |")
    first = child_res(d[0]["sandbox"])
    print("\nalias sandbox:", first.get("alias_python"), "\nalias host:", d[0]["host"].get("alias_python"))


def gitbash():
    d = load(RT2 / "gitbash.json")["result"]
    names = {"A_real": "가. 사용자 Git Bash가 떠 있는 상태(설치본) → 샌드박스", "A_copy": "가. 사용자 Git Bash(복사본) 먼저 → 샌드박스",
             "B": "나. 샌드박스(복사본) 먼저 유지 → 사용자 Git Bash", "C": "다. 샌드박스 두 개 동시(작업 폴더·capability SID 다름)",
             "D": "라. Git Bash 없음 → 샌드박스만"}
    keys = ("bash_echo", "bash_pipe", "bash_subst", "bash_bg")
    print("| 순서 | 샌드박스 T5(echo·파이프라인·명령 치환·백그라운드) | 사용자 쪽 | MSYS2 디렉터리 소유자·DACL |")
    print("| --- | --- | --- | --- |")
    for k, trials in d.items():
        if k == "C":
            sb = count(trials, lambda t: all(ok(child_res(t["A"]).get(x)) for x in keys) and all(ok(child_res(t["B"]).get(x)) for x in keys))
            user = "—"
            snap = (trials[0]["A"].get("during") or {}).get("first") or {}
        elif k == "B":
            sb = count(trials, lambda t: ok(child_res(t["sandbox"]).get("bash_hold"), "hold-ok"))
            user = count(trials, lambda t: all(ok(((t["sandbox"].get("during") or {}).get("user_bash") or {}).get(x)) for x in keys))
            snap = (trials[0]["sandbox"].get("during") or {}).get("dir_after_sandbox_start") or {}
        else:
            sb = count(trials, lambda t: all(ok(child_res(t["sandbox"]).get(x)) for x in keys))
            user = "—"
            snap = (trials[0]["sandbox"].get("during") or {}).get("first") or {}
        pre = count(trials, lambda t: t.get("absent_before", True))
        print(f"| {names[k]} | {sb} | {user} | `{snap.get('dir')}` (회차 시작 전 복사본 디렉터리 없음 {pre}) |")
    if "A_real" in d:
        print("\nA_real launcher:", count(d["A_real"], lambda t: ok(child_res(t["sandbox"]).get("bash_launcher"), "launcher-ok")))


def pwsh():
    d = load(RT2 / "pwsh.json")["result"]
    items = [("PowerShell 시작 위치가 작업 폴더", "ps", "pwd", lambda v, ws: v == ws),
             ("`Get-Content .\\a.txt`", "ps", "gc", lambda v, ws: v == "a-original"),
             ("`New-Item .\\b.txt`", "ps", "ni", lambda v, ws: v == "ok"),
             ("`Resolve-Path ..\\ws`", "ps", "rp", lambda v, ws: v == ws),
             ("작업 폴더 밖 허용 폴더로 `Push-Location`", "ps", "pl_allowed", lambda v, ws: v and not v.startswith("err")),
             ("작업 폴더 밖 허용 폴더로 `Set-Location`", "ps", "sl_allowed", lambda v, ws: v and not v.startswith("err")),
             ("`Set-Location 'C:\\Program Files'`", "ps", "sl_pf", lambda v, ws: v == "C:\\Program Files"),
             ("cmd 시작 위치·`dir`·`type a.txt`", "cmd", "type", lambda v, ws: v == "ok"),
             ("cmd `cd /d` 허용 폴더·`dir`", "cmd", "dir_after", lambda v, ws: v == "ok")]
    conds = ("none", "user-parents")
    print("| 동작 | 상위 목록 ACE 없음 | 사용자 소유 시험 상위에만 목록 ACE |")
    print("| --- | --- | --- |")
    for label, lid, key, pred in items:
        cells = []
        for c in conds:
            def f(t):
                ws = t["launcher"]["launches"]["child"]["result"]["py_rel"]["stdout"].split("cwd=")[1].splitlines()[0].strip()
                r = t["launcher"]["launches"][lid].get("result") or {}
                return pred(r.get(key), ws)
            cells.append(count(d[c], f))
        print(f"| {label} | " + " | ".join(cells) + " |")
    for c in conds:
        print(f"| Python `os.getcwd()`·상대 경로 읽기·쓰기 ({c}) | " +
              count(d[c], lambda t: ok(t["launcher"]["launches"]["child"]["result"]["py_rel"], "write=ok")) + " | |")
    first = d["none"][0]["launcher"]["launches"]
    print("\nnone ps:", json.dumps(first["ps"]["result"], ensure_ascii=False)[:600])
    print("parents none:", json.dumps(first["child"]["result"]["parents"], ensure_ascii=False)[:900])
    print("aces removed:", d.get("aces_removed"), "targets:", d.get("targets_user-parents"))


def net():
    d = load(RT2 / "codex-net.json")
    keys = [("tcp_443", "TCP 443 연결"), ("http_curl", "HTTP(curl)"), ("https_urllib", "HTTPS(Python urllib)"),
            ("https_curl", "HTTPS(curl, schannel)"), ("https_iwr", "HTTPS(Invoke-WebRequest)"),
            ("dns_nslookup", "`nslookup`(직접 DNS 질의)"), ("dns_resolve_dnsname", "`Resolve-DnsName`(DNS 클라이언트 서비스)"),
            ("dns_getaddrinfo", "Python `getaddrinfo`(DNS 클라이언트 서비스)")]
    print("| 항목 | offline | online | 호스트 |")
    print("| --- | --- | --- | --- |")
    for k, label in keys:
        print(f"| {label} | " + " | ".join(count(d[x], lambda r: r["summary"].get(k)) for x in ("offline", "online", "host")) + " |")
    print("\naccounts:", [r.get("account") for r in d["offline"]], [r.get("account") for r in d["online"]],
          "codex accounts unchanged:", d.get("codex_accounts_unchanged"))


def survey():
    r = load(SURVEY / "registry.json")
    p = load(SURVEY / "pipes.json")
    print("registry:", r["seconds"], r["stats"], r["counts"], r["counts_explicit"])
    print("pipes:", p["total"], p["groups"])


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    for name in sys.argv[1:] or ("survey", "net", "tools", "gitbash", "pwsh"):
        print(f"\n## {name}")
        globals()[name]()
