"""Summary table of the reduced restricting SID measurement (runs/2026-11-26-03.md).

Usage: python probe-rt-reduced-summary.py [--detail]
Reads local/2026-11-26-rt/main.json and fix-*.json, prints a Markdown table: per item and configuration,
the number of trials in which the item worked ("k/n"). A trial in which the measuring process itself did
not start counts as "not started" (shown as "시작 못 함"). --detail adds the first error seen per cell.
SIDs are replaced by their kind.
"""
import sys
import json
from pathlib import Path

LOCAL = Path(__file__).resolve().parents[1] / "local" / "2026-11-26-rt"
COLUMNS = [("main", "base", "기준"), ("main", "reduced", "축소"), ("fix-desktop", None, "축소+데스크톱"),
           ("fix-dacl", None, "축소+기본 DACL"), ("fix-desktop-dacl", None, "축소+데스크톱+DACL"),
           ("fix-devices", None, "축소+장치"), ("fix-all", None, "축소+셋 다"), ("fix-all-local", None, "축소+셋 다+Local"),
           ("fix-all-local-bno", None, "축소+셋 다+Local+전역 BNO"),
           ("fix-all-local-bno-msys", None, "위+MSYS2 디렉터리"),
           ("main", "host", "호스트 대조군")]
NA = "na"


def load(name):
    p = LOCAL / f"{name}.json"
    return json.loads(p.read_text(encoding="utf-8"))["result"] if p.exists() else None


def host_shape(h):
    """Host control record -> the trial shape (no window, squat or holes)."""
    launches = {k: {"exit": f"0x{v['exit'] & 0xffffffff:08x}", "result": v["result"]}
                for k, v in h.items() if k in ("ps_basic", "ps_null", "cmd_null")}
    launches["child"] = {"exit": f"0x{h['child']['exit'] & 0xffffffff:08x}", "result": h["child"]["result"]}
    return {"main": {"launcher": {"launches": launches}}, "host": True}


def launch(rec, lid, phase="main"):
    L = (rec.get(phase) or {}).get("launcher")
    return (L or {}).get("launches", {}).get(lid) if isinstance(L, dict) else None


def started(rec, lid, phase="main"):
    """The program ran its script: exit 0, or a result with the final "done" line or a child result."""
    r = launch(rec, lid, phase)
    if not isinstance(r, dict):
        return False
    out = r.get("result")
    return r.get("exit") == "0x00000000" or (isinstance(out, dict) and ("done" in out or "token" in out))


def res(rec, lid, phase="main"):
    r = launch(rec, lid, phase)
    return r.get("result") if isinstance(r, dict) else None


def child(rec):
    r = res(rec, "child")
    return r if isinstance(r, dict) and "token" in r else None


def ck(rec, key):
    c = child(rec)
    return None if c is None else c.get(key)


def run_ok(v, needle=None):
    if not isinstance(v, dict):
        return False, str(v)[:120]
    ok = v.get("exit") == 0 and (needle is None or needle in (v.get("stdout") or ""))
    if ok and "NODEJSON" in (v.get("stdout") or ""):
        body = json.loads(v["stdout"].split("NODEJSON ", 1)[1].splitlines()[0])
        ok = not body.get("error") and not body.get("timeout") and body.get("status") in (None, 0)
        if not ok:
            return False, json.dumps(body)[:160]
    return ok, None if ok else f"exit {v.get('exit')}: {(v.get('stderr') or v.get('stdout') or '').strip()[-160:]}"


# item: (section, label, fn(rec) -> True / False / NA, or (bool, error))
def shell_item(lid, key, want="ok"):
    def f(rec):
        if not started(rec, lid):
            return NA, launch(rec, lid) and launch(rec, lid).get("exit")
        out = res(rec, lid) or {}
        if key not in out:
            return NA, None
        v = out[key]
        return v == want, v
    return f


def child_item(key, needle=None, sub=None):
    def f(rec):
        c = child(rec)
        if c is None:
            return NA, launch(rec, "child") and launch(rec, "child").get("exit")
        if key not in c:
            return NA, None
        v = c.get(key)
        if sub:
            v = (v or {}).get(sub) if isinstance(v, dict) else v
            return v in ("granted", "ok", True, "opened"), v
        return run_ok(v, needle)
    return f


def nobj_item(ns, typ):
    def f(rec):
        c = child(rec)
        if c is None:
            return NA, None
        for name, v in (c.get("nobj_create") or {}).items():
            if name.startswith(ns + "\\") and name.endswith("-" + typ):
                return v.get("created") == "new", v.get("created")
        return False, "missing"
    return f


def hole_fs(key):
    def f(rec):
        c = child(rec)
        if c is None or rec.get("host"):
            return NA, None
        v = (c.get("holes_fs") or {}).get(key)
        return v == "ok", v
    return f


def hole_reg(key):
    def f(rec):
        c = child(rec)
        if c is None or rec.get("host"):
            return NA, None
        v = (c.get("holes_reg") or {}).get(key)
        return v == "granted", v
    return f


def host_obj(right):
    def f(rec):
        c = child(rec)
        if c is None or rec.get("host"):
            return NA, None
        objs = c.get("host_local_objects") or {}
        vals = [v.get(right) for k, v in objs.items() if right in v]
        return bool(vals) and all(x == "granted" for x in vals), sorted(set(map(str, vals)))
    return f


def host_effect(rec):
    if child(rec) is None or rec.get("host"):
        return NA, None
    hc = rec.get("host_check") or {}
    sec = [v for k, v in hc.items() if k.endswith("-section")]
    return bool(sec) and sec[0].get("sandbox_marker_seen") is True, sec[0].get("content") if sec else None


def squat(rec):
    if rec.get("host"):
        return NA, None
    sq = rec.get("squat") or {}
    if not started(rec, "child_squat", "squat"):
        return NA, launch(rec, "child_squat", "squat") and launch(rec, "child_squat", "squat").get("exit")
    made = ((sq.get("during") or {}).get("host_create_same_names") or {})
    vals = [v.get("created") for v in made.values()]
    return bool(vals) and all(v == "existing" for v in vals), vals


def proc(which, right):
    def f(rec):
        c = child(rec)
        if c is None or rec.get("host"):
            return NA, None
        if which == "launcher":
            v = (c.get("proc_launcher") or {}).get("python.exe")
            v = (v or {}).get("process", {}).get(right) if isinstance(v, dict) else v
        else:
            pu = c.get("proc_user") or {}
            keys = list(pu)
            k = keys[1] if which == "explorer" and len(keys) > 1 else keys[0] if keys else None
            v = ((pu.get(k) or {}).get("process") or {}).get(right) if k else None
        return v == "granted", v
    return f


def window(kind):
    def f(rec):
        if rec.get("host"):
            return NA, None
        w = rec.get("window") or {}
        d = w.get("during") or {}
        if kind == "notepad":
            if not started(rec, "ps_window", "window"):
                return NA, launch(rec, "ps_window", "window") and launch(rec, "ps_window", "window").get("exit")
            ok = any(x["image"].lower() == "notepad.exe" and x["visible"] for x in d.get("sandbox_windows", []))
            return ok, res(rec, "ps_window", "window")
        if not started(rec, "child_window", "window"):
            return NA, launch(rec, "child_window", "window") and launch(rec, "child_window", "window").get("exit")
        return (d.get("test_window") or {}).get("visible") is True, d.get("test_window")
    return f


def start_item(lid):
    def f(rec):
        r = launch(rec, lid)
        if r is None:
            return NA, None
        return r.get("exit") == "0x00000000", r.get("exit")
    return f


ITEMS = [
    ("가. 셸", "PowerShell 5.1 시작·기본 cmdlet·파일 쓰기", lambda r: (lambda s: (s[0] and (res(r, "ps_basic") or {}).get("write") == "ok", s[1]))(start_item("ps_basic")(r))),
    ("가. 셸", "cmd 시작·파일 쓰기", lambda r: (lambda s: (s[0] and (res(r, "cmd_basic") or {}).get("write") == "ok", s[1]) if not r.get("host") else (NA, None))(start_item("cmd_basic")(r))),
    ("가. 셸", "Python 시작(측정 프로그램)", lambda r: (child(r) is not None, launch(r, "child") and launch(r, "child").get("exit"))),
    ("가. 셸", "PowerShell에서 띄운 메모장 창이 사용자 데스크톱에 보임", window("notepad")),
    ("가. 셸", "시험 창(Python CreateWindowEx)이 사용자 데스크톱에 보임", window("test")),
    ("가. NUL", "PowerShell `> $null`", shell_item("ps_null", "gt_null")),
    ("가. NUL", "PowerShell `Out-Null`", shell_item("ps_null", "out_null")),
    ("가. NUL", "PowerShell `2> $null`", shell_item("ps_null", "err_stream_to_null")),
    ("가. NUL", "PowerShell `> NUL`(장치)", shell_item("ps_null", "gt_nul_device")),
    ("가. NUL", "PowerShell에서 `cmd /c \"... 2>nul\"`", shell_item("ps_null", "native_err_to_nul")),
    ("가. NUL", "cmd `>nul`", shell_item("cmd_null", "gt_nul")),
    ("가. NUL", "cmd `2>nul`", shell_item("cmd_null", "err_to_nul")),
    ("가. NUL", "cmd `type nul`(읽기)", shell_item("cmd_null", "type_nul")),
    ("가. NUL", "Python `\\\\.\\NUL` 쓰기 열기", child_item("nul", sub="open_write")),
    ("가. NUL", "Python `subprocess.DEVNULL`", child_item("subprocess_devnull", "devnull-ok")),
    ("나. 도구", "Python 다중 프로세스 병렬(G4)", lambda r: (NA, None) if child(r) is None else ((ck(r, "G4") or {}).get("parallel_ok") is True, (ck(r, "G4") or {}).get("parallel_ok"))),
    ("나. 도구", "`multiprocessing.connection.Pipe()`", child_item("Q1", sub="mp_pipe_duplex_True")),
    ("나. 도구", "Node 단순 실행", child_item("node_basic")),
    ("나. 도구", "Node `spawnSync`(stdio pipe)", child_item("node_spawn_pipe")),
    ("나. 도구", "Node `spawn`(stdio pipe)", child_item("node_spawn_async")),
    ("나. 도구", "Node `execSync`", child_item("node_exec_shell")),
    ("나. 도구", "Node `spawnSync`(stdio inherit)", child_item("node_spawn_inherit")),
    ("나. 도구", "Node `fork`(IPC)", child_item("node_fork_ipc")),
    ("나. 도구", "Node `worker_threads`", child_item("node_worker")),
    ("나. 도구", "Node `net` 파이프 서버", child_item("node_pipe_server")),
    ("나. 도구", "Git Bash(`echo`)", child_item("bash_echo", "bash-ok")),
    ("나. 도구", "Git Bash(파이프라인·명령 치환·백그라운드)", lambda r: (lambda c: (NA, None) if c is None else (all(run_ok(c.get(k))[0] for k in ("bash_pipe", "bash_subst", "bash_bg")), run_ok(c.get("bash_pipe"))[1]))(child(r))),
    ("나. 도구", "`git status`(사용자 소유 저장소, 환경 변수 없음)", child_item("git_status")),
    ("나. 도구", "`git status` + `safe.directory` 환경 변수", child_item("git_status_safe_directory")),
    ("나. 도구", "`git status` + `safe.directory` + 읽을 수 있는 `HOME`", child_item("git_status_safe_directory_home")),
    ("나. 이름 있는 객체", "`Local\\` 이벤트 만들기", nobj_item("Local", "event")),
    ("나. 이름 있는 객체", "`Local\\` 뮤텍스 만들기", nobj_item("Local", "mutex")),
    ("나. 이름 있는 객체", "`Local\\` section 만들기", nobj_item("Local", "section")),
    ("나. 이름 있는 객체", "`Global\\` 이벤트·뮤텍스 만들기", lambda r: (lambda a, b: (a[0] and b[0], a[1]) if a[0] is not NA else a)(nobj_item("Global", "event")(r), nobj_item("Global", "mutex")(r))),
    ("다. 쓰기 경로", "작업 폴더(capability SID + 그룹 쓰기 ACE)", hole_fs("ws_A_write")),
    ("다. 쓰기 경로", "capability SID 쓰기 ACE만 있는 폴더", hole_fs("ws_cap_write")),
    ("다. 쓰기 경로", "그룹 쓰기 ACE만 있는 폴더", hole_fs("ws_grp_write")),
    ("다. 쓰기 경로", "계정 쓰기 ACE만 있는 폴더", hole_fs("ws_acct_write")),
    ("다. 구멍", "Everyone 쓰기 폴더에 쓰기", hole_fs("everyone_write_write")),
    ("다. 구멍", "사용자 로그온 SID 쓰기 폴더에 쓰기", hole_fs("logon_write_write")),
    ("다. 구멍", "사용자만 쓰기 폴더에 쓰기(대조)", hole_fs("user_only_write")),
    ("다. 구멍", "Everyone 쓰기 HKCU 키 쓰기 열기", hole_reg("hkcu_everyone-write")),
    ("다. 구멍", "사용자 로그온 SID 쓰기 HKCU 키 쓰기 열기", hole_reg("hkcu_logon-write")),
    ("다. 구멍", "사용자만 쓰기 HKCU 키(대조)", hole_reg("hkcu_user-only")),
    ("다. 구멍", "호스트 `Local\\` 객체를 쓰기 권한으로 열기", host_obj("write")),
    ("다. 구멍", "호스트 `Local\\` section에 샌드박스가 쓴 값이 호스트에 보임", host_effect),
    ("다. 구멍", "같은 이름 선점(호스트가 샌드박스 객체를 받음)", squat),
    ("다. 구멍", "explorer를 `VM_READ`로 열기", proc("explorer", "VM_READ")),
    ("다. 구멍", "explorer를 `TERMINATE`로 열기", proc("explorer", "TERMINATE")),
    ("다. 구멍", "호스트 시험 프로세스(로그온 SID ACE 없음)를 `VM_READ`로 열기", proc("test", "VM_READ")),
    ("다. 구멍", "실행기를 `VM_WRITE`로 열기", proc("launcher", "VM_WRITE")),
    ("다. 구멍", "실행기를 `CREATE_THREAD`로 열기", proc("launcher", "CREATE_THREAD")),
]


def trials_of(group, key):
    d = load(group)
    if d is None:
        return None
    if group == "main":
        t = d.get(key) or []
        return [host_shape(x) for x in t] if key == "host" else t
    return d.get("trials")


def cell(trials, fn, detail):
    if not trials:
        return "—"
    ok = bad = na = 0
    err = None
    for r in trials:
        try:
            v, e = fn(r)
        except Exception as ex:  # a missing field counts as not measured
            v, e = NA, f"{type(ex).__name__}"
        if v is NA and r.get("host"):
            continue  # the host control does not run this item
        if v is NA:
            na += 1
        elif v:
            ok += 1
        else:
            bad += 1
            err = err or e
    n = ok + bad
    if n == 0:
        txt = "시작 못 함" if na else "—"  # "—": not part of this column's runs
    else:
        txt = f"됨 {ok}/{n}" if ok == n else f"안 됨 {bad}/{n}" if ok == 0 else f"됨 {ok}/{n}"
        if na:
            txt += f" (시작 못 함 {na})"
    if detail and err is not None:
        txt += f" `{str(err)[:90]}`"
    return txt


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    detail = "--detail" in sys.argv
    cols = [(g, k, label, trials_of(g, k)) for g, k, label in COLUMNS]
    cols = [c for c in cols if c[3]]
    print("| 구분 | 항목 | " + " | ".join(c[2] for c in cols) + " |")
    print("| --- | --- | " + " | ".join("---" for _ in cols) + " |")
    for sec, label, fn in ITEMS:
        print(f"| {sec} | {label} | " + " | ".join(cell(c[3], fn, detail) for c in cols) + " |")
    print()
    for g, k, label, trials in cols:
        exits = {}
        for r in trials:
            L = (r.get("main") or {}).get("launcher") or {}
            for lid, v in (L.get("launches") or {}).items():
                if isinstance(v, dict):
                    exits.setdefault(lid, {}).setdefault(v.get("exit"), 0)
                    exits[lid][v.get("exit")] += 1
        print(f"- {label} 종료 코드: " + "; ".join(f"{lid} {e}" for lid, e in exits.items()))


if __name__ == "__main__":
    main()
