"""Non-elevated host side of the named object and pipe measurements (plan-token-backends.md N, Q).

Runs in the normal (non-elevated) session for all four configurations, so the host token is the same
whether the campaign itself runs in the normal session or in the UAC-approved session. The campaign
writes local/2026-11-26/hostagent/req-<id>.json; this process performs the request and writes
resp-<id>.json. It only creates, opens and closes synthetic iso-nq-* objects and pipes, using the same
functions as the in-sandbox program. It exits when local/2026-11-26/hostagent/stop appears or after the
lifetime given in seconds (default 10800). Nothing here needs or requests elevation.

Usage: python probe-named-objects-hostagent.py [lifetime_seconds]
"""
import os
import sys
import json
import time
import ctypes
import importlib.util
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import LOCAL, token_sids  # noqa: E402

spec = importlib.util.spec_from_file_location("isochild", Path(__file__).with_name("probe-token-backends-child.py"))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)

BOX = LOCAL / "hostagent"
BOX.mkdir(parents=True, exist_ok=True)
STOP = BOX / "stop"
STOP.unlink(missing_ok=True)
held = {}  # key -> [(type, name, handle)]


def bno_sddl():
    """N0 host side: SDDL of the named object directories (READ_CONTROL only)."""
    out = {}
    sess = C.DW()
    C.k32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sess))
    probe = C.ns_dirs()  # the same per-right opens as in the sandbox, as a host baseline
    out["host_open"] = probe
    out["session"] = sess.value
    return out


def act(req):
    a = req["action"]
    if a == "ping":
        user, logon = token_sids()
        return {"pid": os.getpid(), "user_sid": user, "logon_sid": logon,
                "elevated": bool(ctypes.windll.shell32.IsUserAnAdmin())}
    if a == "dirs":
        return bno_sddl()
    if a == "create":  # N1/N2 host objects, kept until "check"
        out, hs = {}, []
        for o in req["objects"]:
            r = C.nobj_create([{**o, "marker": req["marker"] if o["type"] == "section" else None}], keep=True)
            out.update(r)
            if C.KEEP and r[o["name"]].get("created") in ("new", "existing"):
                hs.append((o["type"], o["name"], C.KEEP.pop()))
        held[req["key"]] = hs
        return out
    if a == "check":  # N1/N2: did the sandbox's operations reach the host objects?
        out = {}
        for typ, name, h in held.pop(req["key"], []):
            if typ == "section":
                v = C.section_io(h)
                out[name] = {"content": v, "sandbox_marker_seen": v == req["marker"]}
            elif typ == "mutex":
                w = C.wait0(h)
                if w in ("signaled", "abandoned"):
                    C.k32.ReleaseMutex(h)
                out[name] = {"host_acquire": w}
            else:  # event: manual reset, created not signaled; semaphore: created with count 0
                out[name] = {"state": C.wait0(h)}
            C.k32.CloseHandle(h)
        return out
    if a == "precreate":  # N4 and Q3, handles closed at once
        out = {"objects": C.nobj_create(req["objects"], keep=False)}
        first, _ = C.pipe_try_create(req["pipe"], first=True)
        plain, _ = C.pipe_try_create(req["pipe"], first=False)
        out["pipe_first_instance"], out["pipe_plain"] = first, plain
        return out
    if a == "open_sandbox":  # N3 and Q2, host side
        return {"objects": C.nobj_open(req["objects"], effects=False),
                "section_read": {o["name"]: (C.nobj_effect("section", o["name"], req["marker"])
                                             if o["type"] == "section" else None) for o in req["objects"]},
                "pipe": C.pipe_client(req["pipe"], req["marker"])}
    return {"error": f"unknown action {a}"}


life = int(sys.argv[1]) if len(sys.argv) > 1 else 10800
print("ready", os.getpid(), flush=True)
t0 = time.time()
while not STOP.exists() and time.time() - t0 < life:
    for p in sorted(BOX.glob("req-*.json")):
        try:
            req = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue  # being written
        try:
            res = {"ok": True, "result": act(req)}
        except Exception as e:  # keep serving; record the failure
            res = {"ok": False, "error": f"{type(e).__name__}:{e}"}
        tmp = BOX / f"tmp-{req['id']}.json"
        tmp.write_text(json.dumps(res, ensure_ascii=False), encoding="utf-8")
        tmp.replace(BOX / f"resp-{req['id']}.json")
        p.unlink(missing_ok=True)
    time.sleep(0.1)
for hs in held.values():
    for _, _, h in hs:
        C.k32.CloseHandle(h)
print("stopped", flush=True)
