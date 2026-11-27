"""Child for the schannel and profile measurement (runs/2026-11-26-05.md). Standalone Python runtime, stdlib + ctypes.

Usage: python tls_child.py <spec.json>     prints one ISOJSON line (and writes spec["out"] when it can)
Runs with the token the harness gives it: the measurement account's logon token (cells A, C), a Codex-style
WRITE_RESTRICTED token made from it (cells B, D), or a restricted copy of the current user's token (control).
Imports child.py (probe-token-backends-child.py) from its own folder for token_info, hkcu_name and run_tool.

Tasks
  token   token_info() of child.py, plus IsTokenRestricted
  env     selected environment variables
  sspi    AcquireCredentialsHandleW outbound: schannel with SCHANNEL_CRED (version 4) and SCH_CREDENTIALS
          (version 5), both with SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION, schannel with no
          auth data, and Negotiate with no auth data. Each handle is freed at once; no context is started.
  hkcu    which hive HKCU is (\\REGISTRY\\USER\\<SID> or .DEFAULT), reads the test values under
          HKCU\\Software\\agent-isolation-tls and writes one value only when HKCU is the account's own hive
          (never .DEFAULT or another account's hive)
  run     an installed tool (curl, PowerShell, Git, Python) with child.py run_tool
"""
import sys
import json
import ctypes
import winreg
import importlib.util
from ctypes import wintypes
from pathlib import Path

_c = importlib.util.spec_from_file_location("child", Path(__file__).with_name("child.py"))
C = importlib.util.module_from_spec(_c)
_c.loader.exec_module(C)

sspi = ctypes.WinDLL("secur32")
adv = ctypes.WinDLL("advapi32", use_last_error=True)
KEY = r"Software\agent-isolation-tls"


class SecHandle(ctypes.Structure):
    _fields_ = [("dwLower", ctypes.c_size_t), ("dwUpper", ctypes.c_size_t)]


class TimeStamp(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class SCHANNEL_CRED(ctypes.Structure):  # SCHANNEL_CRED_VERSION 4
    _fields_ = [("dwVersion", wintypes.DWORD), ("cCreds", wintypes.DWORD), ("paCred", ctypes.c_void_p),
                ("hRootStore", ctypes.c_void_p), ("cMappers", wintypes.DWORD), ("aphMappers", ctypes.c_void_p),
                ("cSupportedAlgs", wintypes.DWORD), ("palgSupportedAlgs", ctypes.c_void_p),
                ("grbitEnabledProtocols", wintypes.DWORD), ("dwMinimumCipherStrength", wintypes.DWORD),
                ("dwMaximumCipherStrength", wintypes.DWORD), ("dwSessionLifespan", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD), ("dwCredFormat", wintypes.DWORD)]


class SCH_CREDENTIALS(ctypes.Structure):  # SCH_CREDENTIALS_VERSION 5
    _fields_ = [("dwVersion", wintypes.DWORD), ("dwCredFormat", wintypes.DWORD), ("cCreds", wintypes.DWORD),
                ("paCred", ctypes.c_void_p), ("hRootStore", ctypes.c_void_p), ("cMappers", wintypes.DWORD),
                ("aphMappers", ctypes.c_void_p), ("dwSessionLifespan", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("cTlsParameters", wintypes.DWORD), ("pTlsParameters", ctypes.c_void_p)]


sspi.AcquireCredentialsHandleW.restype = wintypes.LONG
sspi.AcquireCredentialsHandleW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.ULONG, ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                           ctypes.POINTER(SecHandle), ctypes.POINTER(TimeStamp)]
sspi.FreeCredentialsHandle.argtypes = [ctypes.POINTER(SecHandle)]
adv.IsTokenRestricted.argtypes = [wintypes.HANDLE]
UNISP = "Microsoft Unified Security Protocol Provider"
NO_DEFAULT_CREDS, MANUAL_CRED_VALIDATION = 0x10, 0x8


def ach(package, auth):
    h, ts = SecHandle(), TimeStamp()
    st = sspi.AcquireCredentialsHandleW(None, package, 2, None, ctypes.byref(auth) if auth is not None else None,
                                        None, None, ctypes.byref(h), ctypes.byref(ts))
    if st == 0:
        sspi.FreeCredentialsHandle(ctypes.byref(h))
    return f"0x{st & 0xffffffff:08x}"


def sspi_all():
    v4 = SCHANNEL_CRED(dwVersion=4, dwFlags=NO_DEFAULT_CREDS | MANUAL_CRED_VALIDATION)
    v5 = SCH_CREDENTIALS(dwVersion=5, dwFlags=NO_DEFAULT_CREDS | MANUAL_CRED_VALIDATION)
    return {"schannel_v4": ach(UNISP, v4), "schannel_v5": ach(UNISP, v5), "schannel_null": ach(UNISP, None),
            "negotiate_null": ach("Negotiate", None)}


def token_task():
    out = C.token_info()
    h = C.own_token()
    out["is_token_restricted"] = bool(adv.IsTokenRestricted(h))
    C.k32.CloseHandle(h)
    return out


def hkcu_task(t):
    name = C.hkcu_name()
    h = C.own_token()
    buf = C.tok_raw(h, 1)
    user = C.sid_str(ctypes.c_void_p.from_buffer(buf, 0).value) if buf else None
    C.k32.CloseHandle(h)
    own = bool(user) and isinstance(name, str) and name.upper().endswith("\\" + user.upper())
    out = {"hkcu": name, "own_hive": own, "read": {}}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_READ) as k:
            for v in t.get("read", []):
                try:
                    out["read"][v] = winreg.QueryValueEx(k, v)[0]
                except OSError as e:
                    out["read"][v] = f"error:{e.winerror}"
    except OSError as e:
        out["read"] = f"open_error:{e.winerror}"
    if not own:
        out["write"] = "skipped_not_own_hive"
        return out
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, t["write"], 0, winreg.REG_SZ, t["data"])
        out["write"] = "ok"
    except OSError as e:
        out["write"] = f"error:{e.winerror}"
    return out


def run_task(t):
    kind = t["kind"]
    if kind == "token":
        return token_task()
    if kind == "env":
        import os
        return {n: os.environ.get(n) for n in t["names"]}
    if kind == "sspi":
        return sspi_all()
    if kind == "hkcu":
        return hkcu_task(t)
    if kind == "run":
        return C.run_tool(t["argv"], t.get("cwd"), t.get("timeout", 60), t.get("stdin", "devnull"), t.get("env"))
    return f"unknown_kind:{kind}"


def main():
    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    out = {}
    for t in spec["tasks"]:
        try:
            out[t["id"]] = run_task(t)
        except Exception as e:
            out[t["id"]] = f"exception:{type(e).__name__}:{e}"
    line = json.dumps(out)
    if spec.get("out"):
        try:
            Path(spec["out"]).write_text(line, encoding="utf-8")
        except OSError:
            pass
    print("ISOJSON " + line, flush=True)


if __name__ == "__main__":
    main()
