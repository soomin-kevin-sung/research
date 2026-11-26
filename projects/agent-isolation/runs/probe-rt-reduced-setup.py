"""Non-elevated preparation for the reduced restricting SID measurement (runs/2026-11-26-03.md).

Usage: python probe-rt-reduced-setup.py prep | acl
  prep  before the UAC step. Creates C:\\agent-isolation-test with
          tools\\pyrt, tools\\child.py, tools\\launcher.py   (Users read through the C:\\ inheritance)
          secrets\\sbx.json                                 random passwords of the two measurement accounts,
                                                             DACL user and SYSTEM only
          rt\\  (DACL user, SYSTEM, Administrators only)   ws-A (Node test scripts, null-test.cmd, test Git
                repository owned by the user), ws-cap, ws-grp, ws-acct, temp, out, specs,
                targets\\everyone-write | logon-write | user-only
        and the test keys HKCU\\Software\\agent-isolation-rt\\everyone-write | logon-write | user-only, plus a
        random capability SID in the Codex format (S-1-5-21-a-b-c-d).
  acl   after the accounts exist. Adds the ACEs that depend on them:
          rt               group read (inherited)            (Win32 API, not icacls: see grant())
          ws-A, temp       capability SID modify + group modify (Codex elevated: capability SID and sandbox group)
          ws-cap           capability SID modify only
          ws-grp           group modify only
          ws-acct, out     account modify (both accounts)
Writes local/2026-11-26-rt/setup.json. Run with the test venv Python.
"""
import os
import re
import sys
import json
import random
import secrets
import shutil
import string
import subprocess
import winreg
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26-rt")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import (ROOT, TOOLS, PYRT, CHILD, token_sids, lookup_sid, icacls, protect,  # noqa: E402
                                   dacl_aces, save, load, SID_EVERYONE)

import win32con  # noqa: E402
import win32security  # noqa: E402

RT = ROOT / "rt"
LAUNCHER = TOOLS / "launcher.py"
SECRETS = ROOT / "secrets" / "sbx.json"
ACCOUNTS = ("iso-rt-sbx1", "iso-rt-sbx2")
GROUP = "iso-rt-sbx-users"
HKCU_BASE = r"Software\agent-isolation-rt"
GIT = r"C:\Program Files\Git\cmd\git.exe"
NULL_TEST = r"""@echo off
rem NUL redirection in cmd. A failed redirection skips the command and sets errorlevel 1.
(echo a>nul) && echo gt_nul=ok || echo gt_nul=fail
(echo b>NUL:) && echo gt_nul_colon=ok || echo gt_nul_colon=fail
(echo c 1>&2) 2>nul && echo err_to_nul=ok || echo err_to_nul=fail
(type nul) && echo type_nul=ok || echo type_nul=fail
(dir /b C:\iso-rt-none 2>nul) || echo dir_missing_2nul=done
echo done=ok
"""


def password():
    chars = string.ascii_letters + string.digits + "!#%+-=?@^_"
    while True:
        p = "".join(secrets.choice(chars) for _ in range(24))
        if (any(c.islower() for c in p) and any(c.isupper() for c in p) and any(c.isdigit() for c in p)
                and any(not c.isalnum() for c in p)):
            return p


def node_scripts():
    src = Path(__file__).with_name("probe-tools-prep.py").read_text(encoding="utf-8")
    node = re.search(r'NODETEST = r"""(.*?)"""', src, re.S).group(1)
    fork = re.search(r'FORKCHILD = "(.*?)\\n"', src).group(1) + "\n"
    return node, fork


def prep():
    if ROOT.exists():
        sys.exit(f"{ROOT} already exists; refusing to overwrite")
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, HKCU_BASE).Close()
        sys.exit(f"HKCU\\{HKCU_BASE} already exists")
    except OSError:
        pass
    user_sid, logon_sid = token_sids()
    rec = {"user_sid": user_sid, "logon_sid": logon_sid, "accounts": list(ACCOUNTS), "group": GROUP,
           "cap_sid": "S-1-5-21-" + "-".join(str(random.SystemRandom().randrange(1, 2**32)) for _ in range(4))}
    ROOT.mkdir()
    if os.environ.get("ISO_ROOT"):  # a root under the profile: do not inherit the profile's extra ACEs
        protect(ROOT, user_sid)
    TOOLS.mkdir()
    src = Path(sys.base_prefix)
    PYRT.mkdir()
    for f in ("python.exe", "python3.dll", "python312.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        shutil.copy2(src / f, PYRT / f)
    shutil.copytree(src / "DLLs", PYRT / "DLLs")
    shutil.copytree(src / "Lib", PYRT / "Lib", ignore=shutil.ignore_patterns(
        "site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3", "__pycache__", "pydoc_data"))
    shutil.copy2(Path(__file__).with_name("probe-token-backends-child.py"), CHILD)
    shutil.copy2(Path(__file__).with_name("probe-rt-reduced-launcher.py"), LAUNCHER)
    # tools: users read and run, nobody but the user writes
    icacls(TOOLS, "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F",
           "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX")

    (ROOT / "secrets").mkdir()
    icacls(ROOT / "secrets", "/inheritance:r", "/grant:r", f"*{user_sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
    SECRETS.write_text(json.dumps({n: password() for n in ACCOUNTS}), encoding="utf-8")

    RT.mkdir()
    protect(RT, user_sid)
    for d in ("ws-A", "ws-cap", "ws-grp", "ws-acct", "temp", "out", "specs", "targets"):
        (RT / d).mkdir()
    a = RT / "ws-A"
    node, fork = node_scripts()
    (a / "nodetest.js").write_text(node, encoding="utf-8")
    (a / "forkchild.js").write_text(fork, encoding="utf-8")
    (a / "null-test.cmd").write_text(NULL_TEST.replace("\n", "\r\n"), encoding="ascii")
    (a / "existing.txt").write_text("ws-A-original\n")
    repo = a / "repo"
    repo.mkdir()
    r = subprocess.run([GIT, "init", "-q", str(repo)], capture_output=True)
    rec["git_init_exit"] = r.returncode
    (repo / "a.txt").write_text("untracked\n", encoding="utf-8")
    for name, extra in (("everyone-write", [f"*{SID_EVERYONE}:(OI)(CI)M"]), ("logon-write", [f"*{logon_sid}:(OI)(CI)M"]),
                        ("user-only", [])):
        d = RT / "targets" / name
        d.mkdir()
        if extra:
            icacls(d, "/grant", *extra)
        (d / "f.txt").write_text(f"{name}-original\n")

    # HKCU test keys (deleted after measurement), same DACL scheme as R5 of 2026-11-25
    key_all, key_write = 0xF003F, 0x20006
    base = winreg.CreateKey(winreg.HKEY_CURRENT_USER, HKCU_BASE)
    for name, sid in (("everyone-write", SID_EVERYONE), ("logon-write", logon_sid), ("user-only", None)):
        k = winreg.CreateKey(base, name)
        dacl = win32security.ACL()
        for s, mask in ((user_sid, key_all), ("S-1-5-18", key_all), ("S-1-5-32-544", key_all)) + (
                ((sid, key_write),) if sid else ()):
            dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, win32con.CONTAINER_INHERIT_ACE, mask,
                                       win32security.ConvertStringSidToSid(s))
        win32security.SetSecurityInfo(k.handle, win32security.SE_REGISTRY_KEY,
                                      win32security.DACL_SECURITY_INFORMATION
                                      | win32security.PROTECTED_DACL_SECURITY_INFORMATION, None, None, dacl, None)
        winreg.CloseKey(k)
    winreg.CloseKey(base)
    rec["hkcu_keys"] = {n: rf"{HKCU_BASE}\{n}" for n in ("everyone-write", "logon-write", "user-only")}
    rec["dacl_prep"] = {str(p): dacl_aces(p) for p in [ROOT, TOOLS, ROOT / "secrets", RT, *RT.iterdir(),
                                                       *(RT / "targets").iterdir()]}
    print(save("setup.json", rec))


MODIFY, READ_EXEC = 0x1301BF, 0x1200A9


def grant(path, entries):
    """Adds inheritable allow ACEs with the Win32 API. icacls resolves SIDs first and fails for the random
    capability SID on this PC (domain trust error), the same failure QwenPaw had on 2026-11-25.
    Explicit ACEs are kept, inherited ones are recomputed from the parent; existing identical ACEs are skipped."""
    info = win32security.DACL_SECURITY_INFORMATION
    sd = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, info)
    old = sd.GetSecurityDescriptorDacl()
    protected = bool(sd.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED)
    new = win32security.ACL()
    have = set()
    for i in range(old.GetAceCount()):
        (atype, aflags), mask, sid = old.GetAce(i)
        if aflags & win32security.INHERITED_ACE:
            continue
        have.add((atype, aflags, mask & 0xffffffff, win32security.ConvertSidToStringSid(sid)))
        if atype == 0:
            new.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, aflags, mask, sid)
        else:
            raise RuntimeError(f"unexpected ACE type {atype} on {path}")
    for sid, mask in entries:
        if (0, 0x3, mask, sid) not in have:
            new.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, 0x3, mask,  # OBJECT_INHERIT | CONTAINER_INHERIT
                                      win32security.ConvertStringSidToSid(sid))
    flag = (win32security.PROTECTED_DACL_SECURITY_INFORMATION if protected
            else win32security.UNPROTECTED_DACL_SECURITY_INFORMATION)
    win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT, info | flag, None, None, new, None)


def acl():
    rec = load("setup.json")
    acc = {n: s for n in ACCOUNTS if (s := lookup_sid(n))}  # 2026-11-26-04 creates iso-rt-sbx1 only
    grp = lookup_sid(GROUP)
    if not grp or not acc:
        sys.exit(f"accounts or group missing: {acc} {grp}")
    cap = rec["cap_sid"]
    grant(RT, [(grp, READ_EXEC)])
    for d in ("ws-A", "temp"):
        grant(RT / d, [(cap, MODIFY), (grp, MODIFY)])
    grant(RT / "ws-cap", [(cap, MODIFY)])
    grant(RT / "ws-grp", [(grp, MODIFY)])
    for d in ("ws-acct", "out"):
        grant(RT / d, [(s, MODIFY) for s in acc.values()])
    rec["account_sids"], rec["group_sid"] = acc, grp
    rec["dacl_acl"] = {str(p): dacl_aces(p) for p in [RT, *RT.iterdir(), *(RT / "targets").iterdir(), RT / "ws-A" / "repo"]}
    print(save("setup.json", rec))


PACKAGE_JSON = '{"name": "iso-rt2", "version": "1.0.0", "private": true, "scripts": {"spawnpipe": "node spawnpipe.js"}}\n'
SPAWNPIPE_JS = """// npm run spawnpipe: a child process with stdio pipes, as build and test scripts start them
const cp = require('child_process');
const r = cp.spawnSync(process.execPath, ['-e', 'console.log("child-ok")'], { encoding: 'utf8', timeout: 15000 });
console.log('NPMRUN ' + JSON.stringify({ status: r.status, stdout: (r.stdout || '').trim(), error: r.error ? r.error.code : null }));
process.exit(r.status === 0 ? 0 : 1);
"""
TEST_PY = '''import os
import subprocess
import sys
import tempfile
import unittest


class IsoRt2(unittest.TestCase):
    def test_arithmetic(self):
        self.assertEqual(2 + 2, 4)

    def test_subprocess_pipe(self):
        r = subprocess.run([sys.executable, "-c", "print('sub-ok')"], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "sub-ok")

    def test_tempdir(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "f.txt")
            with open(p, "w") as f:
                f.write("x")
            self.assertTrue(os.path.exists(p))


if __name__ == "__main__":
    unittest.main()
'''


def rt2():
    """2026-11-26-04: second workspace (its own capability SID), npm and unittest test files, a copy of Git's
    MSYS2 files under tools (its own \\\\BaseNamedObjects\\\\msys-* namespace, used by no other process)."""
    rec = load("setup.json")
    if "cap_sid_b" in rec:
        sys.exit("rt2 step already ran")
    rec["cap_sid_b"] = "S-1-5-21-" + "-".join(str(random.SystemRandom().randrange(1, 2**32)) for _ in range(4))
    b = RT / "ws-B"
    b.mkdir()
    grant(b, [(rec["cap_sid_b"], MODIFY), (rec["group_sid"], MODIFY)])
    a = RT / "ws-A"
    (a / "package.json").write_text(PACKAGE_JSON, encoding="utf-8")
    (a / "spawnpipe.js").write_text(SPAWNPIPE_JS, encoding="utf-8")
    (a / "tests").mkdir()
    (a / "tests" / "test_iso.py").write_text(TEST_PY, encoding="utf-8")
    git = Path(r"C:\Program Files\Git")
    copy = TOOLS / "gitcopy"
    for sub in (("usr", "bin"), ("etc",), ("bin",)):
        shutil.copytree(git.joinpath(*sub), copy.joinpath(*sub))
    rec["gitcopy"] = str(copy)
    rec["dacl_rt2"] = {str(p): dacl_aces(p) for p in [ROOT, b, copy]}
    print(save("setup.json", rec))


if __name__ == "__main__":
    {"prep": prep, "acl": acl, "rt2": rt2}[sys.argv[1]]()
