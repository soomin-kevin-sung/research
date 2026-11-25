"""Non-elevated preparation for plan-token-backends.md T1-T6 (Node and Git Bash), run after
probe-named-objects-setup.py with ISO_DATE=2026-11-26-tools.

Writes the Node test scripts (Node built-ins only) into every configuration's ws-A and creates a test
Git repository ws-A\\repo with one untracked file, so that all four configurations start from files with
the same owner and DACL. Records the tool versions in local/<ISO_DATE>/tools-prep.json.
"""
import os
import sys
import subprocess
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26-tools")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import CONFIGS, save, ws, dacl_aces  # noqa: E402

NODE = r"C:\Program Files\nodejs\node.exe"
GIT = r"C:\Program Files\Git\cmd\git.exe"
BASH = r"C:\Program Files\Git\usr\bin\bash.exe"

NODETEST = r"""// T1-T4 (plan-token-backends.md). Node built-ins only. Usage: node nodetest.js <case> <tag>
const cp = require('child_process'), path = require('path'), net = require('net');
const [, , kase, tag] = process.argv;
const errOf = e => ({ code: e && e.code, errno: e && e.errno, syscall: e && e.syscall, message: e && String(e.message).slice(0, 200) });
const timer = setTimeout(() => { console.log('NODEJSON ' + JSON.stringify({ timeout: true })); process.exit(3); }, 20000);
const done = r => { clearTimeout(timer); console.log('NODEJSON ' + JSON.stringify(r)); process.exit(0); };
switch (kase) {
  case 'basic':
    done({ ok: true, version: process.version });
    break;
  case 'spawn_pipe': {
    const r = cp.spawnSync(process.execPath, ['-e', 'console.log("child-ok")'], { encoding: 'utf8', timeout: 15000 });
    done({ status: r.status, stdout: (r.stdout || '').trim(), error: r.error ? errOf(r.error) : null });
    break;
  }
  case 'spawn_inherit': {
    const r = cp.spawnSync(process.execPath, ['-e', '0'], { stdio: 'inherit', timeout: 15000 });
    done({ status: r.status, error: r.error ? errOf(r.error) : null });
    break;
  }
  case 'spawn_async': {
    let c;
    try { c = cp.spawn(process.execPath, ['-e', 'console.log("async-ok")']); } catch (e) { done({ error: errOf(e) }); break; }
    let s = '';
    c.on('error', e => done({ error: errOf(e) }));
    if (c.stdout) c.stdout.on('data', d => { s += d; });
    c.on('close', code => done({ status: code, stdout: s.trim() }));
    break;
  }
  case 'exec_shell':
    try { done({ stdout: cp.execSync('echo shell-ok', { encoding: 'utf8', timeout: 15000 }).trim() }); }
    catch (e) { done({ error: errOf(e), status: e.status }); }
    break;
  case 'fork_ipc': {
    let c;
    try { c = cp.fork(path.join(__dirname, 'forkchild.js')); } catch (e) { done({ error: errOf(e) }); break; }
    c.on('error', e => done({ error: errOf(e) }));
    c.on('message', m => done({ reply: m }));
    c.send('ping-' + tag);
    break;
  }
  case 'worker': {
    const { Worker } = require('worker_threads');
    const w = new Worker('require("worker_threads").parentPort.postMessage("worker-ok")', { eval: true });
    w.on('message', m => done({ reply: m }));
    w.on('error', e => done({ error: errOf(e) }));
    break;
  }
  case 'pipe_server': {
    const name = '\\\\.\\pipe\\iso-nq-node-' + tag;
    const srv = net.createServer(sock => sock.on('data', d => { srv.close(); done({ received: String(d) }); }));
    srv.on('error', e => done({ stage: 'listen', error: errOf(e) }));
    srv.listen(name, () => {
      const c = net.connect(name, () => c.write('node-pipe-' + tag));
      c.on('error', e => done({ stage: 'connect', error: errOf(e) }));
    });
    break;
  }
  default:
    done({ error: 'unknown case' });
}
"""
FORKCHILD = "process.on('message', m => process.send('pong:' + m, () => process.exit(0)));\n"


def run(argv, **kw):
    p = subprocess.run(argv, capture_output=True, **kw)
    return {"exit": p.returncode, "out": (p.stdout + p.stderr).decode("utf-8", "replace").strip()[:200]}


rec = {"versions": {"node": run([NODE, "--version"]), "git": run([GIT, "--version"]),
                    "bash": run([BASH, "--noprofile", "--norc", "-c", "echo $BASH_VERSION"])}, "repos": {}}
for cfg in CONFIGS:
    a = ws(cfg, "ws-A")
    (a / "nodetest.js").write_text(NODETEST, encoding="utf-8")
    (a / "forkchild.js").write_text(FORKCHILD, encoding="utf-8")
    repo = a / "repo"
    repo.mkdir()
    rec["repos"][cfg] = run([GIT, "init", "-q", str(repo)])
    (repo / "a.txt").write_text("untracked\n", encoding="utf-8")
    rec["repos"][cfg]["dacl_aces"] = len(dacl_aces(repo))
print(save("tools-prep.json", rec))
