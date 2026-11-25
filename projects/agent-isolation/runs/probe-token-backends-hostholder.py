"""Non-elevated host targets for the QwenPaw admin measurements (plan-token-backends.md P1, P2, G5).

The QwenPaw admin campaign runs in a UAC-approved session, so test processes and pipes it created itself
would carry the elevated token. This script runs in the normal session before that and keeps, for each of
the five trials, one test process (marker in its command line) and one named pipe server. It writes
local/2026-11-25/uac-host-targets.json and exits when local/2026-11-25/uac-host-targets.stop appears or
after the lifetime given in seconds (default 5400). Nothing here needs or requests elevation.

Usage: python probe-token-backends-hostholder.py [lifetime_seconds]
"""
import sys
import time
import uuid
from pathlib import Path

import win32pipe

sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import LOCAL, save, start_test_process, wait_file, token_sids  # noqa: E402

life = int(sys.argv[1]) if len(sys.argv) > 1 else 5400
stop = LOCAL / "uac-host-targets.stop"
stop.unlink(missing_ok=True)
procs, pipes, trials = [], [], []
for t in range(1, 6):
    marker = f"ISO-TB-MARKER-{uuid.uuid4().hex[:10]}"
    hb = LOCAL / f"uac-testproc-{t}.hb"
    hb.unlink(missing_ok=True)
    tp = start_test_process(life, marker, hb)
    wait_file(hb, 15)
    procs.append(tp)
    name = f"iso-tb-{uuid.uuid4().hex[:8]}"
    pipes += [win32pipe.CreateNamedPipe(rf"\\.\pipe\{name}", win32pipe.PIPE_ACCESS_DUPLEX,
                                        win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT, 255, 4096, 4096, 0, None)
              for _ in range(4)]
    trials.append({"trial": t, "pid": tp.pid, "marker": marker, "hb": str(hb), "pipe": name})
user, _ = token_sids()
save("uac-host-targets.json", {"started": time.time(), "life": life, "holder_user_sid": user, "trials": trials})
print("ready", flush=True)
t0 = time.time()
while not stop.exists() and time.time() - t0 < life:
    time.sleep(2)
for h in pipes:
    h.Close()
for p in procs:
    p.kill()
print("stopped", flush=True)
