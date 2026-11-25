"""Per-trial counts for plan-token-backends.md T1-T6 (Node, Git Bash, Git).

Reads local/<ISO_DATE>/<config>-tools.json (and codex-unelevated-toolshost.json as the host control) and
prints, for each command, how often each outcome occurred. An outcome is the exit code plus a short form
of the output: the NODEJSON line for Node, the first stdout line for the others, or the last stderr
line when the command failed. SIDs, user paths and per-trial tags are replaced, so the output holds no
identifier of the real PC. Usage: python probe-tools-summary.py
"""
import os
import re
import sys
import json
from collections import Counter, OrderedDict
from pathlib import Path

os.environ.setdefault("ISO_DATE", "2026-11-26-tools")
sys.path.insert(0, str(Path(__file__).parent))
from token_backends_common import LOCAL, CONFIGS  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")


def clean(s, tag):
    s = s.replace(tag, "<tag>")
    s = re.sub(r"S-1-5-(?:21|5)-[0-9-]+", "<SID>", s)
    s = re.sub(r"\d+ \[main\] (\S+) \(\d+\)", r"[main] \1 (<pid>)", s)
    s = re.sub(r"C:\\\\?Users\\\\?[^\\\\/\"' ]+", "<USERPROFILE>", s, flags=re.I)
    s = re.sub(r"/c/Users/[^/\"' ]+", "<USERPROFILE>", s, flags=re.I)
    return s


def outcome(v, tag):
    if not isinstance(v, dict):
        return clean(str(v), tag)[:160]
    ex = v.get("exit")
    so = (v.get("stdout") or "").strip()
    se = (v.get("stderr") or "").strip()
    node = [ln for ln in so.splitlines() if ln.startswith("NODEJSON ")]
    if node:
        body = node[-1][9:]
    elif ex == 0 and so:
        body = so.splitlines()[0]
    else:
        body = (se.splitlines()[-1] if se else so.splitlines()[-1] if so else "")
    return clean(f"exit {ex}: {body}", tag)[:220]


cols = OrderedDict()
host = LOCAL / "codex-unelevated-toolshost.json"
if host.exists():
    cols["host"] = json.loads(host.read_text(encoding="utf-8"))["result"]
for cfg in CONFIGS:
    p = LOCAL / f"{cfg}-tools.json"
    if p.exists():
        cols[cfg] = json.loads(p.read_text(encoding="utf-8"))["result"]
keys = []
for trials in cols.values():
    for t in trials:
        for k in (t.get("result") or {}):
            if k != "token" and k not in keys:
                keys.append(k)
for k in keys:
    print(f"## {k}")
    for c, trials in cols.items():
        cnt = Counter(outcome((t.get("result") or {}).get(k), t["tag"]) for t in trials)
        print(f"- {c}: " + " | ".join(f"{o} ({n})" for o, n in cnt.most_common()))
